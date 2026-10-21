package ingest

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
	"github.com/uday68/gdc-airgap-sync/pkg/pathutil"
	"github.com/uday68/gdc-airgap-sync/pkg/truststore"
	"gopkg.in/yaml.v3"
)

const (
	DefaultMaxManifestSize = 1 << 20  // 1 MB
	DefaultMaxSBOMSize     = 10 << 20 // 10 MB
	DefaultMaxArtifactSize = 50 << 30 // 50 GB
)

// Typed Security & Ingestion Errors
type SecurityVerificationError struct {
	Reason string
}

func (e *SecurityVerificationError) Error() string {
	return fmt.Sprintf("cryptographic security verification failed: %s", e.Reason)
}

type ArchiveLayoutError struct {
	Reason string
}

func (e *ArchiveLayoutError) Error() string {
	return fmt.Sprintf("invalid bundle archive layout: %s", e.Reason)
}

type SizeMismatchError struct {
	Artifact string
	Expected int64
	Actual   int64
}

func (e *SizeMismatchError) Error() string {
	return fmt.Sprintf("artifact '%s' size mismatch: expected %d bytes, got %d", e.Artifact, e.Expected, e.Actual)
}

type DigestMismatchError struct {
	Artifact string
	Expected string
	Actual   string
}

func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("artifact '%s' digest mismatch: expected %s, got %s", e.Artifact, e.Expected, e.Actual)
}

type CatalogConflictError struct {
	Artifact string
	Reason   string
}

func (e *CatalogConflictError) Error() string {
	return fmt.Sprintf("catalog conflict for artifact '%s': %s", e.Artifact, e.Reason)
}

// IngestReport summarizes the outcome of air-gap validation and repository ingestion.
type IngestReport struct {
	BundleID        string                  `json:"bundleId"`
	SignerIdentity  string                  `json:"signerIdentity"`
	KeyID           string                  `json:"keyId,omitempty"`
	VerifiedAt      time.Time               `json:"verifiedAt"`
	IngestedImages  []manifest.ArtifactMeta `json:"ingestedImages"`
	CatalogFilePath string                  `json:"catalogFilePath"`
}

// RegistryCatalogEntry mirrors the catalog structure of gdc-vm-operator/pkg/registry.
type RegistryCatalogEntry struct {
	Name        string    `json:"name" yaml:"name"`
	Filename    string    `json:"filename" yaml:"filename"`
	SHA256      string    `json:"sha256" yaml:"sha256"`
	SizeBytes   int64     `json:"sizeBytes" yaml:"sizeBytes"`
	OSFamily    string    `json:"osFamily" yaml:"osFamily"`
	Description string    `json:"description" yaml:"description"`
	AddedAt     time.Time `json:"addedAt" yaml:"addedAt"`
}

// RegistryCatalog represents the GDC local registry index file.
type RegistryCatalog struct {
	Version string                          `json:"version" yaml:"version"`
	Images  map[string]RegistryCatalogEntry `json:"images" yaml:"images"`
}

// IngestOptions configures ingestion behavior, trust sources, and limits.
type IngestOptions struct {
	BundlePath          string
	TrustedPubKey       ed25519.PublicKey
	TrustStore          *truststore.TrustStore
	TargetRegistryDir   string
	AllowOverwrite      bool
	MaxManifestSize     int64
	MaxSBOMSize         int64
	MaxArtifactSize     int64
}

// IngestBundle verifies signatures and digests before registering images into the local registry.
// Backward-compatible entrypoint taking a single trusted public key.
func IngestBundle(bundlePath string, trustedPubKey ed25519.PublicKey, targetRegistryDir string) (*IngestReport, error) {
	return IngestBundleWithOptions(IngestOptions{
		BundlePath:        bundlePath,
		TrustedPubKey:     trustedPubKey,
		TargetRegistryDir: targetRegistryDir,
	})
}

// IngestBundleWithOptions executes the security-first ingestion pipeline.
func IngestBundleWithOptions(opts IngestOptions) (*IngestReport, error) {
	if opts.BundlePath == "" {
		return nil, fmt.Errorf("bundle path cannot be empty")
	}
	if opts.TargetRegistryDir == "" {
		return nil, fmt.Errorf("target registry directory cannot be empty")
	}
	if len(opts.TrustedPubKey) == 0 && opts.TrustStore == nil {
		return nil, fmt.Errorf("either a trusted public key or a trust store must be provided")
	}

	maxManifestSize := opts.MaxManifestSize
	if maxManifestSize <= 0 {
		maxManifestSize = DefaultMaxManifestSize
	}
	maxSBOMSize := opts.MaxSBOMSize
	if maxSBOMSize <= 0 {
		maxSBOMSize = DefaultMaxSBOMSize
	}
	maxArtifactSize := opts.MaxArtifactSize
	if maxArtifactSize <= 0 {
		maxArtifactSize = DefaultMaxArtifactSize
	}

	bundleFile, err := os.Open(opts.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening bundle archive: %w", err)
	}
	defer bundleFile.Close()

	gzReader, err := gzip.NewReader(bundleFile)
	if err != nil {
		return nil, fmt.Errorf("failed reading gzip stream: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	// Step 1: Read the FIRST entry. It MUST be manifest.yaml.
	// This ensures cryptographic verification happens BEFORE any artifact data is read or written.
	firstHdr, err := tarReader.Next()
	if err != nil {
		return nil, fmt.Errorf("failed reading first archive entry: %w", err)
	}

	cleanFirstName := path.Clean(firstHdr.Name)
	if cleanFirstName != "manifest.yaml" {
		return nil, &ArchiveLayoutError{
			Reason: fmt.Sprintf("expected 'manifest.yaml' as first archive entry, found '%s'", firstHdr.Name),
		}
	}

	if firstHdr.Size > maxManifestSize {
		return nil, &ArchiveLayoutError{
			Reason: fmt.Sprintf("manifest.yaml size (%d bytes) exceeds maximum allowed limit (%d bytes)",
				firstHdr.Size, maxManifestSize),
		}
	}

	manifestData, err := io.ReadAll(io.LimitReader(tarReader, maxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed reading manifest payload: %w", err)
	}
	if int64(len(manifestData)) > maxManifestSize {
		return nil, &ArchiveLayoutError{
			Reason: fmt.Sprintf("manifest payload exceeds maximum limit of %d bytes", maxManifestSize),
		}
	}

	var mf manifest.BundleManifest
	if err := yaml.Unmarshal(manifestData, &mf); err != nil {
		return nil, fmt.Errorf("failed parsing manifest YAML: %w", err)
	}

	if err := mf.Validate(); err != nil {
		return nil, &SecurityVerificationError{Reason: fmt.Sprintf("manifest validation failed: %v", err)}
	}

	// Step 2: Cryptographic Signature Verification
	// Determine the public key to verify against.
	var verificationPubKey ed25519.PublicKey

	if opts.TrustStore != nil {
		pubKey, err := opts.TrustStore.ValidateSigner(mf.KeyID, mf.SignerIdentity, time.Now().UTC())
		if err != nil {
			return nil, &SecurityVerificationError{Reason: fmt.Sprintf("signer not trusted by trust store: %v", err)}
		}
		verificationPubKey = pubKey
	} else {
		verificationPubKey = opts.TrustedPubKey
	}

	canonicalBytes, err := mf.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("failed generating canonical manifest: %w", err)
	}

	if !crypto.Verify(verificationPubKey, canonicalBytes, mf.Signature) {
		return nil, &SecurityVerificationError{
			Reason: fmt.Sprintf("invalid digital signature for bundle '%s'; untrusted or tampered release package", mf.BundleID),
		}
	}

	// Signature is VALID. We now prepare the isolated staging area for artifact extraction.
	stagingDir, err := os.MkdirTemp("", "gdc-airgap-stage-*")
	if err != nil {
		return nil, fmt.Errorf("failed creating staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	manifestArtifacts := make(map[string]manifest.ArtifactMeta)
	for _, art := range mf.Artifacts {
		manifestArtifacts[art.Filename] = art
	}

	type stagedArtifact struct {
		Meta     manifest.ArtifactMeta
		TempPath string
	}
	stagedMap := make(map[string]stagedArtifact)
	seenEntries := make(map[string]struct{})
	seenEntries["manifest.yaml"] = struct{}{}

	// Step 3: Stream and extract remaining archive entries safely
	for {
		hdr, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar reading error: %w", err)
		}

		// Reject symlinks, hardlinks, character devices, block devices, and FIFOs
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			return nil, &SecurityVerificationError{
				Reason: fmt.Sprintf("forbidden entry type '%c' for entry '%s'", hdr.Typeflag, hdr.Name),
			}
		}

		cleanEntry := path.Clean(strings.ReplaceAll(hdr.Name, "\\", "/"))

		// Allow directory header "artifacts" or "artifacts/"
		if hdr.Typeflag == tar.TypeDir {
			if cleanEntry != "artifacts" {
				return nil, &ArchiveLayoutError{
					Reason: fmt.Sprintf("forbidden directory entry '%s' in archive", hdr.Name),
				}
			}
			continue
		}

		if _, duplicate := seenEntries[cleanEntry]; duplicate {
			return nil, &ArchiveLayoutError{
				Reason: fmt.Sprintf("duplicate entry '%s' found in archive", cleanEntry),
			}
		}
		seenEntries[cleanEntry] = struct{}{}

		// Handle sbom.json
		if cleanEntry == "sbom.json" {
			if hdr.Size > maxSBOMSize {
				return nil, &ArchiveLayoutError{
					Reason: fmt.Sprintf("sbom.json size (%d bytes) exceeds maximum limit (%d bytes)", hdr.Size, maxSBOMSize),
				}
			}
			sbomData, err := io.ReadAll(io.LimitReader(tarReader, maxSBOMSize+1))
			if err != nil {
				return nil, fmt.Errorf("failed reading sbom.json: %w", err)
			}
			if int64(len(sbomData)) > maxSBOMSize {
				return nil, &ArchiveLayoutError{Reason: "sbom.json exceeded maximum size limit"}
			}
			// Verify SBOM digest against manifest binding if specified
			if mf.SBOM.SHA256 != "" {
				h := sha256.Sum256(sbomData)
				actualSBOMDigest := hex.EncodeToString(h[:])
				if !strings.EqualFold(actualSBOMDigest, mf.SBOM.SHA256) {
					return nil, &DigestMismatchError{
						Artifact: "sbom.json",
						Expected: mf.SBOM.SHA256,
						Actual:   actualSBOMDigest,
					}
				}
			}
			continue
		}

		// Entries must be of the form "artifacts/<filename>"
		if !strings.HasPrefix(cleanEntry, "artifacts/") {
			return nil, &ArchiveLayoutError{
				Reason: fmt.Sprintf("unexpected entry '%s' outside 'artifacts/' prefix", hdr.Name),
			}
		}

		filename := strings.TrimPrefix(cleanEntry, "artifacts/")
		if strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
			return nil, &ArchiveLayoutError{
				Reason: fmt.Sprintf("nested directories inside artifacts are forbidden: '%s'", cleanEntry),
			}
		}

		if err := pathutil.ValidateFilename(filename); err != nil {
			return nil, &ArchiveLayoutError{
				Reason: fmt.Sprintf("invalid artifact filename '%s': %v", filename, err),
			}
		}

		artMeta, declared := manifestArtifacts[filename]
		if !declared {
			return nil, &SecurityVerificationError{
				Reason: fmt.Sprintf("unadvertised artifact '%s' found in bundle archive", filename),
			}
		}

		if artMeta.SizeBytes > maxArtifactSize {
			return nil, &ArchiveLayoutError{
				Reason: fmt.Sprintf("artifact '%s' size (%d bytes) exceeds maximum limit (%d bytes)",
					filename, artMeta.SizeBytes, maxArtifactSize),
			}
		}

		// Stage artifact stream with bounded length and streaming SHA-256 computation
		stagedFile, err := os.CreateTemp(stagingDir, "stage-art-*")
		if err != nil {
			return nil, fmt.Errorf("failed creating staging file: %w", err)
		}
		stagedPath := stagedFile.Name()

		hasher := sha256.New()
		writer := io.MultiWriter(stagedFile, hasher)

		// Read up to SizeBytes + 1 to detect oversized streams
		boundedReader := io.LimitReader(tarReader, artMeta.SizeBytes+1)
		bytesWritten, copyErr := io.Copy(writer, boundedReader)
		_ = stagedFile.Sync()
		_ = stagedFile.Close()

		if copyErr != nil {
			return nil, fmt.Errorf("error reading artifact '%s': %w", filename, copyErr)
		}

		if bytesWritten > artMeta.SizeBytes {
			return nil, &SizeMismatchError{
				Artifact: filename,
				Expected: artMeta.SizeBytes,
				Actual:   bytesWritten,
			}
		}
		if bytesWritten < artMeta.SizeBytes {
			return nil, &SizeMismatchError{
				Artifact: filename,
				Expected: artMeta.SizeBytes,
				Actual:   bytesWritten,
			}
		}

		actualHash := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(actualHash, artMeta.SHA256) {
			return nil, &DigestMismatchError{
				Artifact: filename,
				Expected: artMeta.SHA256,
				Actual:   actualHash,
			}
		}

		stagedMap[filename] = stagedArtifact{
			Meta:     artMeta,
			TempPath: stagedPath,
		}
	}

	// Step 4: Completeness verification: Ensure all declared artifacts were found
	for _, art := range mf.Artifacts {
		if _, found := stagedMap[art.Filename]; !found {
			return nil, &SecurityVerificationError{
				Reason: fmt.Sprintf("artifact '%s' declared in manifest but missing from bundle archive", art.Filename),
			}
		}
	}

	// Step 5: Transactional Promotion to GDC Local Registry
	imagesDir := filepath.Join(opts.TargetRegistryDir, "images")
	if err := os.MkdirAll(imagesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed creating registry images directory: %w", err)
	}

	catalogPath := filepath.Join(opts.TargetRegistryDir, "catalog.yaml")
	catalog := RegistryCatalog{
		Version: "v1",
		Images:  make(map[string]RegistryCatalogEntry),
	}

	if catData, err := os.ReadFile(catalogPath); err == nil {
		if err := yaml.Unmarshal(catData, &catalog); err != nil {
			return nil, fmt.Errorf("failed parsing existing catalog.yaml: %w", err)
		}
		if catalog.Images == nil {
			catalog.Images = make(map[string]RegistryCatalogEntry)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed reading catalog.yaml: %w", err)
	}

	// Check overwrite policy against existing catalog entries
	if !opts.AllowOverwrite {
		for _, art := range mf.Artifacts {
			if existing, exists := catalog.Images[art.Name]; exists {
				if !strings.EqualFold(existing.SHA256, art.SHA256) {
					return nil, &CatalogConflictError{
						Artifact: art.Name,
						Reason: fmt.Sprintf("image already registered with differing digest (%s != %s)",
							existing.SHA256, art.SHA256),
					}
				}
			}
		}
	}

	// Promote all staged artifact files to images directory
	for filename, staged := range stagedMap {
		targetFile, err := pathutil.SafeJoin(imagesDir, filename)
		if err != nil {
			return nil, fmt.Errorf("unsafe target path for %s: %w", filename, err)
		}

		// Stage into temp file in target imagesDir for cross-volume atomic rename safety
		tmpDest, err := os.CreateTemp(imagesDir, ".tmp-promote-*")
		if err != nil {
			return nil, fmt.Errorf("failed creating promote temp file: %w", err)
		}
		tmpDestPath := tmpDest.Name()

		src, err := os.Open(staged.TempPath)
		if err != nil {
			_ = tmpDest.Close()
			_ = os.Remove(tmpDestPath)
			return nil, fmt.Errorf("failed opening staged file: %w", err)
		}

		_, copyErr := io.Copy(tmpDest, src)
		_ = src.Close()
		_ = tmpDest.Sync()
		_ = tmpDest.Close()

		if copyErr != nil {
			_ = os.Remove(tmpDestPath)
			return nil, fmt.Errorf("failed writing artifact to registry: %w", copyErr)
		}

		if err := pathutil.SafeReplaceFile(tmpDestPath, targetFile); err != nil {
			_ = os.Remove(tmpDestPath)
			return nil, fmt.Errorf("failed committing artifact file %s: %w", filename, err)
		}
	}

	// Update catalog in memory and atomically persist to disk
	now := time.Now().UTC()
	for _, art := range mf.Artifacts {
		catalog.Images[art.Name] = RegistryCatalogEntry{
			Name:        art.Name,
			Filename:    art.Filename,
			SHA256:      art.SHA256,
			SizeBytes:   art.SizeBytes,
			OSFamily:    art.OSFamily,
			Description: art.Description,
			AddedAt:     now,
		}
	}

	catalogBytes, err := yaml.Marshal(catalog)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling catalog YAML: %w", err)
	}

	tmpCatFile, err := os.CreateTemp(opts.TargetRegistryDir, ".tmp-catalog-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed creating temp catalog file: %w", err)
	}
	tmpCatPath := tmpCatFile.Name()

	var catSuccess bool
	defer func() {
		if !catSuccess {
			_ = tmpCatFile.Close()
			_ = os.Remove(tmpCatPath)
		}
	}()

	if _, err := tmpCatFile.Write(catalogBytes); err != nil {
		return nil, fmt.Errorf("failed writing temp catalog: %w", err)
	}
	if err := tmpCatFile.Sync(); err != nil {
		return nil, fmt.Errorf("failed syncing temp catalog: %w", err)
	}
	if err := tmpCatFile.Close(); err != nil {
		return nil, fmt.Errorf("failed closing temp catalog: %w", err)
	}

	if err := pathutil.SafeReplaceFile(tmpCatPath, catalogPath); err != nil {
		return nil, fmt.Errorf("failed committing catalog file: %w", err)
	}
	catSuccess = true

	return &IngestReport{
		BundleID:        mf.BundleID,
		SignerIdentity:  mf.SignerIdentity,
		KeyID:           mf.KeyID,
		VerifiedAt:      now,
		IngestedImages:  mf.Artifacts,
		CatalogFilePath: catalogPath,
	}, nil
}
