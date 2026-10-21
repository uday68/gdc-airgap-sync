package bundler

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
	"github.com/uday68/gdc-airgap-sync/pkg/pathutil"
	"gopkg.in/yaml.v3"
)

// BundleOptions specifies packaging and signing parameters.
type BundleOptions struct {
	Name           string
	SourceFilePath string
	OSFamily       string
	Description    string
	SignerIdentity string
	PrivateKey     ed25519.PrivateKey
	OutputPath     string
	Origin         string
	ReleaseID      string
	SBOMPath       string
	DemoFixture    bool
	Timestamp      time.Time
}

// CreateBundle builds and signs a compressed .tar.gz air-gap release archive.
func CreateBundle(opts BundleOptions) (*manifest.BundleManifest, error) {
	if err := pathutil.ValidateResourceName(opts.Name); err != nil {
		return nil, fmt.Errorf("invalid artifact name: %w", err)
	}
	if opts.SourceFilePath == "" {
		return nil, fmt.Errorf("source file path is required")
	}
	if len(opts.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key")
	}
	if opts.SignerIdentity == "" {
		return nil, fmt.Errorf("signer identity is required")
	}
	if opts.OutputPath == "" {
		return nil, fmt.Errorf("output path is required")
	}

	srcInfo, err := os.Stat(opts.SourceFilePath)
	if err != nil {
		return nil, fmt.Errorf("source artifact file not found: %w", err)
	}

	filename := filepath.Base(opts.SourceFilePath)
	if err := pathutil.ValidateFilename(filename); err != nil {
		return nil, fmt.Errorf("invalid source filename: %w", err)
	}

	// 1. Calculate streaming SHA-256 of artifact
	fileHash, err := computeSHA256(opts.SourceFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed computing artifact digest: %w", err)
	}

	// Determine normalized timestamp for reproducible packaging
	buildTime := opts.Timestamp
	if buildTime.IsZero() {
		buildTime = srcInfo.ModTime().UTC().Truncate(time.Second)
	} else {
		buildTime = buildTime.UTC().Truncate(time.Second)
	}

	// Truthful origin
	origin := opts.Origin
	if origin == "" {
		if opts.DemoFixture {
			origin = "fixture:demo-pipeline"
		} else {
			origin = "developer-build"
		}
	}

	// Public key and KeyID fingerprint
	pubKey := opts.PrivateKey.Public().(ed25519.PublicKey)
	keyID := crypto.PublicKeyFingerprint(pubKey)

	artifact := manifest.ArtifactMeta{
		Name:        opts.Name,
		Filename:    filename,
		SHA256:      fileHash,
		SizeBytes:   srcInfo.Size(),
		OSFamily:    opts.OSFamily,
		Description: opts.Description,
		AddedAt:     buildTime,
	}

	// Handle SBOM
	var sbomMeta manifest.SBOMMeta
	var sbomBytes []byte

	if opts.SBOMPath != "" {
		data, err := os.ReadFile(opts.SBOMPath)
		if err != nil {
			return nil, fmt.Errorf("failed reading SBOM file: %w", err)
		}
		sbomBytes = data
		h := sha256.Sum256(data)
		sbomMeta = manifest.SBOMMeta{
			Format:   "SPDX-2.3",
			Filename: "sbom.json",
			SHA256:   hex.EncodeToString(h[:]),
		}
	} else if opts.DemoFixture {
		sbomBytes = []byte(`{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"synthetic-demo-sbom"}`)
		h := sha256.Sum256(sbomBytes)
		sbomMeta = manifest.SBOMMeta{
			Format:        "SPDX-2.3",
			SpecVersion:   "2.3",
			Filename:      "sbom.json",
			SHA256:        hex.EncodeToString(h[:]),
			PackagesCount: 1,
			KeyPackages:   []string{"synthetic-base-package"},
		}
	} else {
		sbomMeta = manifest.SBOMMeta{
			Format: "none",
		}
	}

	bundleID := opts.Name
	if opts.ReleaseID != "" {
		bundleID = fmt.Sprintf("%s-%s", opts.Name, opts.ReleaseID)
	} else {
		bundleID = fmt.Sprintf("%s-%d", opts.Name, buildTime.Unix())
	}

	// 2. Construct Manifest
	mf := &manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       bundleID,
		ReleaseID:      opts.ReleaseID,
		CreatedAt:      buildTime,
		Origin:         origin,
		SignerIdentity: opts.SignerIdentity,
		KeyID:          keyID,
		Artifacts:      []manifest.ArtifactMeta{artifact},
		SBOM:           sbomMeta,
	}

	if err := mf.Validate(); err != nil {
		return nil, fmt.Errorf("manifest validation failed: %w", err)
	}

	// 3. Cryptographic Signature over Canonical Bytes
	canonicalBytes, err := mf.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	mf.Signature = crypto.Sign(opts.PrivateKey, canonicalBytes)

	// 4. Create destination directory if needed
	outDir := filepath.Dir(opts.OutputPath)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("failed creating output directory: %w", err)
	}

	// 5. Stage writing to temporary file for atomic publishing
	tmpFile, err := os.CreateTemp(outDir, ".tmp-bundle-*.tar.gz")
	if err != nil {
		return nil, fmt.Errorf("failed creating temp bundle archive: %w", err)
	}
	tmpPath := tmpFile.Name()

	var success bool
	defer func() {
		if !success {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	gw := gzip.NewWriter(tmpFile)
	gw.Header.ModTime = buildTime
	gw.Header.OS = 255 // normalized unknown OS for reproducible archives

	tw := tar.NewWriter(gw)

	// Entry 1: manifest.yaml (MUST BE FIRST)
	manifestYAML, err := yaml.Marshal(mf)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling manifest YAML: %w", err)
	}
	if err := addFileToTar(tw, "manifest.yaml", manifestYAML, buildTime); err != nil {
		return nil, err
	}

	// Entry 2: sbom.json (if present)
	if len(sbomBytes) > 0 {
		if err := addFileToTar(tw, "sbom.json", sbomBytes, buildTime); err != nil {
			return nil, err
		}
	}

	// Entry 3: artifacts/<clean-filename> (MUST use forward slash)
	srcFile, err := os.Open(opts.SourceFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening source file: %w", err)
	}
	defer srcFile.Close()

	tarArtifactPath := path.Join("artifacts", filename)
	hdr := &tar.Header{
		Name:     tarArtifactPath,
		Mode:     0644,
		Size:     srcInfo.Size(),
		ModTime:  buildTime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, fmt.Errorf("failed writing tar header for %s: %w", tarArtifactPath, err)
	}
	if _, err := io.Copy(tw, srcFile); err != nil {
		return nil, fmt.Errorf("failed copying artifact to tar: %w", err)
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed finalizing tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("failed finalizing gzip: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return nil, fmt.Errorf("failed syncing bundle: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed closing temp bundle: %w", err)
	}

	if err := pathutil.SafeReplaceFile(tmpPath, opts.OutputPath); err != nil {
		return nil, fmt.Errorf("failed committing bundle file: %w", err)
	}

	success = true
	return mf, nil
}

func addFileToTar(tw *tar.Writer, name string, content []byte, modTime time.Time) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0644,
		Size:     int64(len(content)),
		ModTime:  modTime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("failed writing tar header for %s: %w", name, err)
	}
	if _, err := tw.Write(content); err != nil {
		return fmt.Errorf("failed writing content for %s: %w", name, err)
	}
	return nil
}

func computeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
