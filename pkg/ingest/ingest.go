package ingest

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
	"gopkg.in/yaml.v3"
)

// SecurityVerificationError indicates cryptographic signature failure or untrusted origin.
type SecurityVerificationError struct {
	Reason string
}

func (e *SecurityVerificationError) Error() string {
	return fmt.Sprintf("cryptographic security verification failed: %s", e.Reason)
}

// IngestReport summarizes the result of air-gap validation and repository ingestion.
type IngestReport struct {
	BundleID        string                  `json:"bundleId"`
	SignerIdentity  string                  `json:"signerIdentity"`
	VerifiedAt      time.Time               `json:"verifiedAt"`
	IngestedImages  []manifest.ArtifactMeta `json:"ingestedImages"`
	CatalogFilePath string                  `json:"catalogFilePath"`
}

// RegistryCatalog mirrors the structure of gdc-vm-operator/pkg/registry.
type RegistryCatalog struct {
	Version string                           `yaml:"version"`
	Images  map[string]manifest.ArtifactMeta `yaml:"images"`
}

// IngestBundle verifies signatures and digests before registering images into the local registry.
func IngestBundle(bundlePath string, trustedPubKey ed25519.PublicKey, targetRegistryDir string) (*IngestReport, error) {
	bundleFile, err := os.Open(bundlePath)
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

	var mf *manifest.BundleManifest
	var extractedFiles = make(map[string]string) // artifact filename -> temp extracted path

	imagesDir := filepath.Join(targetRegistryDir, "images")
	if err := os.MkdirAll(imagesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed creating registry images directory: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "gdc-airgap-ingest-*")
	if err != nil {
		return nil, fmt.Errorf("failed creating temp extraction dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Step 1: Scan tar archive and extract manifest first
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar reading error: %w", err)
		}

		cleanName := filepath.Clean(header.Name)

		if cleanName == "manifest.yaml" {
			data, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed reading manifest.yaml: %w", err)
			}
			var m manifest.BundleManifest
			if err := yaml.Unmarshal(data, &m); err != nil {
				return nil, fmt.Errorf("failed parsing manifest: %w", err)
			}
			mf = &m
			continue
		}

		if strings.HasPrefix(cleanName, "artifacts") {
			filename := filepath.Base(cleanName)
			tmpDst := filepath.Join(tempDir, filename)
			out, err := os.Create(tmpDst)
			if err != nil {
				return nil, fmt.Errorf("failed creating temp artifact file: %w", err)
			}

			hasher := sha256.New()
			writer := io.MultiWriter(out, hasher)

			if _, err := io.Copy(writer, tarReader); err != nil {
				_ = out.Close()
				return nil, fmt.Errorf("failed extracting artifact: %w", err)
			}
			_ = out.Close()

			actualHash := hex.EncodeToString(hasher.Sum(nil))
			extractedFiles[filename] = actualHash
		}
	}

	if mf == nil {
		return nil, &SecurityVerificationError{Reason: "bundle archive missing required manifest.yaml"}
	}

	// Step 2: Asymmetric Cryptographic Signature Verification
	canonicalBytes, err := mf.CanonicalBytes()
	if err != nil {
		return nil, err
	}

	if !crypto.Verify(trustedPubKey, canonicalBytes, mf.Signature) {
		return nil, &SecurityVerificationError{
			Reason: fmt.Sprintf("invalid digital signature for bundle '%s'; untrusted or tampered release package", mf.BundleID),
		}
	}

	// Step 3: Cryptographic Artifact Digest Verification
	for _, art := range mf.Artifacts {
		actualHash, found := extractedFiles[art.Filename]
		if !found {
			return nil, &SecurityVerificationError{
				Reason: fmt.Sprintf("artifact '%s' declared in manifest but missing in bundle archive", art.Filename),
			}
		}

		if !strings.EqualFold(actualHash, art.SHA256) {
			return nil, &SecurityVerificationError{
				Reason: fmt.Sprintf("checksum mismatch for '%s' (expected %s, got %s); disk tampering detected",
					art.Filename, art.SHA256, actualHash),
			}
		}
	}

	// Step 4: Promote verified images to GDC Local Registry
	for _, art := range mf.Artifacts {
		srcTemp := filepath.Join(tempDir, art.Filename)
		targetFile := filepath.Join(imagesDir, art.Filename)

		// Move or copy verified image into GDC images directory
		if err := copyFile(srcTemp, targetFile); err != nil {
			return nil, fmt.Errorf("failed copying verified image to registry: %w", err)
		}
	}

	// Step 5: Update GDC catalog.yaml
	catalogPath := filepath.Join(targetRegistryDir, "catalog.yaml")
	catalog := RegistryCatalog{
		Version: "v1",
		Images:  make(map[string]manifest.ArtifactMeta),
	}

	if data, err := os.ReadFile(catalogPath); err == nil {
		_ = yaml.Unmarshal(data, &catalog)
		if catalog.Images == nil {
			catalog.Images = make(map[string]manifest.ArtifactMeta)
		}
	}

	for _, art := range mf.Artifacts {
		catalog.Images[art.Name] = art
	}

	catalogBytes, err := yaml.Marshal(catalog)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling registry catalog: %w", err)
	}

	if err := os.WriteFile(catalogPath, catalogBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed updating catalog.yaml: %w", err)
	}

	return &IngestReport{
		BundleID:        mf.BundleID,
		SignerIdentity:  mf.SignerIdentity,
		VerifiedAt:      time.Now().UTC(),
		IngestedImages:  mf.Artifacts,
		CatalogFilePath: catalogPath,
	}, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
