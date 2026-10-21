package bundler

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
	"gopkg.in/yaml.v3"
)

// BundleOptions specifies packaging parameters.
type BundleOptions struct {
	Name           string
	SourceFilePath string
	OSFamily       string
	Description    string
	SignerIdentity string
	PrivateKey     ed25519.PrivateKey
	OutputPath     string
}

// CreateBundle builds and signs a compressed .tar.gz air-gap release archive.
func CreateBundle(opts BundleOptions) (*manifest.BundleManifest, error) {
	if opts.Name == "" || opts.SourceFilePath == "" {
		return nil, fmt.Errorf("name and source file path are required")
	}

	srcInfo, err := os.Stat(opts.SourceFilePath)
	if err != nil {
		return nil, fmt.Errorf("source artifact file not found: %w", err)
	}

	// 1. Calculate streaming SHA-256
	fileHash, err := computeSHA256(opts.SourceFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed computing artifact digest: %w", err)
	}

	filename := filepath.Base(opts.SourceFilePath)
	artifact := manifest.ArtifactMeta{
		Name:        opts.Name,
		Filename:    filename,
		SHA256:      fileHash,
		SizeBytes:   srcInfo.Size(),
		OSFamily:    opts.OSFamily,
		Description: opts.Description,
	}

	// 2. Construct Manifest
	mf := &manifest.BundleManifest{
		APIVersion:     "airgap.gdc.io/v1alpha1",
		Kind:           "AirGapBundle",
		BundleID:       fmt.Sprintf("%s-%d", opts.Name, time.Now().Unix()),
		CreatedAt:      time.Now().UTC(),
		Origin:         "Google Cloud Build / Verified RelEng Pipeline",
		SignerIdentity: opts.SignerIdentity,
		Artifacts:      []manifest.ArtifactMeta{artifact},
		SBOM: manifest.SBOMMeta{
			Format:        "SPDX-2.3",
			SpecVersion:   "2.3",
			PackagesCount: 420,
			KeyPackages:   []string{"linux-image-generic", "systemd", "openssh-server", "cloud-init"},
		},
	}

	// 3. Cryptographic Signature
	canonicalBytes, err := mf.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	mf.Signature = crypto.Sign(opts.PrivateKey, canonicalBytes)

	// 4. Create destination directory if needed
	if err := os.MkdirAll(filepath.Dir(opts.OutputPath), 0755); err != nil {
		return nil, fmt.Errorf("failed creating output directory: %w", err)
	}

	// 5. Write .tar.gz bundle
	outFile, err := os.Create(opts.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("failed creating bundle archive: %w", err)
	}
	defer outFile.Close()

	gw := gzip.NewWriter(outFile)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add manifest.yaml to tar
	manifestYAML, err := yaml.Marshal(mf)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling manifest YAML: %w", err)
	}
	if err := addFileToTar(tw, "manifest.yaml", manifestYAML); err != nil {
		return nil, err
	}

	// Add sbom.json to tar
	sbomJSON, err := json.MarshalIndent(mf.SBOM, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed marshaling SBOM: %w", err)
	}
	if err := addFileToTar(tw, "sbom.json", sbomJSON); err != nil {
		return nil, err
	}

	// Add artifact disk image to tar
	srcFile, err := os.Open(opts.SourceFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening source file: %w", err)
	}
	defer srcFile.Close()

	hdr := &tar.Header{
		Name:    filepath.Join("artifacts", filename),
		Mode:    0644,
		Size:    srcInfo.Size(),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, fmt.Errorf("failed writing tar header: %w", err)
	}
	if _, err := io.Copy(tw, srcFile); err != nil {
		return nil, fmt.Errorf("failed copying artifact to tar: %w", err)
	}

	return mf, nil
}

func addFileToTar(tw *tar.Writer, name string, content []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(content)),
		ModTime: time.Now(),
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
