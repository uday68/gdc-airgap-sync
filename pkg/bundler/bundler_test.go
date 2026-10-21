package bundler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
	"gopkg.in/yaml.v3"
)

func TestCreateBundle_Success(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bundler-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	_, priv, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	srcFile := filepath.Join(tempDir, "disk.raw")
	payload := []byte("DISK_PAYLOAD_BYTES_FOR_VM")
	if err := os.WriteFile(srcFile, payload, 0644); err != nil {
		t.Fatal(err)
	}

	outBundle := filepath.Join(tempDir, "release.tar.gz")

	fixedTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	mf, err := CreateBundle(BundleOptions{
		Name:           "ubuntu-22.04",
		SourceFilePath: srcFile,
		OSFamily:       "linux",
		Description:    "Ubuntu Base Image",
		SignerIdentity: "releng@internal.net",
		PrivateKey:     priv,
		OutputPath:     outBundle,
		Origin:         "staging-ci",
		ReleaseID:      "v1.0.0",
		DemoFixture:    true,
		Timestamp:      fixedTime,
	})
	if err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}

	if mf.Origin != "staging-ci" {
		t.Errorf("expected origin 'staging-ci', got %q", mf.Origin)
	}
	if mf.Signature == "" {
		t.Errorf("expected non-empty signature")
	}

	// Read tar archive and verify structure
	f, err := os.Open(outBundle)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	// Entry 1: manifest.yaml
	hdr1, err := tr.Next()
	if err != nil {
		t.Fatalf("failed reading entry 1: %v", err)
	}
	if hdr1.Name != "manifest.yaml" {
		t.Fatalf("entry 1 must be 'manifest.yaml', got %q", hdr1.Name)
	}

	manifestBytes, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	var parsedMf manifest.BundleManifest
	if err := yaml.Unmarshal(manifestBytes, &parsedMf); err != nil {
		t.Fatalf("failed unmarshaling manifest from bundle: %v", err)
	}
	if parsedMf.BundleID != "ubuntu-22.04-v1.0.0" {
		t.Errorf("expected bundle ID 'ubuntu-22.04-v1.0.0', got %q", parsedMf.BundleID)
	}

	// Entry 2: sbom.json
	hdr2, err := tr.Next()
	if err != nil {
		t.Fatalf("failed reading entry 2: %v", err)
	}
	if hdr2.Name != "sbom.json" {
		t.Fatalf("entry 2 must be 'sbom.json', got %q", hdr2.Name)
	}

	// Entry 3: artifacts/disk.raw (with forward slash)
	hdr3, err := tr.Next()
	if err != nil {
		t.Fatalf("failed reading entry 3: %v", err)
	}
	expectedArtifactEntry := "artifacts/disk.raw"
	if hdr3.Name != expectedArtifactEntry {
		t.Fatalf("entry 3 must be %q, got %q", expectedArtifactEntry, hdr3.Name)
	}
	if strings.Contains(hdr3.Name, "\\") {
		t.Errorf("tar entry must not contain backslashes: %s", hdr3.Name)
	}

	artifactData, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(artifactData, payload) {
		t.Errorf("artifact payload corrupted in bundle")
	}

	// No more entries
	if _, err := tr.Next(); err != io.EOF {
		t.Errorf("expected EOF, got err: %v", err)
	}
}

func TestCreateBundle_Reproducibility(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "repro-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	_, priv, _ := crypto.GenerateKeypair()

	srcFile := filepath.Join(tempDir, "image.raw")
	if err := os.WriteFile(srcFile, []byte("REPRODUCIBLE_IMAGE_DATA"), 0644); err != nil {
		t.Fatal(err)
	}

	out1 := filepath.Join(tempDir, "bundle1.tar.gz")
	out2 := filepath.Join(tempDir, "bundle2.tar.gz")

	fixedTime := time.Date(2026, 5, 10, 10, 0, 0, 0, time.UTC)

	opts1 := BundleOptions{
		Name:           "debian-12",
		SourceFilePath: srcFile,
		OSFamily:       "linux",
		SignerIdentity: "ci@build.org",
		PrivateKey:     priv,
		OutputPath:     out1,
		Origin:         "test-repro",
		ReleaseID:      "build-101",
		Timestamp:      fixedTime,
	}

	opts2 := opts1
	opts2.OutputPath = out2

	if _, err := CreateBundle(opts1); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBundle(opts2); err != nil {
		t.Fatal(err)
	}

	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}

	h1 := sha256.Sum256(b1)
	h2 := sha256.Sum256(b2)

	if h1 != h2 {
		t.Fatalf("bundle creation is not byte-for-byte reproducible:\nbundle1: %s\nbundle2: %s",
			hex.EncodeToString(h1[:]), hex.EncodeToString(h2[:]))
	}
}

func TestCreateBundle_RealSBOM(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sbom-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	_, priv, _ := crypto.GenerateKeypair()
	srcFile := filepath.Join(tempDir, "image.raw")
	_ = os.WriteFile(srcFile, []byte("IMAGE"), 0644)

	sbomFile := filepath.Join(tempDir, "my-sbom.spdx.json")
	sbomContent := []byte(`{"spdxVersion":"SPDX-2.3","packages":[{"name":"kernel"}]}`)
	_ = os.WriteFile(sbomFile, sbomContent, 0644)

	outBundle := filepath.Join(tempDir, "bundle.tar.gz")
	mf, err := CreateBundle(BundleOptions{
		Name:           "custom-img",
		SourceFilePath: srcFile,
		SignerIdentity: "test@domain.com",
		PrivateKey:     priv,
		OutputPath:     outBundle,
		SBOMPath:       sbomFile,
	})
	if err != nil {
		t.Fatalf("CreateBundle failed: %v", err)
	}

	h := sha256.Sum256(sbomContent)
	expectedHex := hex.EncodeToString(h[:])
	if mf.SBOM.SHA256 != expectedHex {
		t.Errorf("expected SBOM digest %s, got %s", expectedHex, mf.SBOM.SHA256)
	}
}
