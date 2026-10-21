package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/bundler"
	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/ingest"
	"github.com/uday68/gdc-airgap-sync/pkg/truststore"
	"gopkg.in/yaml.v3"
)

// VMOperatorCatalogEntry mirrors gdc-vm-operator/pkg/registry.CatalogEntry
type VMOperatorCatalogEntry struct {
	Name        string    `yaml:"name"`
	Filename    string    `yaml:"filename"`
	SHA256      string    `yaml:"sha256"`
	SizeBytes   int64     `yaml:"sizeBytes"`
	OSFamily    string    `yaml:"osFamily"`
	Description string    `yaml:"description"`
	AddedAt     time.Time `yaml:"addedAt"`
}

// VMOperatorCatalog mirrors gdc-vm-operator/pkg/registry.Catalog
type VMOperatorCatalog struct {
	Version string                            `yaml:"version"`
	Images  map[string]VMOperatorCatalogEntry `yaml:"images"`
}

func TestE2E_FullCrossBoundaryPipeline(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gdc-airgap-e2e-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Step 1: Connected Zone - Key generation
	pubKey, privKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed generating keypair: %v", err)
	}

	keysDir := filepath.Join(tempDir, "connected-keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatal(err)
	}
	privPEMPath := filepath.Join(keysDir, "release-private.pem")
	pubPEMPath := filepath.Join(keysDir, "release-public.pem")
	if err := crypto.SavePEM(privKey, pubKey, privPEMPath, pubPEMPath); err != nil {
		t.Fatalf("failed saving PEM: %v", err)
	}

	// Step 2: Connected Zone - Prepare VM image artifact and real SPDX SBOM
	srcImage := filepath.Join(tempDir, "rocky-9-hardened.qcow2")
	imagePayload := []byte("SIMULATED_ROCKY_LINUX_9_QCOW2_GOLD_DISK_IMAGE_PAYLOAD")
	if err := os.WriteFile(srcImage, imagePayload, 0644); err != nil {
		t.Fatal(err)
	}

	sbomFile := filepath.Join(tempDir, "rocky-9.spdx.json")
	sbomContent := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "rocky-9-hardened-sbom",
		"packages": [
			{"name": "kernel-core", "versionInfo": "5.14.0"},
			{"name": "systemd", "versionInfo": "252"},
			{"name": "openssh-server", "versionInfo": "8.7p1"}
		]
	}`)
	if err := os.WriteFile(sbomFile, sbomContent, 0644); err != nil {
		t.Fatal(err)
	}

	bundleOut := filepath.Join(tempDir, "rocky-9.bundle.tar.gz")
	signerIdentity := "releng@cloud-supply-chain.org"

	bundleMf, err := bundler.CreateBundle(bundler.BundleOptions{
		Name:           "rocky-9",
		SourceFilePath: srcImage,
		OSFamily:       "linux",
		Description:    "Rocky Linux 9 Air-Gapped Gold Image",
		SignerIdentity: signerIdentity,
		PrivateKey:     privKey,
		OutputPath:     bundleOut,
		Origin:         "connected-releng-ci",
		ReleaseID:      "v9.4-rc1",
		SBOMPath:       sbomFile,
		Timestamp:      time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("failed creating bundle: %v", err)
	}

	// Invariant: truthful metadata
	if bundleMf.Origin != "connected-releng-ci" {
		t.Errorf("origin should reflect declared build origin, got %q", bundleMf.Origin)
	}
	if bundleMf.SBOM.Format != "SPDX-2.3" || bundleMf.SBOM.SHA256 == "" {
		t.Errorf("SBOM binding missing or invalid: %+v", bundleMf.SBOM)
	}

	// Step 3: Physical Transfer Across Air Gap -> Disconnected Zone
	// Step 4: Disconnected Zone - Setup Offline Trust Store
	ts := truststore.New()
	keyEntry, err := ts.AddKey(pubKey, signerIdentity, "os-images")
	if err != nil {
		t.Fatalf("failed adding key to trust store: %v", err)
	}
	trustStorePath := filepath.Join(tempDir, "truststore.yaml")
	if err := ts.SaveToFile(trustStorePath); err != nil {
		t.Fatalf("failed saving trust store: %v", err)
	}

	// Step 5: Disconnected Zone - Ingest into gdc-vm-operator Registry
	operatorRegistryDir := filepath.Join(tempDir, "gdc-operator-registry")
	report, err := ingest.IngestBundleWithOptions(ingest.IngestOptions{
		BundlePath:        bundleOut,
		TrustStore:        ts,
		TargetRegistryDir: operatorRegistryDir,
	})
	if err != nil {
		t.Fatalf("ingestion failed: %v", err)
	}

	if report.BundleID != bundleMf.BundleID {
		t.Errorf("bundle ID mismatch: expected %s, got %s", bundleMf.BundleID, report.BundleID)
	}
	if report.KeyID != keyEntry.KeyID {
		t.Errorf("key ID mismatch: expected %s, got %s", keyEntry.KeyID, report.KeyID)
	}

	// Step 6: Verify cross-repository contract with gdc-vm-operator
	// Ingested image exists in images/
	promotedImgPath := filepath.Join(operatorRegistryDir, "images", "rocky-9-hardened.qcow2")
	data, err := os.ReadFile(promotedImgPath)
	if err != nil {
		t.Fatalf("promoted image not found: %v", err)
	}
	if string(data) != string(imagePayload) {
		t.Errorf("promoted image data corrupted")
	}

	// Catalog matches gdc-vm-operator's Catalog schema
	catBytes, err := os.ReadFile(filepath.Join(operatorRegistryDir, "catalog.yaml"))
	if err != nil {
		t.Fatalf("failed reading catalog.yaml: %v", err)
	}

	var opCatalog VMOperatorCatalog
	if err := yaml.Unmarshal(catBytes, &opCatalog); err != nil {
		t.Fatalf("catalog failed to unmarshal into gdc-vm-operator catalog schema: %v", err)
	}

	if opCatalog.Version != "v1" {
		t.Errorf("expected catalog version 'v1', got %q", opCatalog.Version)
	}
	opEntry, found := opCatalog.Images["rocky-9"]
	if !found {
		t.Fatalf("entry 'rocky-9' not found in operator catalog")
	}
	if opEntry.Filename != "rocky-9-hardened.qcow2" {
		t.Errorf("expected filename 'rocky-9-hardened.qcow2', got %q", opEntry.Filename)
	}
	if !strings.EqualFold(opEntry.SHA256, bundleMf.Artifacts[0].SHA256) {
		t.Errorf("SHA256 mismatch in operator catalog: %s != %s", opEntry.SHA256, bundleMf.Artifacts[0].SHA256)
	}
	if opEntry.AddedAt.IsZero() {
		t.Errorf("operator catalog entry has zero AddedAt timestamp")
	}
}
