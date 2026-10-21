package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/uday68/gdc-airgap-sync/pkg/bundler"
	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
)

func TestIngest_EndToEndVerifiedPipeline(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gdc-sync-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Generate Keypair
	pubKey, privKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("failed generating keys: %v", err)
	}

	// 2. Create sample source image
	srcImage := filepath.Join(tempDir, "rhel-9-airgap.qcow2")
	payload := []byte("VERIFIED_RHEL_9_DISASTER_RECOVERY_BASE_IMAGE")
	if err := os.WriteFile(srcImage, payload, 0644); err != nil {
		t.Fatalf("failed writing src image: %v", err)
	}

	bundlePath := filepath.Join(tempDir, "rhel-9.bundle.tar.gz")

	// 3. Create Bundle in Connected Zone
	mf, err := bundler.CreateBundle(bundler.BundleOptions{
		Name:           "rhel-9",
		SourceFilePath: srcImage,
		OSFamily:       "linux",
		Description:    "Red Hat Enterprise Linux 9 Hardened Air-Gapped Image",
		SignerIdentity: "releng@cloud.google.com",
		PrivateKey:     privKey,
		OutputPath:     bundlePath,
	})
	if err != nil {
		t.Fatalf("failed creating bundle: %v", err)
	}
	if mf.Signature == "" {
		t.Fatalf("manifest signature is empty")
	}

	// 4. Ingest Bundle in Air-Gapped Zone
	registryDir := filepath.Join(tempDir, "gdc-registry")
	report, err := IngestBundle(bundlePath, pubKey, registryDir)
	if err != nil {
		t.Fatalf("failed ingesting valid bundle: %v", err)
	}

	if report.BundleID != mf.BundleID {
		t.Errorf("expected bundle ID %s, got %s", mf.BundleID, report.BundleID)
	}

	// 5. Verify image exists in target registry
	ingestedImgPath := filepath.Join(registryDir, "images", "rhel-9-airgap.qcow2")
	data, err := os.ReadFile(ingestedImgPath)
	if err != nil {
		t.Fatalf("ingested image file not found in registry: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("ingested payload mismatch")
	}

	// 6. Security Test: Ingest with wrong/untrusted public key must fail
	untrustedPub, _, _ := crypto.GenerateKeypair()
	_, err = IngestBundle(bundlePath, untrustedPub, registryDir)
	if err == nil {
		t.Fatalf("expected signature verification failure with untrusted public key, but succeeded")
	}
	if _, ok := err.(*SecurityVerificationError); !ok {
		t.Errorf("expected *SecurityVerificationError, got %T: %v", err, err)
	}
}
