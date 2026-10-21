package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCrypto_SignAndVerify(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("failed generating keys: %v", err)
	}

	payload := []byte("CRITICAL_GDC_VM_IMAGE_DIGEST_LIST")

	// 1. Sign
	sigHex := Sign(priv, payload)
	if sigHex == "" {
		t.Fatalf("signature is empty")
	}

	// 2. Verify with valid key
	if !Verify(pub, payload, sigHex) {
		t.Fatalf("signature verification failed unexpectedly")
	}

	// 3. Tamper Detection (modify 1 byte of payload)
	tamperedPayload := []byte("CRITICAL_GDC_VM_IMAGE_DIGEST_LIST!")
	if Verify(pub, tamperedPayload, sigHex) {
		t.Fatalf("expected verification failure on tampered payload, but passed")
	}

	// 4. Verification with wrong public key
	otherPub, _, _ := GenerateKeypair()
	if Verify(otherPub, payload, sigHex) {
		t.Fatalf("expected verification failure with different public key")
	}
}

func TestCrypto_PEMExportAndImport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gdc-crypto-test-*")
	if err != nil {
		t.Fatalf("failed temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("failed generating keys: %v", err)
	}

	privPath := filepath.Join(tempDir, "release-private.pem")
	pubPath := filepath.Join(tempDir, "release-public.pem")

	// Export PEM
	if err := SavePEM(priv, pub, privPath, pubPath); err != nil {
		t.Fatalf("failed saving PEM: %v", err)
	}

	// Import PEM
	loadedPriv, err := LoadPrivateKeyPEM(privPath)
	if err != nil {
		t.Fatalf("failed loading private key PEM: %v", err)
	}
	loadedPub, err := LoadPublicKeyPEM(pubPath)
	if err != nil {
		t.Fatalf("failed loading public key PEM: %v", err)
	}

	// Sign with loaded private, verify with loaded public
	data := []byte("TEST_PAYLOAD")
	sig := Sign(loadedPriv, data)
	if !Verify(loadedPub, data, sig) {
		t.Fatalf("failed verification with PEM reloaded keys")
	}
}
