package crypto

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
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

	// 5. Invalid hex or size
	if Verify(pub, payload, "not-hex") {
		t.Errorf("expected failure on invalid hex")
	}
	if Verify(ed25519.PublicKey([]byte("short")), payload, sigHex) {
		t.Errorf("expected failure on short pubkey")
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

func TestCrypto_PublicKeyFingerprint(t *testing.T) {
	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	fp := PublicKeyFingerprint(pub)
	if !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("expected sha256 prefix, got: %s", fp)
	}
	hexPart := strings.TrimPrefix(fp, "sha256:")
	if len(hexPart) != 64 {
		t.Fatalf("expected 64 hex characters, got: %d", len(hexPart))
	}

	// Deterministic
	if PublicKeyFingerprint(pub) != fp {
		t.Errorf("fingerprint is not deterministic")
	}
}

func BenchmarkCrypto_Ed25519Sign(b *testing.B) {
	_, priv, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte("SIMULATED_CANONICAL_MANIFEST_PAYLOAD_FOR_BENCHMARK")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Sign(priv, payload)
	}
}

func BenchmarkCrypto_Ed25519Verify(b *testing.B) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte("SIMULATED_CANONICAL_MANIFEST_PAYLOAD_FOR_BENCHMARK")
	sigHex := Sign(priv, payload)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !Verify(pub, payload, sigHex) {
			b.Fatal("verify failed")
		}
	}
}


