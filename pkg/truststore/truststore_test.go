package truststore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
)

func TestTrustStore_Lifecycle(t *testing.T) {
	ts := New()

	pub, _, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	identity := "releng@cloud.google.com"
	keyEntry, err := ts.AddKey(pub, identity, "os-images")
	if err != nil {
		t.Fatalf("failed to add key: %v", err)
	}

	keyID := keyEntry.KeyID

	// 1. Validate active key
	validatedPub, err := ts.ValidateSigner(keyID, identity, time.Now())
	if err != nil {
		t.Fatalf("validation failed for active key: %v", err)
	}
	if string(validatedPub) != string(pub) {
		t.Fatalf("retrieved public key does not match original")
	}

	// 2. Identity mismatch
	if _, err := ts.ValidateSigner(keyID, "impostor@evil.com", time.Now()); err == nil {
		t.Fatalf("expected error on identity mismatch, got nil")
	}

	// 3. Unknown key
	if _, err := ts.ValidateSigner("sha256:unknown", identity, time.Now()); err == nil {
		t.Fatalf("expected error on unknown key, got nil")
	}

	// 4. Revocation
	if err := ts.RevokeKey(keyID, "compromised private key on build machine"); err != nil {
		t.Fatalf("failed to revoke key: %v", err)
	}

	if _, err := ts.ValidateSigner(keyID, identity, time.Now()); err == nil {
		t.Fatalf("expected error validating revoked key, got nil")
	}
}

func TestTrustStore_ValidityWindow(t *testing.T) {
	ts := New()
	pub, _, _ := crypto.GenerateKeypair()

	entry, err := ts.AddKey(pub, "builder@corp.internal", "all")
	if err != nil {
		t.Fatal(err)
	}

	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entry.NotBefore = baseTime.Add(1 * time.Hour)
	entry.NotAfter = baseTime.Add(24 * time.Hour)
	ts.Keys[entry.KeyID] = *entry

	// Too early
	if _, err := ts.ValidateSigner(entry.KeyID, "builder@corp.internal", baseTime); err == nil {
		t.Errorf("expected error before NotBefore")
	}

	// In window
	if _, err := ts.ValidateSigner(entry.KeyID, "builder@corp.internal", baseTime.Add(2*time.Hour)); err != nil {
		t.Errorf("expected success within window, got: %v", err)
	}

	// Expired
	if _, err := ts.ValidateSigner(entry.KeyID, "builder@corp.internal", baseTime.Add(25*time.Hour)); err == nil {
		t.Errorf("expected error after NotAfter")
	}
}

func TestTrustStore_FilePersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	storePath := filepath.Join(tempDir, "truststore.yaml")
	ts := New()

	pub, _, _ := crypto.GenerateKeypair()
	entry, err := ts.AddKey(pub, "signer@test.org", "all")
	if err != nil {
		t.Fatal(err)
	}

	if err := ts.SaveToFile(storePath); err != nil {
		t.Fatalf("failed to save trust store: %v", err)
	}

	loaded, err := LoadFromFile(storePath)
	if err != nil {
		t.Fatalf("failed to load trust store: %v", err)
	}

	if len(loaded.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(loaded.Keys))
	}

	loadedEntry, found := loaded.GetKey(entry.KeyID)
	if !found {
		t.Fatalf("key %s not found in loaded trust store", entry.KeyID)
	}
	if loadedEntry.Identity != "signer@test.org" {
		t.Errorf("identity mismatch: %s", loadedEntry.Identity)
	}
}
