package truststore

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/pathutil"
	"gopkg.in/yaml.v3"
)

// KeyStatus represents the lifecycle state of a trusted release key.
type KeyStatus string

const (
	StatusActive  KeyStatus = "active"
	StatusRevoked KeyStatus = "revoked"
)

// TrustedKey represents a vetted public key allowed to sign air-gap release bundles.
type TrustedKey struct {
	KeyID            string     `json:"keyId" yaml:"keyId"`
	PublicKeyPEM     string     `json:"publicKeyPEM" yaml:"publicKeyPEM"`
	Identity         string     `json:"identity" yaml:"identity"`
	Scope            string     `json:"scope" yaml:"scope"` // e.g. "all", "os-images"
	Status           KeyStatus  `json:"status" yaml:"status"`
	NotBefore        time.Time  `json:"notBefore,omitempty" yaml:"notBefore,omitempty"`
	NotAfter         time.Time  `json:"notAfter,omitempty" yaml:"notAfter,omitempty"`
	AddedAt          time.Time  `json:"addedAt" yaml:"addedAt"`
	RevokedAt        *time.Time `json:"revokedAt,omitempty" yaml:"revokedAt,omitempty"`
	RevocationReason string     `json:"revocationReason,omitempty" yaml:"revocationReason,omitempty"`
}

// TrustStore stores authorized keys for offline air-gapped signature verification.
type TrustStore struct {
	Version string                `json:"version" yaml:"version"`
	Keys    map[string]TrustedKey `json:"keys" yaml:"keys"` // KeyID -> TrustedKey
	mu      sync.RWMutex
}

// New creates an empty TrustStore.
func New() *TrustStore {
	return &TrustStore{
		Version: "v1alpha1",
		Keys:    make(map[string]TrustedKey),
	}
}

// SingleKeyStore creates a transient TrustStore containing a single trusted public key.
func SingleKeyStore(pubKey ed25519.PublicKey, identity string) (*TrustStore, error) {
	ts := New()
	if _, err := ts.AddKey(pubKey, identity, "all"); err != nil {
		return nil, err
	}
	return ts, nil
}

// AddKey registers an authorized public key in the trust store.
func (ts *TrustStore) AddKey(pubKey ed25519.PublicKey, identity, scope string) (*TrustedKey, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(pubKey))
	}
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return nil, fmt.Errorf("signer identity cannot be empty")
	}
	if scope == "" {
		scope = "all"
	}

	pemBytes, err := crypto.EncodePublicKeyPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed encoding public key to PEM: %w", err)
	}

	keyID := crypto.PublicKeyFingerprint(pubKey)

	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry := TrustedKey{
		KeyID:        keyID,
		PublicKeyPEM: string(pemBytes),
		Identity:     identity,
		Scope:        scope,
		Status:       StatusActive,
		AddedAt:      time.Now().UTC(),
	}

	ts.Keys[keyID] = entry
	return &entry, nil
}

// RevokeKey marks an existing key as revoked with a mandatory reason.
func (ts *TrustStore) RevokeKey(keyID, reason string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	key, found := ts.Keys[keyID]
	if !found {
		return fmt.Errorf("key ID '%s' not found in trust store", keyID)
	}

	now := time.Now().UTC()
	key.Status = StatusRevoked
	key.RevokedAt = &now
	key.RevocationReason = reason
	ts.Keys[keyID] = key

	return nil
}

// GetKey retrieves a trusted key by key ID.
func (ts *TrustStore) GetKey(keyID string) (TrustedKey, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	key, found := ts.Keys[keyID]
	return key, found
}

// ListKeys returns all trusted keys.
func (ts *TrustStore) ListKeys() []TrustedKey {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	res := make([]TrustedKey, 0, len(ts.Keys))
	for _, k := range ts.Keys {
		res = append(res, k)
	}
	return res
}

// ValidateSigner checks if the given keyID and identity are trusted and active at time `now`.
// If valid, returns the parsed ed25519.PublicKey.
func (ts *TrustStore) ValidateSigner(keyID, identity string, now time.Time) (ed25519.PublicKey, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	key, found := ts.Keys[keyID]
	if !found {
		return nil, fmt.Errorf("key '%s' is not registered in trust store", keyID)
	}

	if key.Status != StatusActive {
		return nil, fmt.Errorf("key '%s' has been REVOKED: %s", keyID, key.RevocationReason)
	}

	if identity != "" && key.Identity != "" && key.Identity != identity {
		return nil, fmt.Errorf("key '%s' identity mismatch: expected '%s', manifest claims '%s'",
			keyID, key.Identity, identity)
	}

	if !key.NotBefore.IsZero() && now.Before(key.NotBefore) {
		return nil, fmt.Errorf("key '%s' is not yet valid (valid after %s)", keyID, key.NotBefore)
	}

	if !key.NotAfter.IsZero() && now.After(key.NotAfter) {
		return nil, fmt.Errorf("key '%s' has expired (expired at %s)", keyID, key.NotAfter)
	}

	pubKey, err := crypto.ParsePublicKeyFromPEM([]byte(key.PublicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("corrupt public key in trust store for '%s': %w", keyID, err)
	}

	return pubKey, nil
}

// LoadFromFile reads and unmarshals a trust store YAML file.
func LoadFromFile(filePath string) (*TrustStore, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading trust store file: %w", err)
	}

	var ts TrustStore
	if err := yaml.Unmarshal(data, &ts); err != nil {
		return nil, fmt.Errorf("failed parsing trust store YAML: %w", err)
	}

	if ts.Keys == nil {
		ts.Keys = make(map[string]TrustedKey)
	}

	return &ts, nil
}

// SaveToFile atomically serializes the trust store to disk.
func (ts *TrustStore) SaveToFile(filePath string) error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating trust store directory: %w", err)
	}

	data, err := yaml.Marshal(ts)
	if err != nil {
		return fmt.Errorf("failed marshaling trust store: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp-truststore-*.yaml")
	if err != nil {
		return fmt.Errorf("failed creating temp trust store file: %w", err)
	}
	tmpPath := tmpFile.Name()

	var success bool
	defer func() {
		if !success {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed writing trust store: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed syncing trust store: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed closing temp trust store: %w", err)
	}

	if err := pathutil.SafeReplaceFile(tmpPath, filePath); err != nil {
		return fmt.Errorf("failed committing trust store file: %w", err)
	}

	success = true
	return nil
}
