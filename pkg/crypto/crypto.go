package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateKeypair produces a new Ed25519 public/private keypair.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating Ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// EncodePrivateKeyPEM encodes an Ed25519 private key into PKCS#8 PEM format.
func EncodePrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling private key: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	return pem.EncodeToMemory(privBlock), nil
}

// EncodePublicKeyPEM encodes an Ed25519 public key into PKIX PEM format.
func EncodePublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return pem.EncodeToMemory(pubBlock), nil
}

// SavePEM exports keys into standard PKCS#8 PEM formatted files.
func SavePEM(priv ed25519.PrivateKey, pub ed25519.PublicKey, privPath, pubPath string) error {
	privPEM, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("failed writing private key PEM: %w", err)
	}

	pubPEM, err := EncodePublicKeyPEM(pub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("failed writing public key PEM: %w", err)
	}

	return nil
}

// ParsePrivateKeyFromPEM parses an Ed25519 private key from PEM bytes.
func ParsePrivateKeyFromPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in private key")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing PKCS#8 private key: %w", err)
	}

	privKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 private key")
	}

	return privKey, nil
}

// ParsePublicKeyFromPEM parses an Ed25519 public key from PEM bytes.
func ParsePublicKeyFromPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in public key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing PKIX public key: %w", err)
	}

	pubKey, ok := parsedKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 public key")
	}

	return pubKey, nil
}

// LoadPrivateKeyPEM parses an Ed25519 private key from a PEM file.
func LoadPrivateKeyPEM(filePath string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading private key file: %w", err)
	}
	return ParsePrivateKeyFromPEM(data)
}

// LoadPublicKeyPEM parses an Ed25519 public key from a PEM file.
func LoadPublicKeyPEM(filePath string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading public key file: %w", err)
	}
	return ParsePublicKeyFromPEM(data)
}

// PublicKeyFingerprint computes the deterministic SHA-256 fingerprint of an Ed25519 public key.
func PublicKeyFingerprint(pubKey ed25519.PublicKey) string {
	h := sha256.Sum256(pubKey)
	return "sha256:" + hex.EncodeToString(h[:])
}

// Sign generates an Ed25519 cryptographic signature returned as hex.
func Sign(privKey ed25519.PrivateKey, data []byte) string {
	sig := ed25519.Sign(privKey, data)
	return hex.EncodeToString(sig)
}

// Verify checks the hex signature against the data using the public key.
func Verify(pubKey ed25519.PublicKey, data []byte, sigHex string) bool {
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey, data, sigBytes)
}
