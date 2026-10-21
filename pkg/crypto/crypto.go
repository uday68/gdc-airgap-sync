package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
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

// SavePEM exports keys into standard PKCS#8 PEM formatted files.
func SavePEM(priv ed25519.PrivateKey, pub ed25519.PublicKey, privPath, pubPath string) error {
	// Encode private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed marshaling private key: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600); err != nil {
		return fmt.Errorf("failed writing private key PEM: %w", err)
	}

	// Encode public key
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed marshaling public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644); err != nil {
		return fmt.Errorf("failed writing public key PEM: %w", err)
	}

	return nil
}

// LoadPrivateKeyPEM parses an Ed25519 private key from a PEM file.
func LoadPrivateKeyPEM(filePath string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in private key file")
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

// LoadPublicKeyPEM parses an Ed25519 public key from a PEM file.
func LoadPublicKeyPEM(filePath string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data in public key file")
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

// Sign generates an Ed25519 cryptographic signature returned as hex.
func Sign(privKey ed25519.PrivateKey, data []byte) string {
	sig := ed25519.Sign(privKey, data)
	return hex.EncodeToString(sig)
}

// Verify checks the hex signature against the data using the public key.
func Verify(pubKey ed25519.PublicKey, data []byte, sigHex string) bool {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(pubKey, data, sigBytes)
}
