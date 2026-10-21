package ingest

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func FuzzIngestArchive(f *testing.F) {
	// Seed with empty, random, and header bytes
	f.Add([]byte{})
	f.Add([]byte("not-a-gzip-archive"))
	f.Add([]byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"))

	pubKey := make(ed25519.PublicKey, ed25519.PublicKeySize)

	f.Fuzz(func(t *testing.T, data []byte) {
		tempDir, err := os.MkdirTemp("", "fuzz-ingest-*")
		if err != nil {
			return
		}
		defer os.RemoveAll(tempDir)

		bundlePath := filepath.Join(tempDir, "bundle.tar.gz")
		if err := os.WriteFile(bundlePath, data, 0644); err != nil {
			return
		}

		registryDir := filepath.Join(tempDir, "registry")

		// Fuzz execution must not panic
		_, _ = IngestBundleWithOptions(IngestOptions{
			BundlePath:        bundlePath,
			TrustedPubKey:     pubKey,
			TargetRegistryDir: registryDir,
			MaxManifestSize:   64 << 10,
			MaxSBOMSize:       64 << 10,
			MaxArtifactSize:   1 << 20,
		})
	})
}
