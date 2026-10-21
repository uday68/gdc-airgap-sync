package ingest

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/bundler"
	"github.com/uday68/gdc-airgap-sync/pkg/crypto"
	"github.com/uday68/gdc-airgap-sync/pkg/manifest"
	"github.com/uday68/gdc-airgap-sync/pkg/truststore"
	"gopkg.in/yaml.v3"
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
		DemoFixture:    true,
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

	// 6. Verify catalog.yaml contents
	catalogData, err := os.ReadFile(filepath.Join(registryDir, "catalog.yaml"))
	if err != nil {
		t.Fatalf("failed reading catalog: %v", err)
	}
	var catalog RegistryCatalog
	if err := yaml.Unmarshal(catalogData, &catalog); err != nil {
		t.Fatalf("failed unmarshaling catalog: %v", err)
	}
	entry, found := catalog.Images["rhel-9"]
	if !found {
		t.Fatalf("catalog entry 'rhel-9' not found")
	}
	if entry.Filename != "rhel-9-airgap.qcow2" {
		t.Errorf("expected filename 'rhel-9-airgap.qcow2', got %q", entry.Filename)
	}
	if entry.AddedAt.IsZero() {
		t.Errorf("expected non-zero AddedAt in catalog entry")
	}
}

func TestIngest_UntrustedSignature_ZeroDiskWrites(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "untrusted-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	_, privKey, _ := crypto.GenerateKeypair()
	untrustedPub, _, _ := crypto.GenerateKeypair()

	srcFile := filepath.Join(tempDir, "malicious.raw")
	_ = os.WriteFile(srcFile, []byte("MALICIOUS_PAYLOAD"), 0644)

	bundlePath := filepath.Join(tempDir, "evil.tar.gz")
	_, err = bundler.CreateBundle(bundler.BundleOptions{
		Name:           "evil-image",
		SourceFilePath: srcFile,
		SignerIdentity: "attacker@evil.org",
		PrivateKey:     privKey,
		OutputPath:     bundlePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, untrustedPub, registryDir)
	if err == nil {
		t.Fatalf("expected error for untrusted signature, got nil")
	}

	var secErr *SecurityVerificationError
	if !errors.As(err, &secErr) {
		t.Errorf("expected *SecurityVerificationError, got: %v", err)
	}

	// Invariant check: target registry images must not exist or must be empty
	imagesDir := filepath.Join(registryDir, "images")
	if entries, readErr := os.ReadDir(imagesDir); readErr == nil && len(entries) > 0 {
		t.Errorf("security invariant violated: files written to registry despite signature failure: %v", entries)
	}
}

func TestIngest_TamperedPayload_DigestMismatch(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tamper-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	srcFile := filepath.Join(tempDir, "legit.raw")
	_ = os.WriteFile(srcFile, []byte("AUTHENTIC_BYTES"), 0644)

	bundlePath := filepath.Join(tempDir, "tampered.tar.gz")

	// Create valid manifest
	origHash := sha256.Sum256([]byte("AUTHENTIC_BYTES"))
	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "tampered-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "legit-image",
				Filename:  "legit.raw",
				SHA256:    hex.EncodeToString(origHash[:]),
				SizeBytes: int64(len("AUTHENTIC_BYTES")),
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	// Write archive with tampered bytes of the exact same size
	tamperedBytes := []byte("TAMPERED_BYTES!")
	if len(tamperedBytes) != len("AUTHENTIC_BYTES") {
		t.Fatal("test setup error")
	}

	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "artifacts/legit.raw", Content: tamperedBytes},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected digest mismatch error, got nil")
	}

	var dErr *DigestMismatchError
	if !errors.As(err, &dErr) {
		t.Errorf("expected *DigestMismatchError, got: %v", err)
	}

	// Verify target registry is empty
	targetImg := filepath.Join(registryDir, "images", "legit.raw")
	if _, err := os.Stat(targetImg); !os.IsNotExist(err) {
		t.Errorf("tampered image was promoted to registry!")
	}
}

func TestIngest_OversizedArtifact(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "oversized-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "oversized.tar.gz")

	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "oversized-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "oversized",
				Filename:  "oversized.raw",
				SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				SizeBytes: 10,
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	// Provide 20 bytes when declared size is 10
	payload20 := []byte("12345678901234567890")
	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "artifacts/oversized.raw", Content: payload20},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected size mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "size mismatch") {
		t.Errorf("expected SizeMismatchError, got: %v", err)
	}
}

func TestIngest_PathTraversal_Rejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "traversal-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "traversal.tar.gz")

	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "traversal-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "valid-name",
				Filename:  "disk.raw",
				SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				SizeBytes: 4,
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	// Tar entry contains sneaky traversal
	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "artifacts/../evil.raw", Content: []byte("EVIL")},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected rejection of path traversal entry, got nil")
	}
}

func TestIngest_ManifestNotFirst_Rejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "layout-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "bad-layout.tar.gz")

	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "layout-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "disk",
				Filename:  "disk.raw",
				SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				SizeBytes: 4,
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	// Build tar where artifact is FIRST, manifest is SECOND
	f, _ := os.Create(bundlePath)
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Write artifact first
	artBytes := []byte("DATA")
	_ = tw.WriteHeader(&tar.Header{Name: "artifacts/disk.raw", Mode: 0644, Size: int64(len(artBytes))})
	_, _ = tw.Write(artBytes)

	// Write manifest second
	mfBytes, _ := yaml.Marshal(mf)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.yaml", Mode: 0644, Size: int64(len(mfBytes))})
	_, _ = tw.Write(mfBytes)

	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected error when manifest is not the first entry, got nil")
	}
	var layoutErr *ArchiveLayoutError
	if !errors.As(err, &layoutErr) {
		t.Errorf("expected *ArchiveLayoutError, got: %v", err)
	}
}

func TestIngest_TrustStoreIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "truststore-ingest-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	srcFile := filepath.Join(tempDir, "base.raw")
	payload := []byte("TRUSTED_IMAGE_PAYLOAD")
	_ = os.WriteFile(srcFile, payload, 0644)

	bundlePath := filepath.Join(tempDir, "trusted.tar.gz")
	signer := "releng@cloud.google.com"

	_, err = bundler.CreateBundle(bundler.BundleOptions{
		Name:           "trusted-image",
		SourceFilePath: srcFile,
		SignerIdentity: signer,
		PrivateKey:     priv,
		OutputPath:     bundlePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := truststore.New()
	keyEntry, err := ts.AddKey(pub, signer, "all")
	if err != nil {
		t.Fatal(err)
	}

	registryDir := filepath.Join(tempDir, "registry")

	// 1. Ingestion with active trust store succeeds
	report, err := IngestBundleWithOptions(IngestOptions{
		BundlePath:        bundlePath,
		TrustStore:        ts,
		TargetRegistryDir: registryDir,
	})
	if err != nil {
		t.Fatalf("ingest failed with active trust store: %v", err)
	}
	if report.SignerIdentity != signer {
		t.Errorf("signer identity mismatch: %s", report.SignerIdentity)
	}

	// 2. Revoking the key blocks subsequent ingestion
	if err := ts.RevokeKey(keyEntry.KeyID, "key compromised"); err != nil {
		t.Fatal(err)
	}

	_, err = IngestBundleWithOptions(IngestOptions{
		BundlePath:        bundlePath,
		TrustStore:        ts,
		TargetRegistryDir: registryDir,
		AllowOverwrite:    true,
	})
	if err == nil {
		t.Fatalf("expected ingestion to fail with revoked key, but succeeded")
	}
	if !strings.Contains(err.Error(), "REVOKED") {
		t.Errorf("expected REVOKED in error message, got: %v", err)
	}
}

func TestIngest_OverwriteProtection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "overwrite-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	src1 := filepath.Join(tempDir, "img1.raw")
	_ = os.WriteFile(src1, []byte("IMAGE_V1"), 0644)

	bundle1 := filepath.Join(tempDir, "b1.tar.gz")
	_, err = bundler.CreateBundle(bundler.BundleOptions{
		Name:           "my-image",
		SourceFilePath: src1,
		SignerIdentity: "test@domain.com",
		PrivateKey:     priv,
		OutputPath:     bundle1,
	})
	if err != nil {
		t.Fatal(err)
	}

	registryDir := filepath.Join(tempDir, "registry")

	// Ingest v1
	_, err = IngestBundle(bundle1, pub, registryDir)
	if err != nil {
		t.Fatal(err)
	}

	// Create v2 with same image name but different payload
	src2 := filepath.Join(tempDir, "img2.raw")
	_ = os.WriteFile(src2, []byte("IMAGE_V2_DIFFERENT"), 0644)

	bundle2 := filepath.Join(tempDir, "b2.tar.gz")
	_, err = bundler.CreateBundle(bundler.BundleOptions{
		Name:           "my-image",
		SourceFilePath: src2,
		SignerIdentity: "test@domain.com",
		PrivateKey:     priv,
		OutputPath:     bundle2,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Ingest v2 without AllowOverwrite must fail with CatalogConflictError
	_, err = IngestBundleWithOptions(IngestOptions{
		BundlePath:        bundle2,
		TrustedPubKey:     pub,
		TargetRegistryDir: registryDir,
		AllowOverwrite:    false,
	})
	if err == nil {
		t.Fatalf("expected CatalogConflictError when overwriting without flag")
	}
	if !strings.Contains(err.Error(), "already registered with differing digest") {
		t.Errorf("expected conflict message, got: %v", err)
	}

	// Ingest v2 with AllowOverwrite succeeds
	_, err = IngestBundleWithOptions(IngestOptions{
		BundlePath:        bundle2,
		TrustedPubKey:     pub,
		TargetRegistryDir: registryDir,
		AllowOverwrite:    true,
	})
	if err != nil {
		t.Fatalf("ingest with AllowOverwrite failed: %v", err)
	}
}

func TestIngest_SymlinkRejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "symlink-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "symlink.tar.gz")

	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "symlink-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "disk",
				Filename:  "disk.raw",
				SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				SizeBytes: 4,
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "artifacts/disk.raw", Typeflag: tar.TypeSymlink},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected error rejecting symlink entry")
	}
	if !strings.Contains(err.Error(), "forbidden entry type") {
		t.Errorf("expected forbidden entry type message, got: %v", err)
	}
}

func TestIngest_DuplicateEntry_Rejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dup-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "duplicate.tar.gz")

	h := sha256.Sum256([]byte("DATA"))
	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "dup-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "disk",
				Filename:  "disk.raw",
				SHA256:    hex.EncodeToString(h[:]),
				SizeBytes: 4,
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "artifacts/disk.raw", Content: []byte("DATA")},
		{Name: "artifacts/disk.raw", Content: []byte("DATA")},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected error on duplicate entry")
	}
	if !strings.Contains(err.Error(), "duplicate entry") {
		t.Errorf("expected duplicate entry error, got: %v", err)
	}
}

func TestIngest_MissingDeclaredArtifact_Rejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "missing-art-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "missing.tar.gz")

	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "missing-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "disk-1",
				Filename:  "disk-1.raw",
				SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				SizeBytes: 4,
				OSFamily:  "linux",
			},
			{
				Name:      "disk-2",
				Filename:  "disk-2.raw",
				SHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				SizeBytes: 4,
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	// Tar only includes disk-1.raw
	h1 := sha256.Sum256([]byte("DATA"))
	mf.Artifacts[0].SHA256 = hex.EncodeToString(h1[:])
	canon, _ = mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "artifacts/disk-1.raw", Content: []byte("DATA")},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected error when declared artifact is missing in archive")
	}
	if !strings.Contains(err.Error(), "declared in manifest but missing") {
		t.Errorf("expected missing artifact message, got: %v", err)
	}
}

func TestIngest_UnadvertisedArtifact_Rejected(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unadvertised-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "unadvertised.tar.gz")

	h := sha256.Sum256([]byte("DATA"))
	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "unadvertised-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "disk-1",
				Filename:  "disk-1.raw",
				SHA256:    hex.EncodeToString(h[:]),
				SizeBytes: 4,
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{Format: "none"},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	// Archive includes disk-1 and sneaky unadvertised disk-2
	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "artifacts/disk-1.raw", Content: []byte("DATA")},
		{Name: "artifacts/disk-2.raw", Content: []byte("EVIL")},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected error on unadvertised artifact")
	}
	if !strings.Contains(err.Error(), "unadvertised artifact") {
		t.Errorf("expected unadvertised artifact message, got: %v", err)
	}
}

func TestIngest_SBOMDigestVerification(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sbom-verify-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, _ := crypto.GenerateKeypair()
	bundlePath := filepath.Join(tempDir, "sbom-tampered.tar.gz")

	hDisk := sha256.Sum256([]byte("IMAGE_DATA"))
	hSBOM := sha256.Sum256([]byte("GENUINE_SBOM_JSON"))

	mf := manifest.BundleManifest{
		APIVersion:     manifest.ExpectedAPIVersion,
		Kind:           manifest.ExpectedKind,
		BundleID:       "sbom-test",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test",
		SignerIdentity: "trusted@corp.org",
		Artifacts: []manifest.ArtifactMeta{
			{
				Name:      "disk",
				Filename:  "disk.raw",
				SHA256:    hex.EncodeToString(hDisk[:]),
				SizeBytes: int64(len("IMAGE_DATA")),
				OSFamily:  "linux",
			},
		},
		SBOM: manifest.SBOMMeta{
			Format:   "SPDX-2.3",
			Filename: "sbom.json",
			SHA256:   hex.EncodeToString(hSBOM[:]),
		},
	}
	canon, _ := mf.CanonicalBytes()
	mf.Signature = crypto.Sign(priv, canon)

	// Archive with altered SBOM payload
	writeCustomArchive(t, bundlePath, &mf, []customEntry{
		{Name: "sbom.json", Content: []byte("TAMPERED_SBOM_JSON")},
		{Name: "artifacts/disk.raw", Content: []byte("IMAGE_DATA")},
	})

	registryDir := filepath.Join(tempDir, "registry")
	_, err = IngestBundle(bundlePath, pub, registryDir)
	if err == nil {
		t.Fatalf("expected error when SBOM digest mismatches declared manifest digest")
	}
	if !strings.Contains(err.Error(), "sbom.json") || !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("expected SBOM digest mismatch error, got: %v", err)
	}
}

type customEntry struct {
	Name     string
	Content  []byte
	Typeflag byte
}

func writeCustomArchive(t *testing.T, outPath string, mf *manifest.BundleManifest, entries []customEntry) {
	t.Helper()
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Write manifest first
	mfBytes, err := yaml.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     "manifest.yaml",
		Mode:     0644,
		Size:     int64(len(mfBytes)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(mfBytes); err != nil {
		t.Fatal(err)
	}

	// Write custom entries
	for _, entry := range entries {
		tf := entry.Typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     entry.Name,
			Mode:     0644,
			Size:     int64(len(entry.Content)),
			Typeflag: tf,
		}); err != nil {
			t.Fatal(err)
		}
		if len(entry.Content) > 0 {
			if _, err := tw.Write(entry.Content); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func BenchmarkIngest_5MBBundle(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "bench-ingest-*")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	pub, priv, err := crypto.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	payloadSize := 5 * 1024 * 1024 // 5 MB
	srcFile := filepath.Join(tempDir, "bench-disk.raw")
	f, err := os.Create(srcFile)
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}
	var written int
	for written < payloadSize {
		n, _ := f.Write(chunk)
		written += n
	}
	_ = f.Close()

	bundlePath := filepath.Join(tempDir, "bench.bundle.tar.gz")
	_, err = bundler.CreateBundle(bundler.BundleOptions{
		Name:           "bench-vm",
		SourceFilePath: srcFile,
		SignerIdentity: "bench@supplychain.org",
		PrivateKey:     priv,
		OutputPath:     bundlePath,
		DemoFixture:    true,
	})
	if err != nil {
		b.Fatal(err)
	}

	registryDir := filepath.Join(tempDir, "registry")

	b.SetBytes(int64(payloadSize))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := IngestBundleWithOptions(IngestOptions{
			BundlePath:        bundlePath,
			TrustedPubKey:     pub,
			TargetRegistryDir: registryDir,
			AllowOverwrite:    true,
		})
		if err != nil {
			b.Fatalf("ingest benchmark iteration failed: %v", err)
		}
	}
}

