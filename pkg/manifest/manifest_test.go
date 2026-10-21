package manifest

import (
	"strings"
	"testing"
	"time"
)

func validTestManifest() BundleManifest {
	return BundleManifest{
		APIVersion:     ExpectedAPIVersion,
		Kind:           ExpectedKind,
		BundleID:       "ubuntu-22.04-release",
		ReleaseID:      "rel-20261021",
		CreatedAt:      time.Now().UTC(),
		Origin:         "test-pipeline",
		SignerIdentity: "releng@example.com",
		KeyID:          "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
		Artifacts: []ArtifactMeta{
			{
				Name:        "ubuntu-22.04",
				Filename:    "ubuntu-22.04.qcow2",
				SHA256:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes:   1024,
				OSFamily:    "linux",
				Description: "Ubuntu 22.04 LTS Base Image",
			},
		},
		SBOM: SBOMMeta{
			Format:   "SPDX-2.3",
			Filename: "sbom.json",
			SHA256:   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
}

func TestManifest_Validation(t *testing.T) {
	mf := validTestManifest()
	if err := mf.Validate(); err != nil {
		t.Fatalf("expected valid manifest, got: %v", err)
	}

	// Bad APIVersion
	badAPIVersion := mf
	badAPIVersion.APIVersion = "v1"
	if err := badAPIVersion.Validate(); err == nil {
		t.Errorf("expected error on bad APIVersion")
	}

	// Bad Kind
	badKind := mf
	badKind.Kind = "Pod"
	if err := badKind.Validate(); err == nil {
		t.Errorf("expected error on bad Kind")
	}

	// Empty Artifacts
	emptyArt := mf
	emptyArt.Artifacts = nil
	if err := emptyArt.Validate(); err == nil {
		t.Errorf("expected error on empty artifacts")
	}

	// Duplicate Artifact Name
	dupArt := mf
	dupArt.Artifacts = append(dupArt.Artifacts, ArtifactMeta{
		Name:      "ubuntu-22.04",
		Filename:  "ubuntu-22.04-dup.qcow2",
		SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SizeBytes: 2048,
	})
	if err := dupArt.Validate(); err == nil {
		t.Errorf("expected error on duplicate artifact name")
	}

	// Path Traversal in Filename
	traversalArt := mf
	traversalArt.Artifacts[0].Filename = "../etc/passwd"
	if err := traversalArt.Validate(); err == nil {
		t.Errorf("expected error on traversal filename")
	}

	// Bad SHA256 (not hex / wrong length)
	badSHA := mf
	badSHA.Artifacts[0].SHA256 = "not-a-hash"
	if err := badSHA.Validate(); err == nil {
		t.Errorf("expected error on bad sha256")
	}

	// Non-positive size
	zeroSize := mf
	zeroSize.Artifacts[0].SizeBytes = 0
	if err := zeroSize.Validate(); err == nil {
		t.Errorf("expected error on zero size")
	}
}

func TestManifest_CanonicalBytes(t *testing.T) {
	mf := validTestManifest()
	mf.Signature = "initial-sig"

	b1, err := mf.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}

	// Should omit signature
	if strings.Contains(string(b1), "initial-sig") {
		t.Fatalf("canonical bytes should not contain signature")
	}

	// Modifying signature should not alter CanonicalBytes output
	mf.Signature = "different-sig"
	b2, err := mf.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}

	if string(b1) != string(b2) {
		t.Fatalf("canonical bytes differed across different signatures")
	}
}
