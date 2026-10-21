package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateResourceName(t *testing.T) {
	valid := []string{
		"ubuntu-22.04",
		"rhel-9",
		"debian-12.img",
		"gold-master-v1",
		"my-bundle-1234",
	}
	for _, name := range valid {
		if err := ValidateResourceName(name); err != nil {
			t.Errorf("expected valid resource name for %q, got error: %v", name, err)
		}
	}

	invalid := []string{
		"",
		" ",
		"../escape",
		"name/with/slashes",
		"name\\with\\backslashes",
		"-leading-dash",
		"trailing-dash-",
		".leading.dot",
		"trailing.dot.",
		"CON",
		"nul",
		"com1.foo",
		"aux.tar.gz",
	}
	for _, name := range invalid {
		if err := ValidateResourceName(name); err == nil {
			t.Errorf("expected error for invalid resource name %q, got nil", name)
		}
	}
}

func TestValidateFilename(t *testing.T) {
	valid := []string{
		"ubuntu-22.04.qcow2",
		"disk.raw",
		"manifest.yaml",
		"sbom.json",
		"rhel-9-airgap.tar.gz",
	}
	for _, f := range valid {
		if err := ValidateFilename(f); err != nil {
			t.Errorf("expected valid filename for %q, got: %v", f, err)
		}
	}

	invalid := []string{
		"",
		" ",
		"..",
		".",
		"../evil.raw",
		"..\\evil.raw",
		"dir/file.raw",
		"dir\\file.raw",
		"nul",
		"con.raw",
		"prn.qcow2",
		"file:stream",
		"file*name",
		"file?name",
		"file\x00null",
	}
	for _, f := range invalid {
		if err := ValidateFilename(f); err == nil {
			t.Errorf("expected error for invalid filename %q, got nil", f)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "safejoin-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	joined, err := SafeJoin(tmpDir, "image.raw")
	if err != nil {
		t.Fatalf("expected successful SafeJoin, got: %v", err)
	}
	if filepath.Dir(joined) != filepath.Clean(tmpDir) {
		t.Errorf("unexpected joined path: %s", joined)
	}

	// Traversal attempts
	traversals := []string{
		"../escape.raw",
		"..\\escape.raw",
		"sub/../../escape.raw",
		"/etc/passwd",
		"C:\\Windows\\System32",
	}
	for _, target := range traversals {
		if _, err := SafeJoin(tmpDir, target); err == nil {
			t.Errorf("expected SafeJoin to block %q, but succeeded", target)
		}
	}
}

func TestSafeReplaceFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "saferename-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	src := filepath.Join(tmpDir, "source.tmp")
	dst := filepath.Join(tmpDir, "target.txt")

	if err := os.WriteFile(src, []byte("new-data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old-data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := SafeReplaceFile(src, dst); err != nil {
		t.Fatalf("SafeReplaceFile failed: %v", err)
	}

	content, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new-data" {
		t.Errorf("expected 'new-data', got %q", string(content))
	}
}
