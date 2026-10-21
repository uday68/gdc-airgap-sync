package manifest

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/uday68/gdc-airgap-sync/pkg/pathutil"
	"gopkg.in/yaml.v3"
)

const (
	ExpectedAPIVersion = "airgap.gdc.io/v1alpha1"
	ExpectedKind       = "AirGapBundle"
	MaxArtifactsLimit  = 100
)

// ArtifactMeta describes a virtual machine disk image inside the bundle.
type ArtifactMeta struct {
	Name        string    `json:"name" yaml:"name"`
	Filename    string    `json:"filename" yaml:"filename"`
	SHA256      string    `json:"sha256" yaml:"sha256"`
	SizeBytes   int64     `json:"sizeBytes" yaml:"sizeBytes"`
	OSFamily    string    `json:"osFamily" yaml:"osFamily"`
	Description string    `json:"description" yaml:"description"`
	AddedAt     time.Time `json:"addedAt,omitempty" yaml:"addedAt,omitempty"`
}

// SBOMMeta represents a Software Bill of Materials summary and cryptographic binding.
type SBOMMeta struct {
	Format        string   `json:"format" yaml:"format"` // e.g. "SPDX-2.3", "CycloneDX-1.5", "none"
	SpecVersion   string   `json:"specVersion,omitempty" yaml:"specVersion,omitempty"`
	Filename      string   `json:"filename,omitempty" yaml:"filename,omitempty"`
	SHA256        string   `json:"sha256,omitempty" yaml:"sha256,omitempty"`
	PackagesCount int      `json:"packagesCount,omitempty" yaml:"packagesCount,omitempty"`
	KeyPackages   []string `json:"keyPackages,omitempty" yaml:"keyPackages,omitempty"`
}

// BundleManifest defines the immutable root of trust for an air-gapped release archive.
type BundleManifest struct {
	APIVersion     string         `json:"apiVersion" yaml:"apiVersion"`
	Kind           string         `json:"kind" yaml:"kind"`
	BundleID       string         `json:"bundleId" yaml:"bundleId"`
	ReleaseID      string         `json:"releaseId,omitempty" yaml:"releaseId,omitempty"`
	CreatedAt      time.Time      `json:"createdAt" yaml:"createdAt"`
	Origin         string         `json:"origin" yaml:"origin"`
	SignerIdentity string         `json:"signerIdentity" yaml:"signerIdentity"`
	KeyID          string         `json:"keyId,omitempty" yaml:"keyId,omitempty"`
	Artifacts      []ArtifactMeta `json:"artifacts" yaml:"artifacts"`
	SBOM           SBOMMeta       `json:"sbom" yaml:"sbom"`
	Signature      string         `json:"signature,omitempty" yaml:"signature,omitempty"`
}

// Validate checks internal consistency and prevents malicious fields.
func (m *BundleManifest) Validate() error {
	if m.APIVersion != ExpectedAPIVersion {
		return fmt.Errorf("unsupported apiVersion '%s' (expected %s)", m.APIVersion, ExpectedAPIVersion)
	}
	if m.Kind != ExpectedKind {
		return fmt.Errorf("unsupported kind '%s' (expected %s)", m.Kind, ExpectedKind)
	}
	if err := pathutil.ValidateResourceName(m.BundleID); err != nil {
		return fmt.Errorf("invalid bundleId: %w", err)
	}
	if strings.TrimSpace(m.SignerIdentity) == "" {
		return fmt.Errorf("signerIdentity cannot be empty")
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("manifest must contain at least one artifact")
	}
	if len(m.Artifacts) > MaxArtifactsLimit {
		return fmt.Errorf("manifest exceeds maximum allowed artifacts (%d > %d)", len(m.Artifacts), MaxArtifactsLimit)
	}

	seenNames := make(map[string]struct{})
	seenFilenames := make(map[string]struct{})

	for i, art := range m.Artifacts {
		if err := pathutil.ValidateResourceName(art.Name); err != nil {
			return fmt.Errorf("artifact[%d] has invalid name: %w", i, err)
		}
		if _, exists := seenNames[art.Name]; exists {
			return fmt.Errorf("duplicate artifact name '%s'", art.Name)
		}
		seenNames[art.Name] = struct{}{}

		if err := pathutil.ValidateFilename(art.Filename); err != nil {
			return fmt.Errorf("artifact[%d] has invalid filename: %w", i, err)
		}
		if _, exists := seenFilenames[art.Filename]; exists {
			return fmt.Errorf("duplicate artifact filename '%s'", art.Filename)
		}
		seenFilenames[art.Filename] = struct{}{}

		if art.SizeBytes <= 0 {
			return fmt.Errorf("artifact[%d] '%s' has non-positive size (%d)", i, art.Name, art.SizeBytes)
		}

		if err := validateSHA256Hex(art.SHA256); err != nil {
			return fmt.Errorf("artifact[%d] '%s' has invalid sha256 digest: %w", i, art.Name, err)
		}
	}

	if m.SBOM.SHA256 != "" {
		if err := validateSHA256Hex(m.SBOM.SHA256); err != nil {
			return fmt.Errorf("sbom has invalid sha256 digest: %w", err)
		}
	}

	return nil
}

func validateSHA256Hex(s string) error {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return fmt.Errorf("sha256 digest must be 64 characters long (got %d)", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("invalid hex encoding")
	}
	return nil
}

// CanonicalBytes returns the deterministically serialized manifest bytes for signing/verifying.
// The Signature field is omitted during signature computation to prevent circular hashing.
func (m *BundleManifest) CanonicalBytes() ([]byte, error) {
	clone := *m
	clone.Signature = ""
	data, err := yaml.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling canonical manifest: %w", err)
	}
	return data, nil
}
