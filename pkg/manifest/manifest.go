package manifest

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// ArtifactMeta describes a virtual machine disk image inside the bundle.
type ArtifactMeta struct {
	Name        string `json:"name" yaml:"name"`
	Filename    string `json:"filename" yaml:"filename"`
	SHA256      string `json:"sha256" yaml:"sha256"`
	SizeBytes   int64  `json:"sizeBytes" yaml:"sizeBytes"`
	OSFamily    string `json:"osFamily" yaml:"osFamily"`
	Description string `json:"description" yaml:"description"`
}

// SBOMMeta represents a Software Bill of Materials summary for supply chain compliance.
type SBOMMeta struct {
	Format        string   `json:"format" yaml:"format"`
	SpecVersion   string   `json:"specVersion" yaml:"specVersion"`
	PackagesCount int      `json:"packagesCount" yaml:"packagesCount"`
	KeyPackages   []string `json:"keyPackages" yaml:"keyPackages"`
}

// BundleManifest defines the immutable root of trust for an air-gapped release archive.
type BundleManifest struct {
	APIVersion     string         `json:"apiVersion" yaml:"apiVersion"`
	Kind           string         `json:"kind" yaml:"kind"`
	BundleID       string         `json:"bundleId" yaml:"bundleId"`
	CreatedAt      time.Time      `json:"createdAt" yaml:"createdAt"`
	Origin         string         `json:"origin" yaml:"origin"`
	SignerIdentity string         `json:"signerIdentity" yaml:"signerIdentity"`
	Artifacts      []ArtifactMeta `json:"artifacts" yaml:"artifacts"`
	SBOM           SBOMMeta       `json:"sbom" yaml:"sbom"`
	Signature      string         `json:"signature,omitempty" yaml:"signature,omitempty"`
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
