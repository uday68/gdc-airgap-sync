package manifest

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzParseManifest(f *testing.F) {
	// Seed with a valid manifest
	validMf := validTestManifest()
	data, err := yaml.Marshal(validMf)
	if err == nil {
		f.Add(data)
	}

	// Seed with corrupt YAML
	f.Add([]byte("not: a: yaml: [}"))
	f.Add([]byte("apiVersion: 12345\nartifacts:\n  - name: 99"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, payload []byte) {
		var mf BundleManifest
		if err := yaml.Unmarshal(payload, &mf); err != nil {
			return
		}
		// Validate must never panic
		_ = mf.Validate()

		// CanonicalBytes must never panic
		_, _ = mf.CanonicalBytes()
	})
}
