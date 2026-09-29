// jade:ring local

package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"

	// Linked as cmd/cilock links it, so the test sees what the binary sees.
	_ "github.com/aflock-ai/rookery/plugins/attestors/semgrep"
)

// Linking the semgrep attestor package must not change --workload auto:
// `semgrep` stays unregistered as an attestor name, so run and plan keep
// routing every semgrep invocation through the detection-only catalog entry
// to the sarif attestor, exactly as before the package existed.
func TestDetectCatalogAttestors_SemgrepPackageLeavesRoutingUnchanged(t *testing.T) {
	for _, e := range attestation.RegistrationEntries() {
		assert.NotEqual(t, "semgrep", e.Name, "the semgrep name must not be registered before its routing lands")
	}
	for name, argv := range map[string][]string{
		"--sarif":          {"semgrep", "--config", "p/python", "--sarif", "--output", "r.sarif", "."},
		"--sarif-output=f": {"semgrep", "--config", "p/python", "--sarif-output=r.sarif", "."},
		"--json --output":  {"semgrep", "--config", "p/python", "--json", "--output", "r.json", "."},
	} {
		t.Run(name, func(t *testing.T) {
			got := detectCatalogAttestors(argv, t.TempDir())
			assert.Contains(t, got, "sarif")
			assert.NotContains(t, got, "semgrep")
		})
	}
}
