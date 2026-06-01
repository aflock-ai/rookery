package trivy_test

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/testkit"
	_ "github.com/aflock-ai/rookery/plugins/attestors/trivy" // register the trivy attestor
)

// TestFixtures proves the trivy output contract against its recorded fixtures
// via the catalog testkit — the per-plugin smoke test for fast local iteration
// (the all-plugins harness in presets/all/catalogtest covers the same fixtures
// in CI). Hermetic: no real trivy run, the fixture input is a recorded report.
func TestFixtures(t *testing.T) {
	fxs, err := testkit.LoadFixtures("testdata/fixtures")
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
	if len(fxs) == 0 {
		t.Fatal("no fixtures found under testdata/fixtures")
	}
	for _, fx := range fxs {
		t.Run(fx.Name, func(t *testing.T) {
			res := testkit.RunAttestorWithFixture(t, fx)
			res.AssertContract(t, fx)
		})
	}
}
