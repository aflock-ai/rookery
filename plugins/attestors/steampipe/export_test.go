package steampipe

import "testing"

// TestExportDefaultsInCollection guards the design choice that the steampipe
// attestation rides INSIDE the run's collection by default (so a witness policy
// step can require steampipe/v0.1 and gate its rows directly). Standalone
// sidecar export is the exception, opt-in via WithExport / --attestor-steampipe-export.
func TestExportDefaultsInCollection(t *testing.T) {
	if New().Export() {
		t.Fatal("Export() defaulted to true; the steampipe attestation must ride in the collection by default, not as a sidecar")
	}
}

func TestWithExportOptIn(t *testing.T) {
	a := New()
	WithExport(true)(a)
	if !a.Export() {
		t.Fatal("WithExport(true) did not enable sidecar export")
	}
	WithExport(false)(a)
	if a.Export() {
		t.Fatal("WithExport(false) did not disable sidecar export")
	}
}
