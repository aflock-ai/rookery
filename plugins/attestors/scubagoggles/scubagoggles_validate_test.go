// scubagoggles_validate_test.go runs the attestor against a REAL ScubaGoggles
// artifact captured from a live Google Workspace tenant — the proof-of-life
// harness for testing against actual infra (not the committed example fixture).
//
// Usage:
//
//	# 1. Collect against a live tenant (browser OAuth, super-admin):
//	scubagoggles gws -c /path/to/credentials.json -o /out/dir
//	# 2. Point the harness at the resulting ScubaResults*.json (its Raw section
//	#    is the config) or a ProviderSettingsExport.json:
//	SCUBA_VALIDATE_INPUT=/out/dir/.../ScubaResults_*.json \
//	    go test -tags validate -run TestValidateAgainstRealConfig \
//	    github.com/aflock-ai/rookery/plugins/attestors/scubagoggles
//
// The build tag keeps this out of normal CI.

//go:build validate

package scubagoggles

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

func TestValidateAgainstRealConfig(t *testing.T) {
	inputPath := os.Getenv("SCUBA_VALIDATE_INPUT")
	if inputPath == "" {
		t.Skip("set SCUBA_VALIDATE_INPUT to a real ScubaResults*.json / ProviderSettingsExport.json")
	}

	b, err := os.ReadFile(inputPath) //nolint:gosec // operator-supplied path
	if err != nil {
		t.Fatalf("read %s: %v", inputPath, err)
	}

	pred, err := buildPredicate(b)
	if err != nil {
		t.Fatalf("buildPredicate rejected real artifact: %v", err)
	}
	pred.SourceFile = inputPath
	if ds, derr := cryptoutil.CalculateDigestSetFromBytes(b, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}); derr == nil {
		pred.SourceDigest = ds
	}
	a := &Attestor{Predicate: *pred}
	subjects := a.Subjects()

	t.Logf("tenant=%q domain=%q display=%q tool=%s/%s collected=%s",
		pred.TenantID, pred.DomainName, pred.DisplayName, pred.Tool, pred.ToolVersion, pred.CollectedAt)
	t.Logf("domains: %v", pred.Domains)
	t.Logf("org units: %v", pred.OrgUnits)
	t.Logf("raw config: %d bytes", len(pred.Config))
	t.Logf("emitted %d graph subjects", len(subjects))

	// The captured config must be the raw provider object (the rego `input`):
	// it should carry policies/tenant_info and must NOT contain a verdict.
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(pred.Config, &cfg); err != nil {
		t.Fatalf("config is not a JSON object: %v", err)
	}
	for _, k := range []string{"tenant_info", "policies", "domains"} {
		if _, ok := cfg[k]; !ok {
			t.Errorf("config missing expected raw key %q", k)
		}
	}
	if _, ok := cfg["Results"]; ok {
		t.Error("config leaked the verdict (Results) — must capture facts only")
	}
	t.Logf("raw config keys: %d (%s ...)", len(cfg), firstKeys(cfg, 8))

	if pred.TenantID == "" {
		t.Error("empty TenantID — subject graph join would break")
	}
	if pred.DomainName == "" {
		t.Error("empty DomainName")
	}
	if _, ok := subjects[fmt.Sprintf("googleworkspace:domain:%s", pred.DomainName)]; !ok {
		t.Error("primary domain subject missing")
	}
}

func firstKeys(m map[string]json.RawMessage, n int) string {
	out := ""
	i := 0
	for k := range m {
		if i >= n {
			break
		}
		if i > 0 {
			out += ", "
		}
		out += k
		i++
	}
	return out
}
