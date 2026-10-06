// jade:ring local

package cli

import (
	"bytes"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// TestFirstRunTerminalGuidanceMatchesModel holds what `cilock login` prints to
// the guidance edges formal/pushgate-ux gives the terminal
// (PushgateUx/FirstRun.lean, data in firstrun_formal_data_test.go). The case is
// the 2026-10-06 signup's: a browser login that bound a tenant and a product.
// A change to the next-step text must change the model, or this fails.
func TestFirstRunTerminalGuidanceMatchesModel(t *testing.T) {
	var out bytes.Buffer
	printLoginResult(&out, "https://platform.testifysec.com", &auth.Credential{
		TenantID: "t-1", TenantName: "acme", ProductID: "p-1", ProductName: "api",
	})
	text := out.String()
	// Not vacuous: this is the logged-in-with-a-product output, not an error path.
	if !strings.Contains(text, "logged in") || !strings.Contains(text, "product: api") {
		t.Fatalf("printLoginResult did not render the bound-product login:\n%s", text)
	}
	got := firstRunTargets(text)
	want := slices.Clone(firstRunGuides)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("terminal guides to %v, the model says %v; update FirstRun.lean and regenerate\n%s", got, want, text)
	}
}

func firstRunTargets(text string) []string {
	lower := strings.ToLower(text)
	var got []string
	for _, n := range firstRunNeedles {
		if strings.Contains(lower, n[0]) && !slices.Contains(got, n[1]) {
			got = append(got, n[1])
		}
	}
	sort.Strings(got)
	return got
}
