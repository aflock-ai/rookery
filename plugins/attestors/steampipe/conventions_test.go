// conventions_test.go covers the per-plugin subject extractors, with a focus
// on the Google Workspace plugins (googledirectory / googleworkspace) whose
// identity columns let a Steampipe attestation converge with a ScubaGoggles
// attestation on `customer_id` / `domain_name` in the policyverify graph.

package steampipe

import (
	"sort"
	"testing"
)

func extractedKeys(plugin string, row map[string]any) []string {
	pairs := extract(plugin, row)
	keys := make([]string, 0, len(pairs))
	for _, p := range pairs {
		keys = append(keys, p.Key)
	}
	sort.Strings(keys)
	return keys
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExtract_GoogleWorkspacePlugins(t *testing.T) {
	cases := []struct {
		name   string
		plugin string
		row    map[string]any
		want   []string
	}{
		{
			name:   "googledirectory user",
			plugin: "googledirectory",
			row: map[string]any{
				"primary_email": "alice@example.org",
				"customer_id":   "C01abc234",
				"org_unit_path": "/Engineering",
				"is_admin":      true, // non-identity column, ignored
			},
			want: []string{
				"googleworkspace:customer:C01abc234",
				"googleworkspace:orgunit:/Engineering",
				"googleworkspace:user:alice@example.org",
			},
		},
		{
			name:   "googledirectory domain",
			plugin: "googledirectory",
			row: map[string]any{
				"domain_name": "example.org",
				"customer_id": "C01abc234",
				"is_primary":  true,
			},
			want: []string{
				"googleworkspace:customer:C01abc234",
				"googleworkspace:domain:example.org",
			},
		},
		{
			name:   "googledirectory group",
			plugin: "googledirectory",
			row: map[string]any{
				"email":       "team@example.org",
				"customer_id": "C01abc234",
			},
			want: []string{
				"googleworkspace:customer:C01abc234",
				"googleworkspace:group:team@example.org",
			},
		},
		{
			name:   "googleworkspace gmail settings",
			plugin: "googleworkspace",
			row: map[string]any{
				"user_email":      "bob@example.org",
				"auto_forwarding": false,
			},
			want: []string{"googleworkspace:user:bob@example.org"},
		},
		{
			name:   "googleworkspace activity report",
			plugin: "googleworkspace",
			row: map[string]any{
				"actor_email": "carol@example.org",
				"customer_id": "C01abc234",
				"event_name":  "login",
			},
			want: []string{
				"googleworkspace:customer:C01abc234",
				"googleworkspace:user:carol@example.org",
			},
		},
		{
			name:   "unknown plugin yields nothing",
			plugin: "salesforce",
			row:    map[string]any{"id": "x"},
			want:   []string{},
		},
		{
			name:   "empty identity values skipped",
			plugin: "googledirectory",
			row:    map[string]any{"customer_id": "", "domain_name": "example.org"},
			want:   []string{"googleworkspace:domain:example.org"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractedKeys(tc.plugin, tc.row)
			if !equalStrings(got, tc.want) {
				t.Errorf("extract(%q) keys = %v, want %v", tc.plugin, got, tc.want)
			}
		})
	}
}
