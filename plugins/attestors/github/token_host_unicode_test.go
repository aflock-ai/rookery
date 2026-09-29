// jade:ring local

package github

import (
	"strings"
	"testing"
)

// TestFetchTokenRefusesUnicodeLookalikeEndpoint: the token endpoint check
// lower-cased the host with Unicode rules, so "x.actİons.githubusercontent.com"
// (U+0130) passed as an actions.githubusercontent.com host while Go's
// transport sends the bearer, through IDNA, to a different punycode host.
// A non-ASCII endpoint host is refused before any request.
func TestFetchTokenRefusesUnicodeLookalikeEndpoint(t *testing.T) {
	for _, u := range []string{
		"https://pipelines.actİons.githubusercontent.com/token",
		"https://pipelines.actions.githubuſercontent.com/token",
		"https://pipelines.actions.githubusercontent.comK/token",
	} {
		_, err := fetchToken(u, "secret-bearer", "witness")
		if err == nil || !strings.Contains(err.Error(), "invalid GitHub Actions token endpoint") {
			t.Errorf("fetchToken(%q) = %v, want the endpoint refused before any request", u, err)
		}
	}
}
