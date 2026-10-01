// jade:ring local

package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// These cases exercise local identity paths, even when the host is an Actions
// runner. Unset rather than empty: OIDC providers can detect keys with LookupEnv.
func clearAmbientGitHubIdentity(t *testing.T) {
	t.Helper()
	for _, name := range []string{"CI", "GITHUB_ACTIONS", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		// Setenv registers restoration and rejects parallel environment mutation.
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
}
