//go:build audit

// jade:ring local

package github

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

func TestWorkflowURLValidation(t *testing.T) {
	for _, tc := range []struct{ name, server, repo, run, wantError string }{
		{"valid", "https://github.com", "org/repo", "123", ""},
		{"enterprise", "https://github.example.test/", "org/repo.name", "123", ""},
		{"scheme", "javascript:alert(1)", "org/repo", "123", "invalid GITHUB_SERVER_URL"},
		{"userinfo", "https://user@github.com", "org/repo", "123", "invalid GITHUB_SERVER_URL"},
		{"query", "https://github.com?host=other", "org/repo", "123", "invalid GITHUB_SERVER_URL"},
		{"traversal", "https://github.com", "../repo", "123", "invalid GITHUB_REPOSITORY"},
		{"encoded path", "https://github.com", "org/%2e%2e", "123", "invalid GITHUB_REPOSITORY"},
		{"empty run", "https://github.com", "org/repo", "", "invalid GITHUB_RUN_ID"},
		{"run injection", "https://github.com", "org/repo", "123?other", "invalid GITHUB_RUN_ID"},
		{"oversized run", "https://github.com", "org/repo", strings.Repeat("9", 100000), "invalid GITHUB_RUN_ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, tokens := testJWTInfra(t, map[string]interface{}{"repository": tc.repo, "run_id": tc.run})
			defer keys.Close()
			defer tokens.Close()
			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-bearer")
			t.Setenv("GITHUB_SERVER_URL", tc.server)
			t.Setenv("GITHUB_REPOSITORY", tc.repo)
			t.Setenv("GITHUB_RUN_ID", tc.run)
			a := &Attestor{jwksURL: keys.URL, tokenURL: tokens.URL, ProjectUrl: "stale", PipelineUrl: "stale"}
			ctx, err := attestation.NewContext("test", nil)
			require.NoError(t, err)
			err = a.Attest(ctx)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				require.Empty(t, a.ProjectUrl)
				require.Empty(t, a.PipelineUrl)
				require.Empty(t, a.Subjects())
				require.Empty(t, a.BackRefs())
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, a.CIHost)
			require.Equal(t, strings.TrimSuffix(tc.server, "/")+"/"+tc.repo, a.ProjectUrl)
			require.Equal(t, a.ProjectUrl+"/actions/runs/"+tc.run, a.PipelineUrl)
		})
	}
}

func TestWorkflowClaimBinding(t *testing.T) {
	for _, tc := range []struct {
		name      string
		repo, run interface{}
		wantError string
	}{
		{"matching", "org/repo", "123", ""},
		{"other repository", "attacker/repo", "123", "repository claim"},
		{"other run", "org/repo", "124", "run_id claim"},
		{"missing repository", nil, "123", "repository claim"},
		{"missing run", "org/repo", nil, "run_id claim"},
		{"numeric run", "org/repo", 123, "run_id claim"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, tokens := testJWTInfra(t, map[string]interface{}{"repository": tc.repo, "run_id": tc.run})
			defer keys.Close()
			defer tokens.Close()
			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-bearer")
			t.Setenv("GITHUB_SERVER_URL", "https://github.com")
			t.Setenv("GITHUB_REPOSITORY", "org/repo")
			t.Setenv("GITHUB_RUN_ID", "123")
			a := &Attestor{jwksURL: keys.URL, tokenURL: tokens.URL}
			ctx, err := attestation.NewContext("test", nil)
			require.NoError(t, err)
			err = a.Attest(ctx)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				require.Empty(t, a.ProjectUrl)
				require.Empty(t, a.PipelineUrl)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "https://github.com/org/repo/actions/runs/123", a.PipelineUrl)
		})
	}
}
