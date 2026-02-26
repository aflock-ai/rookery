// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitlab

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	testCases := []struct {
		name string
		opts []Option
		want func(*Attestor) bool
	}{
		{
			name: "no options",
			opts: nil,
			want: func(a *Attestor) bool {
				return a.token == "" && a.tokenEnvVar == ""
			},
		},
		{
			name: "with token",
			opts: []Option{WithToken("test-token")},
			want: func(a *Attestor) bool {
				return a.token == "test-token"
			},
		},
		{
			name: "with token env var",
			opts: []Option{WithTokenEnvVar("TEST_TOKEN_VAR")},
			want: func(a *Attestor) bool {
				return a.tokenEnvVar == "TEST_TOKEN_VAR"
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := New(testCase.opts...)
			assert.True(t, testCase.want(got))
		})
	}
}

func TestSubjects(t *testing.T) {
	attestor := &Attestor{
		PipelineUrl: "https://gitlab.example.com/project/-/pipelines/789012",
		JobUrl:      "https://gitlab.example.com/project/-/jobs/123456",
		ProjectUrl:  "https://gitlab.example.com/project",
	}

	subjects := attestor.Subjects()
	assert.NotNil(t, subjects)
	assert.Equal(t, 3, len(subjects))

	expectedSubjects := []string{
		"pipelineurl:" + attestor.PipelineUrl,
		"joburl:" + attestor.JobUrl,
		"projecturl:" + attestor.ProjectUrl,
	}

	for _, expectedSubject := range expectedSubjects {
		_, ok := subjects[expectedSubject]
		assert.True(t, ok, "Expected subject not found: %s", expectedSubject)
	}

	backRefs := attestor.BackRefs()
	assert.NotNil(t, backRefs)
	assert.Equal(t, 1, len(backRefs))

	// Verify only pipeline URL is in backRefs
	pipelineKey := "pipelineurl:" + attestor.PipelineUrl
	_, ok := backRefs[pipelineKey]
	assert.True(t, ok, "Pipeline URL should be in backRefs")
}

func TestErrNotGitlab(t *testing.T) {
	err := ErrNotGitlab{}
	assert.Equal(t, "not in a gitlab ci job", err.Error())
	assert.Implements(t, (*error)(nil), err)
}

func TestAttestorMethods(t *testing.T) {
	attestor := New()

	assert.Equal(t, Name, attestor.Name())
	assert.Equal(t, Type, attestor.Type())
	assert.Equal(t, RunType, attestor.RunType())
	assert.Equal(t, attestor, attestor.Data())

	schema := attestor.Schema()
	assert.NotNil(t, schema)
	assert.NotNil(t, schema.Definitions)
	assert.Contains(t, schema.Definitions, "Attestor")
}

func TestAttestorInterfaces(t *testing.T) {
	attestor := New()

	assert.Implements(t, (*attestation.Attestor)(nil), attestor)
	assert.Implements(t, (*attestation.Subjecter)(nil), attestor)
	assert.Implements(t, (*attestation.BackReffer)(nil), attestor)
	assert.Implements(t, (*GitLabAttestor)(nil), attestor)
}

func TestConstants(t *testing.T) {
	assert.Equal(t, "gitlab", Name)
	assert.Equal(t, "https://aflock.ai/attestations/gitlab/v0.1", Type)
	assert.Equal(t, attestation.PreMaterialRunType, RunType)
}

func TestSubjectsEmpty(t *testing.T) {
	attestor := &Attestor{}
	subjects := attestor.Subjects()
	assert.NotNil(t, subjects)
	// Should still create subjects even with empty URLs, though they may be empty strings
	assert.Equal(t, 3, len(subjects))
}

// fakeJWT returns a minimal JWS compact serialization that go-jose can parse.
func fakeJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"testkey"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","iss":"gitlab"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesignature"))
	return header + "." + payload + "." + sig
}

func TestJWKSURLOverride(t *testing.T) {
	tests := []struct {
		name        string
		envVal      string
		ciServerURL string
		wantPath    string
	}{
		{
			name:        "default URL derived from CI_SERVER_URL",
			envVal:      "",
			ciServerURL: "", // will be set to mock server
			wantPath:    "/oauth/discovery/keys",
		},
		{
			name:        "custom URL from env overrides default",
			envVal:      "", // will be set to mock server + /custom/jwks
			ciServerURL: "http://should-not-be-used",
			wantPath:    "/custom/jwks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"keys":[]}`))
			}))
			defer mockServer.Close()

			t.Setenv("GITLAB_CI", "true")

			if tt.envVal != "" {
				t.Setenv("WITNESS_GITLAB_JWKS_URL", tt.envVal)
			} else if tt.name == "custom URL from env overrides default" {
				t.Setenv("WITNESS_GITLAB_JWKS_URL", mockServer.URL+"/custom/jwks")
			} else {
				require.NoError(t, os.Unsetenv("WITNESS_GITLAB_JWKS_URL"))
				t.Setenv("CI_SERVER_URL", mockServer.URL)
			}

			a := New(WithToken(fakeJWT()))
			ctx, err := attestation.NewContext("test", []attestation.Attestor{})
			require.NoError(t, err)

			// Attest will fail at JWT signature verification, but it should
			// still hit the JWKS endpoint, proving the URL was correct.
			_ = a.Attest(ctx)

			assert.Equal(t, tt.wantPath, gotPath, "JWKS request should have gone to expected path")
		})
	}
}

func TestJWKSURLOverrideNoToken(t *testing.T) {
	// When no JWT token is available, the JWKS URL is constructed but
	// never used. The attestor should still succeed and populate fields.
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://gitlab.example.com")
	t.Setenv("CI_JOB_ID", "12345")
	t.Setenv("CI_PROJECT_URL", "https://gitlab.example.com/myproject")
	require.NoError(t, os.Unsetenv("CI_JOB_JWT"))
	require.NoError(t, os.Unsetenv("WITNESS_GITLAB_JWKS_URL"))

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "12345", a.JobID)
	assert.Equal(t, "https://gitlab.example.com/myproject", a.ProjectUrl)
	assert.Nil(t, a.JWT)
}
