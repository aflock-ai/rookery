// jade:ring local
//
// Copyright 2026 TestifySec, Inc.
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CI_*_URL variables are recorded, and turned into subjects, as they are
// read. The environment attestor already redacts a URL userinfo from the
// same variables; this attestor signed it verbatim beside it.
func TestAttestRedactsURLCredentials(t *testing.T) {
	const secret = "gitlab-url-pw-1234"
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", "https://ci:"+secret+"@gitlab.example.com")
	t.Setenv("CI_JOB_URL", "https://ci:"+secret+"@gitlab.example.com/g/p/-/jobs/9")
	t.Setenv("CI_PIPELINE_URL", "https://ci:"+secret+"@gitlab.example.com/g/p/-/pipelines/8")
	t.Setenv("CI_PROJECT_URL", "https://ci:"+secret+"@gitlab.example.com/g/p")
	require.NoError(t, os.Unsetenv("CI_JOB_JWT"))
	require.NoError(t, os.Unsetenv("WITNESS_GITLAB_JWKS_URL"))

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, "https://******@gitlab.example.com", a.CIServerUrl)
	assert.Equal(t, "https://******@gitlab.example.com/g/p/-/jobs/9", a.JobUrl)
	assert.Equal(t, "https://******@gitlab.example.com/g/p/-/pipelines/8", a.PipelineUrl)
	assert.Equal(t, "https://******@gitlab.example.com/g/p", a.ProjectUrl)
	predicate, err := json.Marshal(a)
	require.NoError(t, err)
	assert.NotContains(t, string(predicate), secret, "signed predicate carries a credential")
	for subject := range a.Subjects() {
		assert.NotContains(t, subject, secret, "subject name carries a credential")
	}
}

// Redaction is for the record only. The JWKS URL derived from CI_SERVER_URL
// must still carry the configured login to the server, or a GitLab behind
// basic auth stops verifying its job token.
func TestAttestFetchesJWKSWithTheConfiguredLogin(t *testing.T) {
	const secret = "gitlab-jwks-pw-1234"
	var gotUser, gotPassword string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPassword, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_SERVER_URL", strings.Replace(server.URL, "http://", "http://ci:"+secret+"@", 1))
	require.NoError(t, os.Unsetenv("WITNESS_GITLAB_JWKS_URL"))

	a := New(WithToken(fakeJWT()))
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)
	_ = a.Attest(ctx) // fails at signature verification, after the fetch

	assert.Equal(t, "ci", gotUser)
	assert.Equal(t, secret, gotPassword)
	assert.NotContains(t, a.CIServerUrl, secret)
}
