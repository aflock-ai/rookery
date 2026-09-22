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

package jenkins

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// JENKINS_URL and BUILD_URL are recorded, and turned into subjects, as they
// are read. A Jenkins behind basic auth is often configured with the login in
// the URL, and the environment attestor already redacts that userinfo from
// the same variables; this attestor signed it verbatim beside it.
func TestAttestRedactsURLCredentials(t *testing.T) {
	const secret = "jenkins-url-pw-1234"
	t.Setenv("JENKINS_URL", "https://ci:"+secret+"@jenkins.example.com/")
	t.Setenv("BUILD_URL", "https://ci:"+secret+"@jenkins.example.com/job/app/7/")

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, "https://******@jenkins.example.com/", a.JenkinsUrl)
	assert.Equal(t, "https://******@jenkins.example.com/job/app/7/", a.PipelineUrl)
	predicate, err := json.Marshal(a)
	require.NoError(t, err)
	assert.NotContains(t, string(predicate), secret, "signed predicate carries a credential")
	for subject := range a.Subjects() {
		assert.NotContains(t, subject, secret, "subject name carries a credential")
	}
}

// A URL without userinfo is recorded unchanged.
func TestAttestKeepsPlainURLs(t *testing.T) {
	t.Setenv("JENKINS_URL", "https://jenkins.example.com/")
	t.Setenv("BUILD_URL", "https://jenkins.example.com/job/app/7/")

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, "https://jenkins.example.com/", a.JenkinsUrl)
	assert.Equal(t, "https://jenkins.example.com/job/app/7/", a.PipelineUrl)
}
