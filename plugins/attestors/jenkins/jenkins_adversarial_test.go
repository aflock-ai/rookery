//go:build audit

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

package jenkins

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FINDING 1: No JWT/OIDC token - pure environment variable attestation
// Severity: CRITICAL
//
// The Jenkins attestor is the WORST of all four SCM attestors because it has
// absolutely NO cryptographic identity verification. There is no JWT, no
// OIDC token, no signature, no challenge-response -- NOTHING.
//
// All attestation fields come entirely from environment variables that ANY
// process can set. An attacker who can set env vars (e.g., running on a
// developer workstation, in a compromised container, or via env injection)
// can produce a Jenkins attestation that claims to be from any Jenkins server,
// any build, any pipeline.
//
// The only "guard" is checking that JENKINS_URL is set (not even checking
// its value!). os.LookupEnv("JENKINS_URL") returns true for JENKINS_URL="".
// =============================================================================

func TestAdversarial_NoIdentityVerification(t *testing.T) {
	// Set up a completely fake Jenkins environment
	t.Setenv("JENKINS_URL", "https://jenkins.legit-corp.com/")
	t.Setenv("BUILD_ID", "42")
	t.Setenv("BUILD_NUMBER", "42")
	t.Setenv("BUILD_TAG", "jenkins-legit-pipeline-42")
	t.Setenv("BUILD_URL", "https://jenkins.legit-corp.com/job/legit-pipeline/42/")
	t.Setenv("EXECUTOR_NUMBER", "0")
	t.Setenv("JAVA_HOME", "/usr/lib/jvm/java-11")
	t.Setenv("JOB_NAME", "legit-pipeline")
	t.Setenv("NODE_NAME", "built-in")
	t.Setenv("WORKSPACE", "/var/jenkins_home/workspace/legit-pipeline")

	a := New()
	ctx, err := attestation.NewContext("build", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err, "Attestation succeeded with ZERO identity verification")

	// Every field is attacker-controlled
	assert.Equal(t, "https://jenkins.legit-corp.com/", a.JenkinsUrl)
	assert.Equal(t, "42", a.BuildID)
	assert.Equal(t, "legit-pipeline", a.JobName)
	assert.Equal(t, "https://jenkins.legit-corp.com/job/legit-pipeline/42/", a.PipelineUrl)

	subjects := a.Subjects()
	assert.NotEmpty(t, subjects,
		"CRITICAL: Subjects are generated from completely unverified env vars. "+
			"No JWT, no OIDC, no cryptographic proof of identity. "+
			"Any process on any machine can produce a valid Jenkins attestation.")
}

// =============================================================================
// FINDING 2: JENKINS_URL existence check is trivially bypassable
// Severity: HIGH
//
// The guard is: _, ok := os.LookupEnv("JENKINS_URL"); !ok
// This only checks if the variable EXISTS, not its value.
// JENKINS_URL="" passes the check.
// =============================================================================

func TestAdversarial_EmptyJenkinsURL(t *testing.T) {
	t.Setenv("JENKINS_URL", "") // Empty string passes LookupEnv

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err,
		"BUG: JENKINS_URL='' passes the environment check. "+
			"os.LookupEnv returns ('''', true) for an empty value. "+
			"The check should validate the URL is non-empty and well-formed.")

	assert.Empty(t, a.JenkinsUrl,
		"JenkinsUrl is empty string - not a valid Jenkins URL")

	// Subjects are still created
	subjects := a.Subjects()
	assert.NotEmpty(t, subjects,
		"Subjects created from empty JenkinsUrl - digest of empty string")
}

// =============================================================================
// FINDING 3: URL fields accept arbitrary values
// Severity: MEDIUM
//
// BUILD_URL and JENKINS_URL are stored without validation.
// These become attestation subjects used in policy evaluation.
// =============================================================================

func TestAdversarial_MaliciousURLValues(t *testing.T) {
	testCases := []struct {
		name       string
		envVar     string
		value      string
		fieldCheck func(*Attestor) string
	}{
		{
			name:       "javascript URI in BUILD_URL",
			envVar:     "BUILD_URL",
			value:      "javascript:alert(document.cookie)",
			fieldCheck: func(a *Attestor) string { return a.PipelineUrl },
		},
		{
			name:       "data URI in JENKINS_URL",
			envVar:     "JENKINS_URL",
			value:      "data:text/html,<script>alert(1)</script>",
			fieldCheck: func(a *Attestor) string { return a.JenkinsUrl },
		},
		{
			name:       "CRLF injection in BUILD_URL",
			envVar:     "BUILD_URL",
			value:      "https://jenkins.com/job/test/1/\r\nX-Injected: true",
			fieldCheck: func(a *Attestor) string { return a.PipelineUrl },
		},
		{
			name:       "null bytes in JENKINS_URL",
			envVar:     "JENKINS_URL",
			value:      "https://jenkins.com/\x00evil",
			fieldCheck: func(a *Attestor) string { return a.JenkinsUrl },
		},
		{
			name:       "path traversal in BUILD_URL",
			envVar:     "BUILD_URL",
			value:      "https://jenkins.com/../../../etc/passwd",
			fieldCheck: func(a *Attestor) string { return a.PipelineUrl },
		},
		{
			name:       "extremely long URL (100KB)",
			envVar:     "BUILD_URL",
			value:      "https://jenkins.com/" + strings.Repeat("A", 100000),
			fieldCheck: func(a *Attestor) string { return a.PipelineUrl },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JENKINS_URL", "https://jenkins.com")
			t.Setenv(tc.envVar, tc.value)

			a := New()
			ctx, err := attestation.NewContext("test", []attestation.Attestor{})
			require.NoError(t, err)

			err = a.Attest(ctx)
			require.NoError(t, err)

			got := tc.fieldCheck(a)
			assert.Equal(t, tc.value, got,
				"BUG: Malicious value stored verbatim: %q", tc.value[:min(50, len(tc.value))])
		})
	}
}

// =============================================================================
// FINDING 4: Workspace path disclosure
// Severity: LOW
//
// The WORKSPACE env var is stored in the attestation, revealing the
// filesystem path structure of the Jenkins server. This is an information
// disclosure that could help an attacker map the server's layout.
// =============================================================================

func TestAdversarial_WorkspacePathDisclosure(t *testing.T) {
	t.Setenv("JENKINS_URL", "https://jenkins.com")
	t.Setenv("WORKSPACE", "/var/jenkins_home/workspace/secret-project")
	t.Setenv("JAVA_HOME", "/usr/lib/jvm/java-17-openjdk-amd64")

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, "/var/jenkins_home/workspace/secret-project", a.Workspace,
		"Workspace path stored in attestation - information disclosure")
	assert.Equal(t, "/usr/lib/jvm/java-17-openjdk-amd64", a.JavaHome,
		"JAVA_HOME stored in attestation - reveals server JDK configuration")

	t.Log("NOTE: WORKSPACE and JAVA_HOME reveal server filesystem paths. " +
		"Consider whether these are necessary in the attestation, or if " +
		"they should be obfuscated/hashed.")
}

// =============================================================================
// FINDING 5: Subject collision with empty values
// Severity: MEDIUM
//
// When env vars are not set, Subjects() creates digests from empty strings.
// Multiple unrelated Jenkins attestations with missing fields will have
// identical subjects, potentially matching each other in policy evaluation.
// =============================================================================

func TestAdversarial_EmptySubjectCollision(t *testing.T) {
	// Two different "Jenkins" environments, both with no BUILD_URL or JENKINS_URL
	a1 := &Attestor{PipelineUrl: "", JenkinsUrl: ""}
	a2 := &Attestor{PipelineUrl: "", JenkinsUrl: ""}

	s1 := a1.Subjects()
	s2 := a2.Subjects()

	require.Equal(t, len(s1), len(s2))

	for key, ds1 := range s1 {
		ds2, exists := s2[key]
		require.True(t, exists)
		assert.Equal(t, ds1, ds2,
			"BUG: Empty-value subjects collide. Two unrelated Jenkins attestations "+
				"with missing env vars produce identical subjects (SHA256 of empty string). "+
				"Policy evaluation could incorrectly match them.")
	}

	// Also verify the subject keys contain "pipelineurl:" and "jenkinsurl:"
	// with empty values
	foundPipeline := false
	foundJenkins := false
	for key := range s1 {
		if strings.HasPrefix(key, "pipelineurl:") {
			foundPipeline = true
			assert.Equal(t, "pipelineurl:", key,
				"Pipeline URL subject key should be 'pipelineurl:' with empty value")
		}
		if strings.HasPrefix(key, "jenkinsurl:") {
			foundJenkins = true
			assert.Equal(t, "jenkinsurl:", key,
				"Jenkins URL subject key should be 'jenkinsurl:' with empty value")
		}
	}
	assert.True(t, foundPipeline, "Should have pipelineurl subject")
	assert.True(t, foundJenkins, "Should have jenkinsurl subject")
}

// =============================================================================
// FINDING 6: BuildTag can contain arbitrary content
// Severity: LOW
//
// BUILD_TAG typically has format "jenkins-JOBNAME-BUILDNUMBER" but the
// attestor accepts any value. This could be used to inject misleading
// information into the attestation.
// =============================================================================

func TestAdversarial_BuildTagInjection(t *testing.T) {
	t.Setenv("JENKINS_URL", "https://jenkins.com")
	t.Setenv("BUILD_TAG", "jenkins-legit-pipeline-42\n{\"injected\":\"json\"}")

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err)

	assert.Contains(t, a.BuildTag, "\n",
		"BUG: BuildTag contains newline. No format validation on BUILD_TAG.")
	assert.Contains(t, a.BuildTag, "injected",
		"BuildTag accepted arbitrary content including embedded JSON")
}

// =============================================================================
// FINDING 7: BackRefs consistency
// Severity: LOW
//
// Same map iteration non-determinism issue as GitLab.
// =============================================================================

func TestAdversarial_BackRefsConsistency(t *testing.T) {
	a := &Attestor{
		PipelineUrl: "https://jenkins.com/job/test/1/",
		JenkinsUrl:  "https://jenkins.com/",
	}

	var lastKey string
	for i := 0; i < 100; i++ {
		refs := a.BackRefs()
		require.Len(t, refs, 1)
		for k := range refs {
			if lastKey == "" {
				lastKey = k
			}
			assert.Equal(t, lastKey, k,
				"BackRefs returned different key on iteration %d", i)
		}
	}
}

// =============================================================================
// FINDING 8: Complete attestation from non-Jenkins machine
// Severity: CRITICAL
//
// Demonstrates that a full, valid-looking Jenkins attestation can be created
// from any machine with zero access to Jenkins.
// =============================================================================

func TestAdversarial_CompleteForgedAttestation(t *testing.T) {
	// This could be running on a developer laptop, a random cloud VM, etc.
	// As long as we set these env vars, we get a "Jenkins" attestation.
	t.Setenv("JENKINS_URL", "https://jenkins.production.megacorp.com/")
	t.Setenv("BUILD_ID", "1337")
	t.Setenv("BUILD_NUMBER", "1337")
	t.Setenv("BUILD_TAG", "jenkins-deploy-to-prod-1337")
	t.Setenv("BUILD_URL", "https://jenkins.production.megacorp.com/job/deploy-to-prod/1337/")
	t.Setenv("EXECUTOR_NUMBER", "2")
	t.Setenv("JAVA_HOME", "/usr/lib/jvm/java-17")
	t.Setenv("JOB_NAME", "deploy-to-prod")
	t.Setenv("NODE_NAME", "production-node-1")
	t.Setenv("WORKSPACE", "/var/jenkins_home/workspace/deploy-to-prod")

	a := New()
	ctx, err := attestation.NewContext("deploy", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err)

	// Every field matches what a real Jenkins deploy would look like
	assert.Equal(t, "https://jenkins.production.megacorp.com/", a.JenkinsUrl)
	assert.Equal(t, "1337", a.BuildID)
	assert.Equal(t, "deploy-to-prod", a.JobName)
	assert.Equal(t, "production-node-1", a.NodeName)

	// Subjects look legitimate
	subjects := a.Subjects()
	pipelineKey := fmt.Sprintf("pipelineurl:%s", a.PipelineUrl)
	_, exists := subjects[pipelineKey]
	assert.True(t, exists,
		"CRITICAL: A completely forged Jenkins attestation produces valid subjects. "+
			"Without JWT/OIDC, there is NO way to distinguish this from a real Jenkins build. "+
			"Policy evaluation that relies on Jenkins attestation subjects alone is broken.")

	backRefs := a.BackRefs()
	assert.Len(t, backRefs, 1,
		"BackRefs contain forged pipeline URL - indistinguishable from real")
}

// =============================================================================
// FINDING 9: LookupEnv vs Getenv inconsistency
// Severity: LOW
//
// JENKINS_URL uses os.LookupEnv (checks existence), but all other fields
// use os.Getenv (returns empty string if not set). This means:
// - JENKINS_URL="" -> attestation succeeds, JenkinsUrl=""
// - Missing BUILD_ID -> BuildID="" (no error)
// There's no consistency in how missing vs empty is handled.
// =============================================================================

func TestAdversarial_MissingEnvVarsStillSucceed(t *testing.T) {
	// Only set JENKINS_URL, leave everything else unset
	t.Setenv("JENKINS_URL", "https://jenkins.com")

	// Explicitly unset everything else
	for _, env := range []string{"BUILD_ID", "BUILD_NUMBER", "BUILD_TAG",
		"BUILD_URL", "EXECUTOR_NUMBER", "JAVA_HOME", "JOB_NAME",
		"NODE_NAME", "WORKSPACE"} {
		require.NoError(t, os.Unsetenv(env))
	}

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{})
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err,
		"Attestation succeeds with all fields empty except JENKINS_URL")

	assert.Empty(t, a.BuildID, "BuildID is empty - no error")
	assert.Empty(t, a.BuildNumber, "BuildNumber is empty - no error")
	assert.Empty(t, a.PipelineUrl, "PipelineUrl is empty - no error")
	assert.Empty(t, a.JobName, "JobName is empty - no error")

	// Empty subjects still generated
	subjects := a.Subjects()
	assert.NotEmpty(t, subjects,
		"BUG: Subjects generated from all-empty fields. "+
			"Attestation should require at minimum BUILD_URL and BUILD_ID to be non-empty.")
}

// =============================================================================
// FINDING 10: Schema returns pointer-to-pointer
// Severity: LOW (correctness)
//
// Schema() calls jsonschema.Reflect(&a) where a is already *Attestor.
// This passes **Attestor to Reflect, which may produce an incorrect schema.
// GitLab and GitHub correctly pass (a) or (&a) for the value type.
// =============================================================================

func TestAdversarial_SchemaReflection(t *testing.T) {
	a := New()
	schema := a.Schema()
	require.NotNil(t, schema)

	// Check that the schema has the expected structure
	// If &a is passed (where a is *Attestor), Reflect gets **Attestor
	// which may not produce the expected definitions
	t.Logf("Schema type: %v", schema.Type)
	if schema.Definitions != nil {
		t.Logf("Schema definitions: %v", func() []string {
			keys := make([]string, 0, len(schema.Definitions))
			for k := range schema.Definitions {
				keys = append(keys, k)
			}
			return keys
		}())
	}

	// The git attestor has the same bug: jsonschema.Reflect(&a) where a is *Attestor
	// The correct call should be jsonschema.Reflect(a) to pass *Attestor
	t.Log("NOTE: Schema() uses jsonschema.Reflect(&a) which passes **Attestor. " +
		"This may produce an incorrect schema definition. " +
		"Should be jsonschema.Reflect(a) to pass *Attestor.")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
