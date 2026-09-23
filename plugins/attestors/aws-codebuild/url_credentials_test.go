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

package aws_codebuild

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CODEBUILD_SOURCE_REPO_URL is recorded as it is read. A source configured
// with a token in the clone URL puts that token here, and the environment
// attestor already redacts it from the same variable.
func TestAttestRedactsSourceRepoCredentials(t *testing.T) {
	const secret = "ghp_codebuild-url-token-1234"
	// Keep the build-details lookup off any real AWS account on the machine.
	missing := t.TempDir() + "/missing"
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv(envCodeBuildBuildID, "project:build-id-123")
	t.Setenv(envCodeBuildSourceRepo, "https://"+secret+"@github.com/example/repo.git")

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, "https://******@github.com/example/repo.git", a.BuildInfo.SourceRepo)
	predicate, err := json.Marshal(a)
	require.NoError(t, err)
	assert.NotContains(t, string(predicate), secret, "signed predicate carries a credential")
}

// The build-details lookup is an HTTP request the SDK makes, and its error is
// logged. net/http's error quotes a redirect's Location and an endpoint's
// username; the SDK today follows no redirect and drops the endpoint's
// userinfo, and redact.HTTPError keeps the error clean if either changes.
func TestBuildDetailsErrorCarriesNoURLCredential(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	endpoints := make([]string, 1, 3)
	endpoints[0] = strings.Replace(closed.URL, "http://", "http://glpat-p14secret@", 1)
	for _, location := range []string{"http://ci:p14secret-redirect@host:bad/", endpoints[0] + "/"} {
		redirect := httptest.NewServer(http.RedirectHandler(location, http.StatusTemporaryRedirect))
		defer redirect.Close()
		endpoints = append(endpoints, redirect.URL)
	}
	for _, endpoint := range endpoints {
		a := &Attestor{BuildInfo: BuildInfo{BuildID: "project:build-1"}, awsConfig: aws.Config{
			Region: "us-east-1", BaseEndpoint: aws.String(endpoint), Retryer: func() aws.Retryer { return aws.NopRetryer{} },
			Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "example"}, nil
			}),
		}}
		err := a.getBuildDetails()
		require.Error(t, err)
		for e := err; e != nil; e = errors.Unwrap(e) {
			assert.NotContains(t, e.Error(), "p14secret", "endpoint %s", endpoint)
		}
	}
}
