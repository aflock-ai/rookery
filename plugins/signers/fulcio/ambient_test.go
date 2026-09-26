// jade:ring local

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

package fulcio

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const fakeJWT = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln"

type fakeCI struct {
	env   map[string]string
	out   string
	err   error
	calls [][]string
}

func (f *fakeCI) source() ambientSource {
	return ambientSource{
		getenv: func(k string) string { return f.env[k] },
		run: func(_ context.Context, name string, args ...string) (string, error) {
			f.calls = append(f.calls, append([]string{name}, args...))
			return f.out, f.err
		},
	}
}

func TestAmbientCITokenGitLabReadsTheConfiguredIDTokenVariable(t *testing.T) {
	f := &fakeCI{env: map[string]string{"GITLAB_CI": "true", "SIGSTORE_ID_TOKEN": fakeJWT + "\n"}}
	tok, ci, err := ambientCIToken(context.Background(), f.source(), "")
	if err != nil || ci != "GitLab CI" || tok != fakeJWT {
		t.Fatalf("got (%q, %q, %v), want the SIGSTORE_ID_TOKEN value", tok, ci, err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("GitLab must not exec anything, ran %v", f.calls)
	}

	f = &fakeCI{env: map[string]string{"GITLAB_CI": "true", "MY_TOKEN": fakeJWT}}
	tok, _, err = ambientCIToken(context.Background(), f.source(), "MY_TOKEN")
	if err != nil || tok != fakeJWT {
		t.Fatalf("a renamed id_tokens variable must be honoured: (%q, %v)", tok, err)
	}
}

func TestAmbientCITokenGitLabRefusesClearlyWhenTheVariableIsAbsent(t *testing.T) {
	f := &fakeCI{env: map[string]string{"GITLAB_CI": "true"}}
	_, ci, err := ambientCIToken(context.Background(), f.source(), "")
	if err == nil || ci != "GitLab CI" {
		t.Fatalf("want a refusal on GitLab without the token variable, got (%q, %v)", ci, err)
	}
	for _, want := range []string{"SIGSTORE_ID_TOKEN", "id_tokens", "aud: sigstore"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must tell the user how to fix it; missing %q in: %v", want, err)
		}
	}
}

func TestAmbientCITokenBuildkiteRequestsTheSigstoreAudience(t *testing.T) {
	f := &fakeCI{env: map[string]string{"BUILDKITE": "true"}, out: fakeJWT + "\n"}
	tok, ci, err := ambientCIToken(context.Background(), f.source(), "")
	if err != nil || ci != "Buildkite" || tok != fakeJWT {
		t.Fatalf("got (%q, %q, %v)", tok, ci, err)
	}
	want := "buildkite-agent oidc request-token --audience sigstore"
	if len(f.calls) != 1 || strings.Join(f.calls[0], " ") != want {
		t.Fatalf("ran %v, want exactly %q", f.calls, want)
	}
}

func TestAmbientCITokenCircleCIRequestsTheSigstoreAudience(t *testing.T) {
	// $CIRCLE_OIDC_TOKEN[_V2] carries aud=<org-id>, which the platform Fulcio
	// refuses; a token for Fulcio must be minted with aud=sigstore.
	f := &fakeCI{env: map[string]string{"CIRCLECI": "true", "CIRCLE_OIDC_TOKEN_V2": "wrong-audience", "CIRCLE_OIDC_TOKEN": "wrong-audience"}, out: fakeJWT}
	tok, ci, err := ambientCIToken(context.Background(), f.source(), "")
	if err != nil || ci != "CircleCI" || tok != fakeJWT {
		t.Fatalf("got (%q, %q, %v)", tok, ci, err)
	}
	want := `circleci run oidc get --claims {"aud":"sigstore"}`
	if len(f.calls) != 1 || strings.Join(f.calls[0], " ") != want {
		t.Fatalf("ran %v, want exactly %q", f.calls, want)
	}
}

func TestAmbientCITokenRefusesAFailedOrMalformedFetch(t *testing.T) {
	cases := map[string]*fakeCI{
		"buildkite command fails": {env: map[string]string{"BUILDKITE": "true"}, err: errors.New("exit status 1")},
		"circleci command fails":  {env: map[string]string{"CIRCLECI": "true"}, err: errors.New("not found")},
		"buildkite prints junk":   {env: map[string]string{"BUILDKITE": "true"}, out: "Error: no job token"},
		"circleci prints nothing": {env: map[string]string{"CIRCLECI": "true"}, out: "  \n"},
		"gitlab var is not a JWT": {env: map[string]string{"GITLAB_CI": "true", "SIGSTORE_ID_TOKEN": "not-a-jwt"}},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			tok, ci, err := ambientCIToken(context.Background(), f.source(), "")
			if err == nil || tok != "" || ci == "" {
				t.Fatalf("want a refusal, got (%q, %q, %v)", tok, ci, err)
			}
		})
	}
}

func TestAmbientCITokenOutsideASupportedCIDoesNothing(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{"GITLAB_CI": "1"}, // only the exact value the vendor sets counts
		{"JENKINS_URL": "https://ci.example"},
		{"SIGSTORE_ID_TOKEN": fakeJWT}, // a token alone does not make this GitLab
	} {
		f := &fakeCI{env: env}
		tok, ci, err := ambientCIToken(context.Background(), f.source(), "")
		if tok != "" || ci != "" || err != nil || len(f.calls) != 0 {
			t.Fatalf("env %v: got (%q, %q, %v, calls %v), want nothing", env, tok, ci, err, f.calls)
		}
	}
}

// TestSignerRefusesOnGitLabWithoutTheIDToken proves the refusal surfaces from
// Signer itself, before any request to Fulcio, instead of the generic
// "no token provided" message.
func TestSignerRefusesOnGitLabWithoutTheIDToken(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("SIGSTORE_ID_TOKEN", "")
	fsp := New(WithFulcioURL("https://fulcio.invalid"))
	_, err := fsp.Signer(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SIGSTORE_ID_TOKEN") {
		t.Fatalf("want the GitLab id_tokens refusal, got %v", err)
	}
}
