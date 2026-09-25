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

// jade:ring local

package attestation

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"slices"
	"testing"
)

// unsignedJWT builds an UNSIGNED JWT carrying claims. Only the claims are
// ever parsed; nothing here verifies a signature.
func unsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
}

// Windows resolves environment names case-insensitively, so a lowercase or
// mixed-case credential is the same credential there: it must be withheld, or
// the step reads it back through the uppercase name while the predicate says
// "scrubbed".
func TestScrubFoldsNameCaseWhereTheOSDoes(t *testing.T) {
	if got, want := envNamesFoldCase, runtime.GOOS == "windows"; got != want {
		t.Fatalf("envNamesFoldCase = %v on %s, want %v", got, runtime.GOOS, want)
	}
	prev := envNamesFoldCase
	envNamesFoldCase = true
	t.Cleanup(func() { envNamesFoldCase = prev })

	selfManaged := unsignedJWT(t, map[string]any{"iss": "https://gitlab.example.com"})
	in := []string{
		"A=1",
		"actions_id_token_request_token=y",
		"Actions_Id_Token_Request_Url=https://token.example",
		"Sigstore_Id_Token=z",
		"ci_job_jwt_v2=w",
		"ci_server_url=https://gitlab.example.com",
		"VAULT_ID_TOKEN=" + selfManaged,
	}
	out, removed := ScrubCIOIDCCredentials(in)
	wantOut := []string{"A=1", "ci_server_url=https://gitlab.example.com"}
	if !slices.Equal(out, wantOut) {
		t.Errorf("env = %v, want %v", out, wantOut)
	}
	wantRemoved := []string{"actions_id_token_request_token", "Actions_Id_Token_Request_Url", "Sigstore_Id_Token", "ci_job_jwt_v2", "VAULT_ID_TOKEN"}
	if !slices.Equal(removed, wantRemoved) {
		t.Errorf("removed = %v, want %v", removed, wantRemoved)
	}

	// Two spellings of one name are one variable on Windows: record it once.
	_, removed = ScrubCIOIDCCredentials([]string{"SIGSTORE_ID_TOKEN=a", "sigstore_id_token=b"})
	if len(removed) != 1 {
		t.Errorf("removed = %v, want a single entry for one case-folded name", removed)
	}
}

// On POSIX, names are case-sensitive: a lowercase look-alike is a different
// variable no tool reads as the credential, so it passes through.
func TestScrubCIOIDCCredentialsIsCaseExactAndKeepsOrder(t *testing.T) {
	prev := envNamesFoldCase
	envNamesFoldCase = false
	t.Cleanup(func() { envNamesFoldCase = prev })
	in := []string{"A=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=x", "actions_id_token_request_token=y", "B=2", "CI_JOB_JWT_V2=z", "NOEQUALS"}
	out, removed := ScrubCIOIDCCredentials(in)
	wantOut := []string{"A=1", "actions_id_token_request_token=y", "B=2", "NOEQUALS"}
	if !slices.Equal(out, wantOut) {
		t.Errorf("env = %v, want %v", out, wantOut)
	}
	if !slices.Equal(removed, []string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "CI_JOB_JWT_V2"}) {
		t.Errorf("removed = %v", removed)
	}
}
