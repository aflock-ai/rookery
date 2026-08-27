// Copyright 2026 The Aflock Authors
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

package options

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// TestSummaryReportsTheAssuranceLevelOfTheTokenThatSigned pins the second
// half of the signing-time refresh: the run summary's assurance level must
// describe the credential that actually bought the certificate. The pre-command
// exchange is minted at one level, the signing-time re-exchange at another, and
// the summary -- which cli/run.go builds from a BY-VALUE copy of RunOptions
// taken before the command -- must report the second. Reporting the first
// would let evidence claim a stronger AAL than the identity that signed it.
func TestSummaryReportsTheAssuranceLevelOfTheTokenThatSigned(t *testing.T) {
	isolateCredentialStore(t)

	var exchanges int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/oauth/sign-token" {
			http.NotFound(w, r)
			return
		}
		i := atomic.AddInt64(&exchanges, 1)
		level := "aal2"
		if i > 1 {
			// The session was stepped down between option resolution and
			// signing; the platform now mints at a weaker level.
			level = "aal1"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token":           "session-token-" + strconv.FormatInt(i, 10),
			"token_type":      "oidc",
			"assurance_level": level,
		})
	}))
	t.Cleanup(srv.Close)

	if err := auth.Save(auth.Credential{
		PlatformURL: srv.URL,
		Token:       "stored-session-credential",
		AuthMode:    auth.AuthModeBrowser,
	}); err != nil {
		t.Fatal(err)
	}

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if got := ro.ResolvedAssuranceLevel(); got != "aal2" {
		t.Fatalf("precondition: pre-command exchange should report aal2, got %q", got)
	}
	refresh := ro.FulcioTokenRefresher()
	if refresh == nil {
		t.Fatal("precondition: a stored session must install a signing-time refresher")
	}

	// cli/run.go hands RunOptions to runRun by value BEFORE the wrapped command
	// and builds the summary from that copy AFTER signing. Take the same copy.
	summaryView := *ro

	if err := refresh(); err != nil {
		t.Fatalf("signing-time refresh failed: %v", err)
	}
	if exchanges != 2 {
		t.Fatalf("expected the refresher to re-exchange, saw %d exchanges", exchanges)
	}

	if got := summaryView.ResolvedAssuranceLevel(); got != "aal1" {
		t.Fatalf("the summary reports assurance %q, but the token that bought the certificate was minted at aal1; "+
			"the signing-time exchange's assurance level was discarded", got)
	}
	if got := ro.ResolvedAssuranceLevel(); got != "aal1" {
		t.Fatalf("RunOptions itself reports %q after the refresh, want aal1", got)
	}
}
