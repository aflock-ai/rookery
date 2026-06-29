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

package options

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestSecurity_Issue5987_RedirectLeaksBearer asserts that PolicyClient.post does
// NOT follow a cross-origin 30x redirect — following it would resend the
// Authorization: Bearer header (and request body) to the redirect target.
//
// Without the fix, the default http.Client follows up to 10 redirects, so the
// "attacker" origin is reached with the bearer. SECURE behavior: the redirect
// target is never contacted and post returns an error.
func TestSecurity_Issue5987_RedirectLeaksBearer(t *testing.T) {
	var attackerHit int32

	// The redirect TARGET: an off-origin "attacker" that must never be reached.
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attackerHit, 1)
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("bearer leaked to attacker via redirect: Authorization=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer attacker.Close()

	// The "platform" GraphQL endpoint 302s cross-origin to the attacker.
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/query", http.StatusFound)
	}))
	defer platform.Close()

	c := &PolicyClient{GraphQLURL: platform.URL + "/query", Token: "secret-bearer"}

	var out map[string]any
	err := c.post(context.Background(), `query { __typename }`, nil, &out)

	if atomic.LoadInt32(&attackerHit) != 0 {
		t.Fatalf("cross-origin redirect target was reached %d time(s) — bearer leaked", attackerHit)
	}
	if err == nil {
		t.Fatalf("post followed a cross-origin redirect without error; expected refusal")
	}
}
