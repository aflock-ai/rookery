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

package cli

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A binding with no release is "latest", which no component may select, and
// the platform enforces it nowhere. The CLI refuses to create one, BEFORE
// reaching the platform.
func TestPolicyBind_RefusesAnUnpinnedReleaseBeforeAnyCall(t *testing.T) {
	calls := 0
	srv := newPolicyTestServer(t, func(string, map[string]any, http.ResponseWriter) bool { calls++; return false })
	stubSession(t, srv.URL)
	for name, args := range map[string][]string{
		"no release":      {"-d", "supply-chain", "--product", "svc"},
		"release is name": {"-d", "supply-chain", "--release", "latest", "--product", "svc"},
		"release upper":   {"-d", "supply-chain", "--release", "6A4E31BC-A182-4CDF-A909-C4419377C802", "--product", "svc"},
		"latest flag":     {"-d", "supply-chain", "--latest", "--product", "svc"},
	} {
		_, err := runCmd(t, PolicyBindCmd(), append(args, "--platform-url", srv.URL)...)
		if err == nil {
			t.Errorf("%s: bind was accepted", name)
			continue
		}
		if name == "no release" && !strings.Contains(err.Error(), "--release <uuid>") {
			t.Errorf("%s: refusal does not name the remedy: %v", name, err)
		}
	}
	if calls != 0 {
		t.Fatalf("a refused bind reached the platform %d time(s)", calls)
	}
}

// An exact release id binds exactly that release.
func TestPolicyBind_ExactReleaseIsBound(t *testing.T) {
	const rel = "6a4e31bc-a182-4cdf-a909-c4419377c802"
	var bindInput map[string]any
	srv := newPolicyTestServer(t, func(q string, vars map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockPolicyDefByName"):
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-1","name":"supply-chain"}}]}}}`)
		case strings.Contains(q, "CilockProductBy") || strings.Contains(q, "products"):
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[{"node":{"id":"prod-1","name":"svc"}}]}}}`)
		case strings.Contains(q, "CilockCreatePolicyBinding"):
			bindInput, _ = vars["input"].(map[string]any)
			_, _ = io.WriteString(w, `{"data":{"createPolicyBinding":{"id":"bind-1","policyDefinition":{"id":"def-1","name":"supply-chain"},"policyRelease":{"id":"`+rel+`","tag":"v1"},"product":{"id":"prod-1","name":"svc"}}}}`)
		default:
			return false
		}
		return true
	})
	stubSession(t, srv.URL)
	out, err := runCmd(t, PolicyBindCmd(), "-d", "supply-chain", "--release", rel, "--product", "svc", "--platform-url", srv.URL)
	if err != nil {
		t.Fatalf("bind: %v\n%s", err, out)
	}
	if bindInput["policyReleaseID"] != rel {
		t.Fatalf("bound release %v, want %s", bindInput["policyReleaseID"], rel)
	}
}
