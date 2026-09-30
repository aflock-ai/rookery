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

package cli

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// --dry-run resolves everything a bind would bind (definition, release,
// product) and reports it, and never sends the createPolicyBinding mutation.
func TestPolicyBind_DryRunResolvesAndDoesNotBind(t *testing.T) {
	mutated := false
	srv := newPolicyTestServer(t, func(q string, _ map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockPolicyDefByName"):
			_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-1","name":"supply-chain"}}]}}}`)
		case strings.Contains(q, "CilockReleaseByTag"):
			_, _ = io.WriteString(w, `{"data":{"policyReleases":{"edges":[{"node":{"id":"rel-7","tag":"v1.0.0"}}]}}}`)
		case strings.Contains(q, "CilockProductByID"):
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[]}}}`)
		case strings.Contains(q, "CilockProductByName"):
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[{"node":{"id":"prod-1","name":"svc"}}]}}}`)
		case strings.Contains(q, "CilockCreatePolicyBinding"):
			mutated = true
			_, _ = io.WriteString(w, `{"data":{"createPolicyBinding":{"id":"bind-1"}}}`)
		default:
			return false
		}
		return true
	})
	stubSession(t, srv.URL)

	out, err := runCmd(t, PolicyBindCmd(),
		"--definition", "supply-chain", "--tag", "v1.0.0", "--product", "svc", "--platform-url", srv.URL, "--dry-run")
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if mutated {
		t.Fatal("--dry-run sent createPolicyBinding")
	}
	for _, want := range []string{"would bind", "def-1", "rel-7", "v1.0.0", "prod-1", "nothing was changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "✓ bound") {
		t.Errorf("a dry run must not claim a binding:\n%s", out)
	}
}

// A dry run refuses what a real bind refuses: no release pinned is an error
// before any platform call.
func TestPolicyBind_DryRunKeepsTheReleaseRule(t *testing.T) {
	_, err := runCmd(t, PolicyBindCmd(), "--definition", "d", "--product", "p", "--dry-run")
	if err == nil || !strings.Contains(err.Error(), "without an exact release") {
		t.Fatalf("dry run without a release: err = %v", err)
	}
}
