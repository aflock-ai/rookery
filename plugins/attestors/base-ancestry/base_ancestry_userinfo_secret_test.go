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

package baseancestry

import (
	"strings"
	"testing"
)

const userinfoCanary = "CANARY0SECRET"

// TestBaseAncestryRemotesNeverCarryUserinfoSecrets is the base-ancestry half of
// the gitremote sweep. This attestor keeps its own copy of the remote grammar,
// so the same spellings are held against it: each is stripped or omitted, and
// nothing recorded holds the secret or a token prefix.
func TestBaseAncestryRemotesNeverCarryUserinfoSecrets(t *testing.T) {
	inputs := make([]string, 0, 42)
	inputs = append(inputs,
		"ghs_"+userinfoCanary+"@github.com/acme/api.git",
		userinfoCanary+"@github.com/acme/api.git",
		"ghs%5F"+userinfoCanary+"@github.com/acme/api.git",
		"alice@example.com:ghs_"+userinfoCanary+"@github.com/acme/api.git",
		"https://x-access-token:ghs_"+userinfoCanary+"@github.com/acme/api.git",
		"ssh://git:"+userinfoCanary+"@[2001:db8::1]:2222/acme/api.git",
		"https://github.com/acme/api.git?token="+userinfoCanary,
	)
	for _, p := range []string{"ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_", "glpat-"} {
		tok := p + userinfoCanary
		inputs = append(inputs,
			tok+"@github.com:acme/api.git",
			"git@github.com:acme/"+tok+".git",
			"/srv/git/"+tok+"/api.git",
			"https://github.com/acme/"+tok+".git",
			"git@github.com:acme/"+strings.ReplaceAll(strings.ReplaceAll(tok, "_", "%5F"), "-", "%2D")+".git",
		)
	}
	for _, in := range inputs {
		out, ok := sanitizeRemoteURL(in)
		if !ok {
			if out != "" {
				t.Errorf("omitted remote %q still returned %q", in, out)
			}
			continue
		}
		if strings.Contains(strings.ToUpper(out), userinfoCanary) {
			t.Errorf("sanitizeRemoteURL(%q) = %q, still carries the secret", in, out)
		}
	}
}

func TestBaseAncestryUserinfoSweepPositiveControls(t *testing.T) {
	for _, in := range []string{
		"git@github.com:org/repo.git",
		"https://github.com/acme/api.git",
		"/srv/git/a@b.git",
		"git@[2001:db8::1]:acme/api.git",
		"https://github.com/acme/highs_report.git",
	} {
		out, ok := sanitizeRemoteURL(in)
		if !ok || out != in {
			t.Errorf("sanitizeRemoteURL(%q) = %q %v, want verbatim", in, out, ok)
		}
	}
}
