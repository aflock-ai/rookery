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

package gitremote

import (
	"strings"
	"testing"
)

// userinfoCanary is the secret body every case below plants. It is short and
// built at runtime so no fixture here matches a real token pattern.
const userinfoCanary = "CANARY0SECRET"

// sweepTokenPrefixes is spelled out independently of production on purpose.
var sweepTokenPrefixes = []string{"ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_", "glpat-"}

type secretCase struct {
	name   string
	in     string
	secret string
	// want, when set, is the exact value a redaction must record.
	want string
}

func userinfoSecretCases() []secretCase {
	tok := "ghs_" + userinfoCanary
	cases := make([]secretCase, 0, 20+8*len(sweepTokenPrefixes))
	cases = append(cases, []secretCase{
		// scp form: the token sits in the PATH's first segment, as userinfo.
		{name: "scp path userinfo token", in: "alice@example.com:" + tok + "@github.com/acme/api.git", secret: userinfoCanary},
		{name: "scp path userinfo bare", in: "alice@example.com:" + userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary},
		{name: "scp host is the user", in: "x-access-token:" + userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary},
		{name: "scp ipv6 path userinfo", in: "git@[2001:db8::1]:" + userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary},

		// local or scheme-less TOKEN@host/path.
		{name: "local token prefix", in: tok + "@github.com/acme/api.git", secret: userinfoCanary},
		{name: "local bare token", in: userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary},
		{name: "local percent-encoded underscore", in: "ghs%5F" + userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary},

		// https userinfo: redacted to the bare repository.
		{name: "https user:pass", in: "https://alice:" + userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary, want: "https://github.com/acme/api.git"},
		{name: "https x-access-token", in: "https://x-access-token:" + tok + "@github.com/acme/api.git", secret: userinfoCanary, want: "https://github.com/acme/api.git"},
		{name: "https oauth2", in: "https://oauth2:glpat-" + userinfoCanary + "@gitlab.com/acme/api.git", secret: userinfoCanary, want: "https://gitlab.com/acme/api.git"},
		{name: "https token only", in: "https://" + tok + "@github.com/acme/api.git", secret: userinfoCanary, want: "https://github.com/acme/api.git"},
		{name: "https percent-encoded user", in: "https://alice%40corp:" + userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary, want: "https://github.com/acme/api.git"},
		{name: "https percent-hidden delimiters", in: "https://alice%3A" + userinfoCanary + "%40github.com/acme/api.git", secret: userinfoCanary},

		// ssh:// with a password.
		{name: "ssh password", in: "ssh://git:" + userinfoCanary + "@github.com/acme/api.git", secret: userinfoCanary, want: "ssh://github.com/acme/api.git"},
		{name: "ssh ipv6 password", in: "ssh://git:" + userinfoCanary + "@[2001:db8::1]:2222/acme/api.git", secret: userinfoCanary, want: "ssh://[2001:db8::1]:2222/acme/api.git"},
		{name: "https ipv6 password", in: "https://alice:" + userinfoCanary + "@[2001:db8::1]/acme/api.git", secret: userinfoCanary, want: "https://[2001:db8::1]/acme/api.git"},

		// query and fragment.
		{name: "https token query", in: "https://github.com/acme/api.git?token=" + userinfoCanary, secret: userinfoCanary, want: "https://github.com/acme/api.git"},
		{name: "https token fragment", in: "https://github.com/acme/api.git#" + userinfoCanary, secret: userinfoCanary, want: "https://github.com/acme/api.git"},
		{name: "scp token query", in: "git@github.com:acme/api.git?token=" + userinfoCanary, secret: userinfoCanary},
		{name: "local token fragment", in: "/srv/git/api.git#" + userinfoCanary, secret: userinfoCanary},
	}...)
	for _, p := range sweepTokenPrefixes {
		t := p + userinfoCanary
		cases = append(cases,
			secretCase{name: p + " as scp login", in: t + "@github.com:acme/api.git", secret: userinfoCanary},
			secretCase{name: p + " in scp path", in: "git@github.com:acme/" + t + ".git", secret: userinfoCanary},
			secretCase{name: p + " in local path", in: "/srv/git/" + t + "/api.git", secret: userinfoCanary},
			secretCase{name: p + " in https path", in: "https://github.com/acme/" + t + ".git", secret: userinfoCanary},
			secretCase{name: p + " in ssh login", in: "ssh://" + t + "@github.com/acme/api.git", secret: userinfoCanary, want: "ssh://github.com/acme/api.git"},
			secretCase{name: p + " upper-cased", in: strings.ToUpper(t) + "@github.com:acme/api.git", secret: userinfoCanary},
			secretCase{name: p + " percent-encoded in scp path", in: "git@github.com:acme/" + strings.ReplaceAll(strings.ReplaceAll(t, "_", "%5F"), "-", "%2D") + ".git", secret: userinfoCanary},
			secretCase{name: p + " double-encoded in local path", in: "/srv/git/" + strings.ReplaceAll(strings.ReplaceAll(t, "_", "%255F"), "-", "%252D") + ".git", secret: userinfoCanary},
		)
	}
	return cases
}

// TestUserinfoSecretsNeverReachEvidence pins the contract on every spelling a
// credential takes in a remote: Record either redacts it (and the value it
// returns holds no part of the secret and no token prefix) or refuses the
// remote with a reason from the closed set. Never verbatim.
func TestUserinfoSecretsNeverReachEvidence(t *testing.T) {
	for _, tc := range userinfoSecretCases() {
		t.Run(tc.name, func(t *testing.T) {
			verdict, recorded, reason := Record(tc.in)
			if !verdict.Recordable() {
				if recorded != "" {
					t.Fatalf("refused remote still returned a value %q", recorded)
				}
				switch reason {
				case ReasonAmbiguousAuthority, ReasonOpaqueTransport, ReasonPathBytesNotRedactable:
				default:
					t.Fatalf("refusal reason %q is outside the closed set", reason)
				}
				if tc.want != "" {
					t.Fatalf("refused (%s), want redacted %q", reason, tc.want)
				}
				return
			}
			if verdict != Redacted {
				t.Fatalf("verdict %v recorded %q verbatim; a remote carrying a secret must be redacted or refused", verdict, recorded)
			}
			if strings.Contains(strings.ToUpper(recorded), strings.ToUpper(tc.secret)) {
				t.Fatalf("recorded %q still carries the secret", recorded)
			}
			if hasTokenPrefix(recorded) {
				t.Fatalf("recorded %q still carries a token prefix", recorded)
			}
			if tc.want != "" && recorded != tc.want {
				t.Fatalf("recorded %q, want %q", recorded, tc.want)
			}
		})
	}
}

// TestUserinfoSweepPositiveControls holds the over-refusal side: remotes that
// carry no credential must still be recorded byte for byte.
func TestUserinfoSweepPositiveControls(t *testing.T) {
	for _, in := range []string{
		"git@github.com:org/repo.git",
		"git@example.com:repo@release.git",
		"https://github.com/acme/api.git",
		"https://gitlab.com/acme/sub/api.git",
		"ssh://github.com/acme/api.git",
		"/srv/git/a@b.git",
		"/srv/git/repo%20one.git",
		"git@[2001:db8::1]:acme/api.git",
		"https://[2001:db8::1]/acme/api.git",
		"https://github.com/acme/highs_report.git",
		"git@github.com:acme/knights_tale.git",
		"acme/repo@v1.git",
	} {
		t.Run(in, func(t *testing.T) {
			verdict, recorded, reason := Record(in)
			if verdict != Clean || recorded != in {
				t.Fatalf("Record(%q) = %v %q (%s), want Clean verbatim", in, verdict, recorded, reason)
			}
		})
	}
}

func hasTokenPrefix(v string) bool {
	lower := strings.ToLower(v)
	for _, p := range sweepTokenPrefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
