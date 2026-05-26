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

package policy

import (
	"context"
	"strings"
	"testing"
)

// TestAdversarial_HTTPSource_URLInjection_StepName_PathTraversal
// guards F1: a hostile policy-author-controlled step name like
// "../admin" must NOT be substituted into the URL template raw.
// Without the fix, the template
// "https://archive.example/sidecar/{downstreamStep}.json" would
// resolve to "https://archive.example/sidecar/../admin.json" —
// a redirect to a path the operator never intended.
func TestAdversarial_HTTPSource_URLInjection_StepName_PathTraversal(t *testing.T) {
	const validDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	src := NewHTTPChainSidecarSource("https://archive.example/sidecar/{downstreamStep}.json")

	cases := []string{
		"../admin",
		"../../etc/passwd",
		"build/../secrets",
		"a/b/c",
		"\\windows\\admin",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := src.LookupChainSidecar(context.Background(), name, "upstream", validDigest)
			if err == nil {
				t.Fatalf("LookupChainSidecar must reject hostile step name %q", name)
			}
			if !strings.Contains(err.Error(), "step name") {
				t.Errorf("error %q should mention 'step name' to point at the offending input", err)
			}
		})
	}
}

// TestAdversarial_HTTPSource_URLInjection_StepName_QueryString
// covers URL-syntactic characters that don't produce path traversal
// but still escape the intended URL structure (?, #, &, etc.).
func TestAdversarial_HTTPSource_URLInjection_StepName_QueryString(t *testing.T) {
	const validDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	src := NewHTTPChainSidecarSource("https://archive.example/sidecar/{downstreamStep}.json")

	cases := []string{
		"build?evil=1",
		"build#fragment",
		"build&other=x",
		"build%20space",
		"build name with space",
		"build\nnewline",
		"build\ttab",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := src.LookupChainSidecar(context.Background(), name, "upstream", validDigest)
			if err == nil {
				t.Fatalf("LookupChainSidecar must reject step name with URL-syntactic chars: %q", name)
			}
		})
	}
}

// TestAdversarial_HTTPSource_URLInjection_Digest is the symmetric
// case for the digest argument. The digest is derived from a signed
// payload's hash so legitimate values never contain URL-syntactic
// characters — but the substitution must still defend against a
// caller passing one.
func TestAdversarial_HTTPSource_URLInjection_Digest(t *testing.T) {
	src := NewHTTPChainSidecarSource("https://archive.example/sidecar/{envelopeDigest}.json")
	cases := []string{
		"../etc/passwd",
		"abc?evil=1",
		"abc#fragment",
		"abc/extra",
		"",
	}
	for _, digest := range cases {
		t.Run(digest, func(t *testing.T) {
			_, err := src.LookupChainSidecar(context.Background(), "build", "upstream", digest)
			if err == nil {
				t.Fatalf("LookupChainSidecar must reject digest %q", digest)
			}
		})
	}
}

// TestAdversarial_OverbroadAllowedUntracked guards F7: the most
// dangerous case is a single-line policy footnote that disables
// chain-of-custody enforcement for an entire step. compileAllowedUntracked
// must reject patterns that match every conceivable path at compile
// time with a clear "use specific directory globs" error.
func TestAdversarial_OverbroadAllowedUntracked(t *testing.T) {
	cases := []string{
		"**",
		"**/*",
		"/**",
		"/**/*",
		"*",
		"*/**",
	}
	for _, pattern := range cases {
		t.Run(pattern, func(t *testing.T) {
			_, err := compileAllowedUntracked([]string{pattern})
			if err == nil {
				t.Fatalf("compileAllowedUntracked must reject overbroad pattern %q", pattern)
			}
			if !strings.Contains(err.Error(), "matches every path") {
				t.Errorf("error %q should explain the security implication", err)
			}
		})
	}
}

// TestAdversarial_AllowedUntracked_SpecificStillAllowed confirms F7
// did not over-correct. Legitimate narrow patterns must still
// compile and match as expected — '/usr/lib/**' is the canonical
// example a hermetic build needs to allow without listing every
// system file.
func TestAdversarial_AllowedUntracked_SpecificStillAllowed(t *testing.T) {
	cases := []string{
		"/usr/lib/**",
		"/usr/include/**",
		"/etc/ssl/**",
		"build/intermediate/**",
		"vendor/**",
	}
	for _, pattern := range cases {
		t.Run(pattern, func(t *testing.T) {
			matchers, err := compileAllowedUntracked([]string{pattern})
			if err != nil {
				t.Fatalf("compileAllowedUntracked rejected legitimate narrow pattern %q: %v", pattern, err)
			}
			if len(matchers) != 1 {
				t.Errorf("expected 1 matcher for %q, got %d", pattern, len(matchers))
			}
		})
	}
}
