// Copyright 2025 The Aflock Authors
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

package cryptoutil

import "testing"

// TestIsHardenedGitAttestationType pins the TYPE half of what counts as
// hardened git evidence — the fact SubjectMatchScope.HardenedGitAttested is
// derived from (together with the in-payload marker) at two call sites, from
// two different representations of the same bytes.
//
// The predicate is deliberately an EXACT string, not namespace + version. The
// SHA-1 commit exception is justified by a producer-side invariant (the
// attested id came through computeVerifiedCommitHash), so it is granted per
// hardened format, never per namespace: evidence under any other type —
// legacy witness.dev, an unknown future version — never promised the
// invariant, and must not inherit the exception the day someone signs under
// it. The accepted cost: a version bump FAILS CLOSED (sha1 anchoring stops,
// loudly) until the new format is consciously added here with the marker
// contract intact. Unknown means no exception.
func TestIsHardenedGitAttestationType(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
		why  string
	}{
		{"https://aflock.ai/attestations/git/v0.1", true,
			"the current hardened producer's type, plugins/attestors/git/git.go Type — note type alone still grants nothing: pre-hardening evidence shares this string, and the scope additionally requires the commithashverified marker from the signed body"},
		{"https://witness.dev/attestations/git/v0.1", false,
			"the legacy witness.dev form. Evidence signed under it predates the verified-commit-hash hardening, so granting it the exception would apply the exception retroactively to evidence lacking the invariant it depends on. It stays decodable via attestation.legacyAliases — it just cannot anchor a SHA-1 match, exactly its status before the exception existed"},
		{"https://aflock.ai/attestations/git/v0.2", false,
			"an unknown FUTURE version: its producer has made no promise yet, so it must not inherit the exception by namespace. When the attestor's version bumps, carrying the exception forward is a conscious edit to hardenedGitAttestationType — until then sha1 anchoring fails CLOSED for the new version, which is loud, instead of granting a collision-prone arm to an unvetted format, which is silent"},
		{"https://aflock.ai/attestations/git/v0.1/commithash:3d7b4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70", false,
			"that string is a SUBJECT NAME, not an attestation type. Accepting it here would let a producer smuggle the git claim back in through the one field the scope exists to stop trusting"},
		{"https://aflock.ai/attestations/git/", false,
			"a bare namespace names no version and no attestor"},
		{"https://aflock.ai/attestations/GIT/v0.1", false,
			"predicate-type URIs are case-sensitive identifiers: this is a DIFFERENT type nothing here vouches for, and folding it into the trusted form would reopen the case-variant substitution the subject-name check also closes"},
		{"https://aflock.ai/attestations/github/v0.1", false,
			"a different attestor: it observes the CI environment, not the repository object model, so it vouches for no commit id"},
		{"https://aflock.ai/attestations/gitlab/v0.1", false,
			"same reasoning — a near-miss name must not inherit the exception"},
		{"https://evil.example.com/attestations/git/v0.1", false,
			"the namespace is part of the identity"},
		{"", false, "the empty type is not git"},
	}

	for _, c := range cases {
		t.Run(c.uri, func(t *testing.T) {
			if got := IsHardenedGitAttestationType(c.uri); got != c.want {
				t.Errorf("IsHardenedGitAttestationType(%q) = %v, want %v\nwhy this matters: %s",
					c.uri, got, c.want, c.why)
			}
		})
	}
}

// TestHasGitCommitVerifiedMarker pins the MARKER half: the capability claim
// must come out of the attestation body's own JSON, and every malformed or
// absent shape fails CLOSED. The marker discriminates hardened from legacy
// evidence under the SAME type string, so "no marker" must always read as
// "legacy — no exception", never as an error that widens anything.
func TestHasGitCommitVerifiedMarker(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
		why  string
	}{
		{"hardened body", `{"commithash":"3d7b4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70","commithashverified":true}`, true,
			"the shape the hardened producer signs: marker and hash in one unit"},
		{"legacy body", `{"commithash":"3d7b4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70"}`, false,
			"pre-hardening evidence: same type, no marker — the case the whole fix exists for"},
		{"marker explicitly false", `{"commithashverified":false}`, false,
			"an explicit false is not a claim"},
		{"marker of the wrong JSON type", `{"commithashverified":"true"}`, false,
			"a string is not the boolean capability; a lenient coercion here would let near-miss producers back in"},
		{"non-object body", `["commithashverified"]`, false,
			"RawAttestation bodies are arbitrary JSON; any non-object shape carries no marker and must not error the surrounding decode"},
		{"null body", `null`, false, "an absent attestation carries no capability"},
		{"empty body", ``, false, "no bytes, no claim"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HasGitCommitVerifiedMarker([]byte(c.body)); got != c.want {
				t.Errorf("HasGitCommitVerifiedMarker(%q) = %v, want %v\nwhy this matters: %s",
					c.body, got, c.want, c.why)
			}
		})
	}
}
