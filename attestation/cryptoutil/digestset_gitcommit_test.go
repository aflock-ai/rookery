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

// The git-commit exception to the SHA-1 subject-match ban, and the boundaries
// that keep it an exception rather than a hole.
//
// SHA-1 is refused as a subject-match algorithm because it has practical
// chosen-prefix collisions: if an attacker can produce a second artifact with
// the same digest, a collection legitimately signed over one can be replayed
// against the other. That reasoning is untouched for every digest an ATTESTOR
// chooses. It does not fit a git commit id, which the repository's own object
// model produced and which, on a SHA-1 repository, has no sha256 restatement
// anywhere in already-signed evidence.
//
// The exception is therefore scoped TWICE — by NAME BOUND TO VALUE, and to a
// statement that actually attests git (SubjectMatchScope) — and these tests
// exist to keep it that way. Every case below that expects false is a way the
// scoping could rot into "any SHA-1 an attacker labels nicely".

const (
	// A well-formed 40-hex commit id.
	gcCommit = "3d7b4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70"
	// A DIFFERENT well-formed commit id, for the relabelling case.
	gcOther = "aaaa0000beef1111cafe2222f00d3333feed4444"
)

func TestIsMatchableSubjectDigest_GitCommit(t *testing.T) {
	cases := []struct {
		name string
		// gitAttested is the caller's finding that the STATEMENT carrying
		// this subject holds a HARDENED git attestation — the exact current
		// type with the verified-commit-hash marker in its signed body (the
		// derivation sites in attestation/source establish both halves).
		// Every git-commit row states it explicitly, because the value of
		// the field IS the control.
		gitAttested bool
		subj        string
		algo        string
		value       string
		want        bool
		why         string
	}{
		{
			name: "bare commithash", gitAttested: true, subj: "commithash:" + gcCommit,
			algo: "sha1", value: gcCommit, want: true,
			why: "the form the git attestor writes directly",
		},
		{
			name:        "namespaced commithash",
			gitAttested: true,
			subj:        "https://aflock.ai/attestations/git/v0.1/commithash:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: true,
			why: "the form real collections carry once Collection.Subjects() prefixes the attestation type — if only the bare form matched, the exception would be useless on actual evidence",
		},
		{
			name:        "commithash subject on a statement that does not attest git",
			gitAttested: false,
			subj:        "commithash:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: false,
			why: "THE case this scope exists for. Subject names are producer-controlled, so binding the exception to the name alone made it self-service: anything able to sign a statement — an sbom step, a scan step, a hand-rolled producer that never touched a repository — could mint 'commithash:<sha1>' over a SHA-1 of its choosing and re-open collision-prone matching. The statement now has to CLAIM git evidence, which is a claim the policy's per-step attestor requirements already constrain",
		},
		{
			name:        "namespaced commithash on a statement that does not attest git",
			gitAttested: false,
			subj:        "https://aflock.ai/attestations/git/v0.1/commithash:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: false,
			why: "spelling the git attestor's type URI into the SUBJECT NAME is not attesting git — the name is producer-controlled text, and admitting it here would make the type prefix the very free label the scope removes",
		},
		{
			name:        "non-git-namespaced commithash in a git-attested (mixed) collection",
			gitAttested: true,
			subj:        "https://aflock.ai/attestations/sbom/v0.1/commithash:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: false,
			why: "THE mixed-collection substitution. Any git entry makes the scope git-attested, but Collection.Subjects() prefixes each subject with the type that PRODUCED it, so this name is the sbom attestor's — its namespace is not a git attestation type, so it must not back into the SHA-1 commit arm. Accepting it would let a non-git attestor's collision-prone SHA-1 subject ride the git exception (evidence substitution)",
		},
		{
			name:        "case-variant namespace GIT/v0.1 in a git-attested (mixed) collection",
			gitAttested: true,
			subj:        "https://aflock.ai/attestations/GIT/v0.1/commithash:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: false,
			why: "predicate-type URIs are case-sensitive identifiers: '.../attestations/GIT/v0.1' is a DIFFERENT type from the git attestor's '.../attestations/git/v0.1', one nothing here vouches for. Folding the whole subject name before the namespace check canonicalized it INTO the trusted git namespace, so in a mixed collection (any genuine hardened git entry sets HardenedGitAttested) a non-git attestor publishing under the case-variant type could hand its collision-prone SHA-1 subject the git exception. The namespace must be compared exactly as attested",
		},
		{
			name:        "case-variant relation COMMITHASH: is not the attestor's name",
			gitAttested: true,
			subj:        "COMMITHASH:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: false,
			why: "same class as the namespace fold: the relation label is an identifier the git attestor writes exactly as 'commithash:' — folding it admits names the attestor never writes. Only the hex digest characters carry no case meaning",
		},
		{
			name:        "leading whitespace is not the attestor's name",
			gitAttested: true,
			subj:        " commithash:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: false,
			why: "same class again, folding by trimming: the attestor writes the exact name, so a whitespace-padded variant is a different producer-controlled string and must fail closed rather than be normalized into the trusted form",
		},
		{
			name:        "uppercase digest characters in the subject name still match",
			gitAttested: true,
			subj:        "commithash:3D7B4FDB1C9E2A5F8B0C7D4E6A1F3B8C9D2E5A70",
			algo:        "sha1", value: gcCommit, want: true,
			why: "the counterpart to the case-exact namespace rows: hex case is NOT identity, so removing the whole-name fold must not start rejecting a digest spelled uppercase in the name — only the digest component is folded",
		},
		{
			name:        "namespaced form with uppercase digest characters still matches",
			gitAttested: true,
			subj:        "https://aflock.ai/attestations/git/v0.1/commithash:3D7B4FDB1C9E2A5F8B0C7D4E6A1F3B8C9D2E5A70",
			algo:        "sha1", value: gcCommit, want: true,
			why: "digest-case insensitivity must survive in the namespaced form too: the genuine lowercase git type with an uppercase-spelled digest names the same commit",
		},
		{
			name:        "non-git-namespaced commithash, scope not git either",
			gitAttested: false,
			subj:        "https://aflock.ai/attestations/sbom/v0.1/commithash:" + gcCommit,
			algo:        "sha1", value: gcCommit, want: false,
			why: "belt and braces: neither the scope nor the subject namespace is git",
		},
		{
			// NOTE the limit of this case. It pins THIS PREDICATE's
			// case-insensitivity and nothing more: a subject whose value is
			// uppercase is judged matchable here, but MemorySource indexes the
			// raw value while callers seed lowercase, so it would still not
			// produce a search hit end to end. That is fail-CLOSED, so it is a
			// gap rather than a bypass — but do not read this row as "uppercase
			// evidence works".
			name: "uppercase value is matchable at this layer", gitAttested: true,
			subj: "commithash:" + gcCommit,
			algo: "sha1", value: "3D7B4FDB1C9E2A5F8B0C7D4E6A1F3B8C9D2E5A70", want: true,
			why: "hex case is not identity, so the predicate must not reject on it; end-to-end matching of uppercase values is a separate, unsolved gap in the index",
		},
		{
			name: "parenthash is NOT a commit claim", gitAttested: true,
			subj: "parenthash:" + gcCommit,
			algo: "sha1", value: gcCommit, want: false,
			why: "a parenthash names a DIFFERENT commit, for graph chaining. Admitting it lets evidence gathered at commit Y satisfy a query for its parent X — so a scan that never examined X would clear X",
		},
		{
			name: "namespaced parenthash is NOT a commit claim", gitAttested: true,
			subj: "https://aflock.ai/attestations/git/v0.1/parenthash:" + gcCommit,
			algo: "sha1", value: gcCommit, want: false,
			why: "the namespaced form must not sneak past what the bare form is denied",
		},
		{
			name: "relabelled: name says one commit, digest carries another", gitAttested: true,
			subj: "commithash:" + gcOther,
			algo: "sha1", value: gcCommit, want: false,
			why: "THE load-bearing case. If the name were merely required to start with commithash:, an attacker could label any SHA-1 as a commit and make it matchable. Binding name to value is what stops that",
		},
		{
			name: "suffix without a segment boundary", gitAttested: true,
			subj: "notacommithash:" + gcCommit,
			algo: "sha1", value: gcCommit, want: false,
			why: "a bare HasSuffix test would admit this; the boundary is required",
		},
		{
			name: "generic artifact subject", gitAttested: true,
			subj: "artifact",
			algo: "sha1", value: gcCommit, want: false,
			why: "the original control: an ordinary SHA-1 artifact digest stays unmatchable",
		},
		{
			name: "null object id", gitAttested: true,
			subj: "commithash:0000000000000000000000000000000000000000",
			algo: "sha1", value: "0000000000000000000000000000000000000000", want: false,
			why: "git writes the all-zero id for the absent side of a create or delete. It is valid hex and names no commit, so it must not anchor anything — every branch creation in a repository would otherwise share it",
		},
		{
			name: "gitoid:sha1 keeps no exception", gitAttested: true,
			subj: "commithash:" + gcCommit,
			algo: "gitoid:sha1", value: gcCommit, want: false,
			why: "a gitoid addresses blob/tree CONTENT, not a commit; the exception is about the commit id specifically",
		},
		{
			name: "wrong length is not a commit id", gitAttested: true,
			subj: "commithash:abc123", algo: "sha1", value: "abc123", want: false,
			why: "malformed values must not be indexed, same as the sha256 length rule",
		},
		{
			name: "non-hex value", gitAttested: true,
			subj: "commithash:zzzz4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70",
			algo: "sha1", value: "zzzz4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70", want: false,
			why: "40 characters is not enough; they must be hex",
		},
		{
			name: "sha256 subject is unaffected", gitAttested: false,
			subj: "artifact", algo: "sha256",
			value: "9f2c1e7a4b6d803f5c9e1a7b3d5f8092c4e6a1b3d5f7092c4e6a8b1d3f5709ac",
			want:  true,
			why:   "the ordinary path must not regress, and must not start DEPENDING on the scope — a collision-resistant algorithm is matchable whether or not anything attested git",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope := SubjectMatchScope{HardenedGitAttested: c.gitAttested}
			got := scope.IsMatchableSubjectDigest(c.subj, c.algo, c.value)
			if got != c.want {
				t.Errorf("SubjectMatchScope{HardenedGitAttested:%v}.IsMatchableSubjectDigest(%q, %q, %q) = %v, want %v\nwhy this matters: %s",
					c.gitAttested, c.subj, c.algo, c.value, got, c.want, c.why)
			}
		})
	}
}

// TestIsMatchableSubjectDigest_ScopelessCallerForfeitsTheException pins the
// documented caller contract for the package-level function: a caller that
// establishes nothing about the statement gets the STRICT scope. It is the
// safe default in the direction that matters — a call site that forgets to
// pass the scope stops finding git evidence, which is loud, rather than
// admitting a minted SHA-1, which is silent.
func TestIsMatchableSubjectDigest_ScopelessCallerForfeitsTheException(t *testing.T) {
	if IsMatchableSubjectDigest("commithash:"+gcCommit, "sha1", gcCommit) {
		t.Fatal("the scope-less entry point granted the git-commit exception — " +
			"a caller that has not established the statement attests git must fail closed")
	}
	// ...and the ordinary algorithms still work with no scope at all.
	if !IsMatchableSubjectDigest("artifact", "sha256",
		"9f2c1e7a4b6d803f5c9e1a7b3d5f8092c4e6a1b3d5f7092c4e6a8b1d3f5709ac") {
		t.Fatal("the scope-less entry point broke ordinary sha256 matching")
	}
}

// TestIsMatchableSubjectDigest_EmptyNameForfeitsTheException pins the
// documented caller contract: a caller that has no subject name to hand over
// loses only the name-scoped arm and never gains it by accident. Note the
// scope is SET here — establishing that the statement attests git does not on
// its own make an unnamed SHA-1 matchable. Both halves are required.
func TestIsMatchableSubjectDigest_EmptyNameForfeitsTheException(t *testing.T) {
	gitScope := SubjectMatchScope{HardenedGitAttested: true}
	if gitScope.IsMatchableSubjectDigest("", "sha1", gcCommit) {
		t.Fatal("an empty subject name must not satisfy the git-commit exception — " +
			"a caller that cannot supply the name must fail closed, not open")
	}
	// ...while the ordinary algorithms still work without a name.
	if !IsMatchableSubjectDigest("", "sha256",
		"9f2c1e7a4b6d803f5c9e1a7b3d5f8092c4e6a1b3d5f7092c4e6a8b1d3f5709ac") {
		t.Fatal("an empty subject name must not break ordinary sha256 matching")
	}
}
