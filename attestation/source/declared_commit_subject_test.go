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

package source

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A Pushgate VSA names its commit ONLY as a SHA-1 subject spelled
// https://pushgate.dev/v0.1/commithash:<sha>. The substitution guard refuses
// it by default; a search that carries the policy-declared commit subject for
// that external admits exactly that spelling and nothing near it.

const (
	vsaBindingPredicate = "https://pushgate.dev/verification_summary/v0.5"
	vsaBindingPrefix    = "https://pushgate.dev/v0.1/commithash:"
	vsaBindingCommit    = "ef2115760123456789abcdef0123456789abcdef"
	vsaBindingOther     = "0123456789abcdef0123456789abcdef01234567"
)

type vsaBindingSigner struct {
	signer   cryptoutil.Signer
	verifier cryptoutil.Verifier
}

func vsaBindingNewSigner(t *testing.T) vsaBindingSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return vsaBindingSigner{
		signer:   cryptoutil.NewECDSASigner(priv, crypto.SHA256),
		verifier: cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256),
	}
}

// vsaBindingSource loads one signed statement per ref into a MemorySource
// behind a real VerifiedSource.
func vsaBindingSource(t *testing.T, key vsaBindingSigner, stmts map[string]intoto.Statement) *VerifiedSource {
	t.Helper()
	mem := NewMemorySource()
	for ref, stmt := range stmts {
		payload, err := json.Marshal(stmt)
		require.NoError(t, err)
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
		require.NoError(t, err)
		require.NoError(t, mem.LoadEnvelope(ref, env))
	}
	return NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))
}

// vsaBindingAllSource returns every loaded envelope for any predicate search,
// ignoring predicate type and subjects: the shape of a remote store whose own
// filter is not trusted (Archivista), so only the VerifiedSource guard decides.
type vsaBindingAllSource struct{ envs []StatementEnvelope }

func (a *vsaBindingAllSource) Search(context.Context, string, []string, []string) ([]CollectionEnvelope, error) {
	return nil, nil
}

func (a *vsaBindingAllSource) SearchByPredicateType(context.Context, []string, []string) ([]StatementEnvelope, error) {
	out := make([]StatementEnvelope, len(a.envs))
	copy(out, a.envs)
	return out, nil
}

// vsaBindingUnfilteredSource signs each statement and serves it through
// vsaBindingAllSource behind a real VerifiedSource.
func vsaBindingUnfilteredSource(t *testing.T, key vsaBindingSigner, stmts map[string]intoto.Statement) *VerifiedSource {
	t.Helper()
	all := &vsaBindingAllSource{}
	for ref, stmt := range stmts {
		payload, err := json.Marshal(stmt)
		require.NoError(t, err)
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
		require.NoError(t, err)
		all.envs = append(all.envs, StatementEnvelope{Envelope: env, Statement: stmt, Reference: ref})
	}
	return NewVerifiedSource(all, dsse.VerifyWithVerifiers(key.verifier))
}

func vsaBindingStatement(predicateType string, subjects ...intoto.Subject) intoto.Statement {
	return intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: predicateType,
		Subject:       subjects,
		Predicate:     json.RawMessage(`{"verificationResult":"PASSED"}`),
	}
}

func vsaBindingSubject(name, value string) intoto.Subject {
	return intoto.Subject{Name: name, Digest: map[string]string{"sha1": value}}
}

func vsaBindingAccepted(envs []StatementEnvelope, ref string) bool {
	for _, e := range envs {
		if e.Reference == ref {
			return len(e.Errors) == 0 && len(e.Verifiers) > 0
		}
	}
	return false
}

func vsaBindingRefusal(t *testing.T, envs []StatementEnvelope, ref string) error {
	t.Helper()
	for _, e := range envs {
		if e.Reference == ref {
			require.NotEmpty(t, e.Errors, "%s must be refused", ref)
			return errors.Join(e.Errors...)
		}
	}
	t.Fatalf("%s was not returned by the search at all", ref)
	return nil
}

func TestVsaBindingOptInAdmitsDeclaredCommitSubject(t *testing.T) {
	key := vsaBindingNewSigner(t)
	vs := vsaBindingSource(t, key, map[string]intoto.Statement{
		"vsa": vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)),
	})
	ctx := context.Background()

	// Without the opt-in the existing signature stays strict.
	plain, err := vs.SearchByPredicateType(ctx, []string{vsaBindingPredicate}, []string{vsaBindingCommit})
	require.NoError(t, err)
	assert.False(t, vsaBindingAccepted(plain, "vsa"), "the default guard must keep refusing a SHA-1 subject")

	opted, err := vs.SearchByPredicateTypeWithOptions(ctx, []string{vsaBindingPredicate}, []string{vsaBindingCommit},
		PredicateSearchOptions{CommitSubjects: map[string][]string{vsaBindingPredicate: {vsaBindingPrefix}}})
	require.NoError(t, err)
	assert.True(t, vsaBindingAccepted(opted, "vsa"), "the declared commit subject must admit the VSA")

	// Through a source that returns it regardless (Archivista's shape), the
	// verified guard is what refuses it without the opt-in and admits it with.
	unfiltered := vsaBindingUnfilteredSource(t, key, map[string]intoto.Statement{
		"vsa": vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)),
	})
	plain, err = unfiltered.SearchByPredicateType(ctx, []string{vsaBindingPredicate}, []string{vsaBindingCommit})
	require.NoError(t, err)
	assert.ErrorIs(t, vsaBindingRefusal(t, plain, "vsa"), ErrExternalSubjectNotRequested)
	opted, err = unfiltered.SearchByPredicateTypeWithOptions(ctx, []string{vsaBindingPredicate}, []string{vsaBindingCommit},
		PredicateSearchOptions{CommitSubjects: map[string][]string{vsaBindingPredicate: {vsaBindingPrefix}}})
	require.NoError(t, err)
	assert.True(t, vsaBindingAccepted(opted, "vsa"))
}

// Enumerates the value space around the declared subject. Every row but the
// first must be refused even WITH the opt-in.
func TestVsaBindingOptInRefusesEverythingElse(t *testing.T) {
	upper := strings.ToUpper(vsaBindingCommit)
	collectionPredicate, err := json.Marshal(attestation.Collection{Name: "c"})
	require.NoError(t, err)
	collection := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: attestation.CollectionType,
		Subject:       []intoto.Subject{vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)},
		Predicate:     collectionPredicate,
	}
	cases := []struct {
		name   string
		stmt   intoto.Statement
		digest string
		accept bool
	}{
		{"exact", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)), vsaBindingCommit, true},
		{"name hex upper-cased", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+upper, vsaBindingCommit)), vsaBindingCommit, true},
		{"different prefix", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject("https://evil.example/v0.1/commithash:"+vsaBindingCommit, vsaBindingCommit)), vsaBindingCommit, false},
		{"case-variant prefix", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject("https://Pushgate.dev/v0.1/commithash:"+vsaBindingCommit, vsaBindingCommit)), vsaBindingCommit, false},
		{"prefix plus whitespace", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+" "+vsaBindingCommit, vsaBindingCommit)), vsaBindingCommit, false},
		{"bare git form", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject("commithash:"+vsaBindingCommit, vsaBindingCommit)), vsaBindingCommit, false},
		{"null oid", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+strings.Repeat("0", 40), strings.Repeat("0", 40))), strings.Repeat("0", 40), false},
		{"short digest", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit[:39], vsaBindingCommit[:39])), vsaBindingCommit[:39], false},
		{"non-hex digest", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+"zz"+vsaBindingCommit[2:], "zz"+vsaBindingCommit[2:])), "zz" + vsaBindingCommit[2:], false},
		{"name names another commit", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingOther, vsaBindingCommit)), vsaBindingCommit, false},
		{"right digest under another name", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject("pkg:github/testifysec/judge", vsaBindingCommit)), vsaBindingCommit, false},
		{"another commit requested", vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)), vsaBindingOther, false},
		{"other predicate type signed", vsaBindingStatement("https://example.com/other/v1", vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)), vsaBindingCommit, false},
		{"collection-typed envelope", collection, vsaBindingCommit, false},
	}
	for _, tc := range cases {
		for _, via := range []string{"memory", "unfiltered"} {
			t.Run(tc.name+"/"+via, func(t *testing.T) {
				key := vsaBindingNewSigner(t)
				stmts := map[string]intoto.Statement{"cand": tc.stmt}
				vs := vsaBindingSource(t, key, stmts)
				if via == "unfiltered" {
					// The source returns the candidate whatever it is, so the
					// verified guard alone must refuse it.
					vs = vsaBindingUnfilteredSource(t, key, stmts)
				}
				pts := []string{vsaBindingPredicate, tc.stmt.PredicateType}
				envs, err := vs.SearchByPredicateTypeWithOptions(context.Background(), pts, []string{tc.digest},
					PredicateSearchOptions{CommitSubjects: map[string][]string{vsaBindingPredicate: {vsaBindingPrefix}}})
				require.NoError(t, err)
				if tc.accept {
					assert.True(t, vsaBindingAccepted(envs, "cand"))
					return
				}
				assert.False(t, vsaBindingAccepted(envs, "cand"), "must be refused")
				if via == "unfiltered" {
					assert.ErrorIs(t, vsaBindingRefusal(t, envs, "cand"), ErrExternalSubjectNotRequested, "refused by the substitution guard")
				}
			})
		}
	}
}

// An invalid declared prefix admits nothing: the matcher refuses it even if a
// caller skipped policy validation.
func TestVsaBindingInvalidDeclaredPrefixAdmitsNothing(t *testing.T) {
	key := vsaBindingNewSigner(t)
	vs := vsaBindingSource(t, key, map[string]intoto.Statement{
		"vsa": vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject("commithash:"+vsaBindingCommit, vsaBindingCommit)),
	})
	envs, err := vs.SearchByPredicateTypeWithOptions(context.Background(), []string{vsaBindingPredicate}, []string{vsaBindingCommit},
		PredicateSearchOptions{CommitSubjects: map[string][]string{vsaBindingPredicate: {"commithash:"}}})
	require.NoError(t, err)
	assert.False(t, vsaBindingAccepted(envs, "vsa"))
}

// MatchExternalSubjects is the per-external re-check the policy engine runs:
// one search may carry several externals' prefixes, but each external is held
// to its own.
func TestVsaBindingMatchExternalSubjectsIsPerExternal(t *testing.T) {
	stmt := vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit))
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)

	require.NoError(t, MatchExternalSubjects(payload, []string{vsaBindingCommit}, vsaBindingPredicate, vsaBindingPrefix))

	err = MatchExternalSubjects(payload, []string{vsaBindingCommit}, vsaBindingPredicate, "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrExternalSubjectNotRequested))

	err = MatchExternalSubjects(payload, []string{vsaBindingCommit}, "https://example.com/other/v1", vsaBindingPrefix)
	require.Error(t, err, "the declared subject applies only to the external's own signed predicate type")
}

// The refusal names the subject, says it is SHA-1, and names the policy field
// that would admit it, with the exact prefix to declare.
func TestVsaBindingRefusalExplainsSha1AndCommitSubject(t *testing.T) {
	key := vsaBindingNewSigner(t)
	vs := vsaBindingUnfilteredSource(t, key, map[string]intoto.Statement{
		"vsa": vsaBindingStatement(vsaBindingPredicate, vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)),
	})
	envs, err := vs.SearchByPredicateType(context.Background(), []string{vsaBindingPredicate}, []string{vsaBindingCommit})
	require.NoError(t, err)
	reason := vsaBindingRefusal(t, envs, "vsa")
	assert.True(t, errors.Is(reason, ErrExternalSubjectNotRequested), "the sentinel must survive: %v", reason)
	msg := reason.Error()
	assert.Contains(t, msg, vsaBindingPrefix+vsaBindingCommit)
	assert.Contains(t, msg, "SHA-1")
	assert.Contains(t, msg, "commitSubject")
	assert.Contains(t, msg, `"`+vsaBindingPrefix+`"`, "names the exact prefix to declare")
}

// A plain mismatch names the signed subjects and the requested digests.
func TestVsaBindingRefusalNamesSubjectsOnPlainMismatch(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	// MemorySource would filter it out, so drive the guard directly.
	payload, err := json.Marshal(vsaBindingStatement(vsaBindingPredicate, intoto.Subject{Name: "pkg:a", Digest: map[string]string{"sha256": sha}}))
	require.NoError(t, err)
	err = MatchExternalSubjects(payload, []string{other}, vsaBindingPredicate, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pkg:a (sha256)")
	assert.Contains(t, err.Error(), "sha256:"+other)
}

// Declaring the collection type itself as the key does not hand a collection
// the arm: attestation collections keep only the hardened-git SHA-1 arm.
func TestVsaBindingCollectionKeyGainsNothing(t *testing.T) {
	predicate, err := json.Marshal(attestation.Collection{Name: "c"})
	require.NoError(t, err)
	stmt := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: attestation.CollectionType,
		Subject:       []intoto.Subject{vsaBindingSubject(vsaBindingPrefix+vsaBindingCommit, vsaBindingCommit)},
		Predicate:     predicate,
	}
	key := vsaBindingNewSigner(t)
	vs := vsaBindingUnfilteredSource(t, key, map[string]intoto.Statement{"coll": stmt})
	envs, err := vs.SearchByPredicateTypeWithOptions(context.Background(), []string{attestation.CollectionType}, []string{vsaBindingCommit},
		PredicateSearchOptions{CommitSubjects: map[string][]string{attestation.CollectionType: {vsaBindingPrefix}}})
	require.NoError(t, err)
	assert.False(t, vsaBindingAccepted(envs, "coll"))

	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	assert.Error(t, MatchExternalSubjects(payload, []string{vsaBindingCommit}, attestation.CollectionType, vsaBindingPrefix))
}
