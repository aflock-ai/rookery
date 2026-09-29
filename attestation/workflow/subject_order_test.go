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

// jade:ring local

package workflow

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

func collectionStatement(t *testing.T, results []RunResult) intoto.Statement {
	t.Helper()
	require.NotEmpty(t, results)
	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(results[len(results)-1].SignedEnvelope.Payload, &stmt))
	return stmt
}

func statementSubjectNames(stmt intoto.Statement) []string {
	out := make([]string, 0, len(stmt.Subject))
	for _, s := range stmt.Subject {
		out = append(out, s.Name)
	}
	return out
}

// attestorSubject is the name dummySubjectAttestor's subject takes in the
// collection statement, which prefixes each attestor subject with its type.
const attestorSubject = dummySubjectAttestorType + "/" + matchSubjectName

func sha256Set(hexByte string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{{Hash: crypto.SHA256}: strings.Repeat(hexByte, 32)}
}

// User-supplied subjects lead the collection statement in the order the
// operator gave them; attestor subjects follow, sorted. "zz-*" names sort
// after the attestor's "test/subjectattestor/...", so this fails under
// sort-only output.
func TestRun_UserSubjectsLeadCollectionStatementInFlagOrder(t *testing.T) {
	names, subjects, err := ParseSubjectFlagsOrdered([]string{
		"zz-second.tar=sha256:" + strings.Repeat("bb", 32),
		"zz-first.tar=sha256:" + strings.Repeat("aa", 32),
	})
	require.NoError(t, err)
	require.Equal(t, []string{"zz-second.tar", "zz-first.tar"}, names)

	results, err := RunWithExports("order-step",
		RunWithSigners(newTestSigner(t)),
		RunWithAttestors([]attestation.Attestor{&dummySubjectAttestor{}}),
		RunWithAdditionalSubjects(subjects),
		RunWithSubjectOrder(names),
	)
	require.NoError(t, err)
	require.Equal(t, []string{"zz-second.tar", "zz-first.tar", attestorSubject},
		statementSubjectNames(collectionStatement(t, results)))
}

// Without an explicit order (RunWithAdditionalSubjects alone, as
// cilock-action's older call sites do) user subjects still lead, sorted.
func TestRun_UserSubjectsLeadSortedWithoutExplicitOrder(t *testing.T) {
	results, err := RunWithExports("order-step",
		RunWithSigners(newTestSigner(t)),
		RunWithAttestors([]attestation.Attestor{&dummySubjectAttestor{}}),
		RunWithAdditionalSubjects(map[string]cryptoutil.DigestSet{
			"zz-b.tar": sha256Set("bb"),
			"zz-a.tar": sha256Set("aa"),
		}),
	)
	require.NoError(t, err)
	require.Equal(t, []string{"zz-a.tar", "zz-b.tar", attestorSubject},
		statementSubjectNames(collectionStatement(t, results)))
}

// A user subject whose name collides with an attestor subject is emitted once,
// in the leading position, with the user's digest (the documented --subjects
// precedence).
func TestRun_CollidingUserSubjectLeadsWithUserDigest(t *testing.T) {
	results, err := RunWithExports("order-step",
		RunWithSigners(newTestSigner(t)),
		RunWithAttestors([]attestation.Attestor{&dummySubjectAttestor{}}),
		RunWithAdditionalSubjects(map[string]cryptoutil.DigestSet{
			"zz-artifact.tar": sha256Set("cc"),
			attestorSubject:   sha256Set("dd"),
		}),
		RunWithSubjectOrder([]string{"zz-artifact.tar", attestorSubject}),
	)
	require.NoError(t, err)
	stmt := collectionStatement(t, results)
	require.Equal(t, []string{"zz-artifact.tar", attestorSubject}, statementSubjectNames(stmt))
	require.Equal(t, strings.Repeat("dd", 32), stmt.Subject[1].Digest["sha256"])
}

// Two runs over the same inputs produce the same statement payload.
func TestRun_UserSubjectOrderIsDeterministic(t *testing.T) {
	var first []string
	for i := 0; i < 20; i++ {
		results, err := RunWithExports("order-step",
			RunWithSigners(newTestSigner(t)),
			RunWithAttestors([]attestation.Attestor{&dummySubjectAttestor{}}),
			RunWithAdditionalSubjects(map[string]cryptoutil.DigestSet{
				"zz-3": sha256Set("03"), "zz-1": sha256Set("01"), "zz-2": sha256Set("02"),
			}),
			RunWithSubjectOrder([]string{"zz-2", "zz-3", "zz-1"}),
		)
		require.NoError(t, err)
		got := statementSubjectNames(collectionStatement(t, results))
		if i == 0 {
			first = got
			continue
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d order %v, first run %v", i, got, first)
		}
	}
	require.Equal(t, []string{"zz-2", "zz-3", "zz-1", attestorSubject}, first)
}

// Policy verification matches subjects by digest, not position: collections
// whose statements lead with a user subject still verify when seeded with
// that subject's digest.
func TestRun_PolicyVerifiesCollectionsLedByUserSubject(t *testing.T) {
	registerDummyAttestors()
	testPolicy, functionarySigner := makePolicyWithPublicKeyFunctionary(t)
	functionaryVerifier, err := functionarySigner.Verifier()
	require.NoError(t, err)

	user := map[string]cryptoutil.DigestSet{"zz-artifact.tar": {{Hash: crypto.SHA256}: seedDigestHex}}
	run := func(step string) RunResult {
		r, err := Run(step,
			RunWithSigners(functionarySigner),
			RunWithAttestors([]attestation.Attestor{
				&dummySubjectAttestor{Data: "test"},
				&dummyCommandRunAttestor{Cmd: []string{"true"}},
			}),
			RunWithAdditionalSubjects(user),
			RunWithSubjectOrder([]string{"zz-artifact.tar"}),
		)
		require.NoError(t, err)
		var stmt intoto.Statement
		require.NoError(t, json.Unmarshal(r.SignedEnvelope.Payload, &stmt))
		require.Equal(t, "zz-artifact.tar", stmt.Subject[0].Name, "fixture must exercise the new order")
		return r
	}
	step1, step2 := run("step01"), run("step02")

	memorySource := source.NewMemorySource()
	require.NoError(t, memorySource.LoadEnvelope("step01", step1.SignedEnvelope))
	require.NoError(t, memorySource.LoadEnvelope("step02", step2.SignedEnvelope))
	pass, stepResults, err := testPolicy.Verify(context.Background(),
		policy.WithVerifiedSource(source.NewVerifiedSource(memorySource, dsse.VerifyWithVerifiers(functionaryVerifier))),
		policy.WithSubjectDigests([]string{seedDigestHex}),
	)
	require.NoError(t, err)
	require.True(t, pass, fmt.Sprintf("policy failed: %+v", stepResults))
}
