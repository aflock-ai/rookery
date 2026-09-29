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

package intoto

import (
	"crypto"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

func orderTestSubjects() map[string]cryptoutil.DigestSet {
	ds := func(b string) cryptoutil.DigestSet {
		return cryptoutil.DigestSet{{Hash: crypto.SHA256}: strings.Repeat(b, 32)}
	}
	return map[string]cryptoutil.DigestSet{
		"https://aflock.ai/attestations/material/v0.3/tree:materials": ds("11"),
		"https://aflock.ai/attestations/product/v0.3/tree:products":   ds("22"),
		"zeta.tar":  ds("33"),
		"alpha.tar": ds("44"),
	}
}

func subjectNames(s Statement) []string {
	out := make([]string, 0, len(s.Subject))
	for _, subj := range s.Subject {
		out = append(out, subj.Name)
	}
	return out
}

// JFrog Evidence binds an evidence DSSE to the artifact named by the FIRST
// in-toto subject and refuses the upload otherwise ("evidence subject digest
// (sha256) mismatch"). Sorted-only output put cilock's Merkle tree roots
// (https://aflock.ai/...) ahead of the artifact, so the leading subjects are
// emitted first, in the caller's order, and the rest stay sorted.
func TestNewStatementV1WithLeadingSubjectsPutsLeadingFirstInGivenOrder(t *testing.T) {
	stmt, err := NewStatementV1WithLeadingSubjects("https://example.com/p", []byte(`{}`), orderTestSubjects(),
		[]string{"zeta.tar", "alpha.tar"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"zeta.tar",
		"alpha.tar",
		"https://aflock.ai/attestations/material/v0.3/tree:materials",
		"https://aflock.ai/attestations/product/v0.3/tree:products",
	}
	if got := subjectNames(stmt); !reflect.DeepEqual(got, want) {
		t.Fatalf("subject order = %v, want %v", got, want)
	}
	if stmt.Type != StatementTypeV1 {
		t.Fatalf("_type = %q, want %q", stmt.Type, StatementTypeV1)
	}
	if stmt.Subject[0].Digest["sha256"] != strings.Repeat("33", 32) {
		t.Fatalf("leading subject carries the wrong digest: %v", stmt.Subject[0].Digest)
	}
}

// A leading name the subject set does not contain is skipped (a sidecar
// signed over an attestor's own subjects never carries the user's), and a
// repeated leading name is emitted once.
func TestNewStatementV1WithLeadingSubjectsSkipsAbsentAndRepeatedNames(t *testing.T) {
	stmt, err := NewStatementV1WithLeadingSubjects("https://example.com/p", []byte(`{}`), orderTestSubjects(),
		[]string{"missing", "alpha.tar", "alpha.tar"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"alpha.tar",
		"https://aflock.ai/attestations/material/v0.3/tree:materials",
		"https://aflock.ai/attestations/product/v0.3/tree:products",
		"zeta.tar",
	}
	if got := subjectNames(stmt); !reflect.DeepEqual(got, want) {
		t.Fatalf("subject order = %v, want %v", got, want)
	}
}

// With no leading names the output is byte-identical to NewStatementV1, so
// every caller that does not ask for an order signs exactly what it did before.
func TestNewStatementV1WithLeadingSubjectsNilMatchesSortedOutput(t *testing.T) {
	a, err := NewStatementV1("https://example.com/p", []byte(`{}`), orderTestSubjects())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewStatementV1WithLeadingSubjects("https://example.com/p", []byte(`{}`), orderTestSubjects(), nil)
	if err != nil {
		t.Fatal(err)
	}
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	if string(aj) != string(bj) {
		t.Fatalf("nil leading changed the payload:\n%s\n%s", aj, bj)
	}
}

// Go map iteration is randomised; the payload must not be.
func TestNewStatementV1WithLeadingSubjectsIsDeterministic(t *testing.T) {
	first := ""
	for i := 0; i < 50; i++ {
		stmt, err := NewStatementV1WithLeadingSubjects("https://example.com/p", []byte(`{}`), orderTestSubjects(),
			[]string{"zeta.tar"})
		if err != nil {
			t.Fatal(err)
		}
		j, _ := json.Marshal(stmt)
		if i == 0 {
			first = string(j)
		} else if string(j) != first {
			t.Fatalf("run %d produced a different payload", i)
		}
	}
}

// The spec checks NewStatement enforces still apply to a leading subject.
func TestNewStatementV1WithLeadingSubjectsRefusesEmptyDigest(t *testing.T) {
	subjects := orderTestSubjects()
	subjects["zeta.tar"] = cryptoutil.DigestSet{}
	if _, err := NewStatementV1WithLeadingSubjects("https://example.com/p", []byte(`{}`), subjects,
		[]string{"zeta.tar"}); err == nil {
		t.Fatal("expected an error for a leading subject with no digest")
	}
}
