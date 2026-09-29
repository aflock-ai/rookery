// Copyright 2021 The Witness Contributors
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

package intoto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

const (
	// StatementTypeV1 is the in-toto Statement v1 _type, which slsa-verifier
	// and gh attestation verify expect for SLSA v1 provenance. cilock signs its
	// collections and the VSAs `cilock verify` builds with it, through
	// NewStatementV1 (#9879).
	StatementTypeV1 = "https://in-toto.io/Statement/v1"
	// StatementType is the legacy v0.1 _type. NewStatement still emits it,
	// because platform-signed records (push receipts, VSAs, entitlements)
	// are checked for it byte-for-byte by deployed verifiers. Readers accept
	// both through IsStatementType.
	StatementType = "https://in-toto.io/Statement/v0.1"
	PayloadType   = "application/vnd.in-toto+json"
)

// IsStatementType reports whether t is an in-toto Statement _type this
// module reads: v1, or the legacy v0.1. The field layout is identical.
func IsStatementType(t string) bool {
	return t == StatementTypeV1 || t == StatementType
}

// NewStatementV1 is NewStatement with the in-toto Statement v1 _type.
func NewStatementV1(predicateType string, predicate []byte, subjects map[string]cryptoutil.DigestSet) (Statement, error) {
	return NewStatementV1WithLeadingSubjects(predicateType, predicate, subjects, nil)
}

// NewStatementV1WithLeadingSubjects is NewStatementV1 with the subjects named
// in leading emitted first, in that order; the rest follow sorted by name.
// Names absent from subjects are skipped and repeats are emitted once, so the
// same leading list can be passed for every envelope a run signs.
//
// Consumers that bind a statement to one artifact read subject[0]: JFrog
// Evidence refuses an upload whose first subject is not the artifact
// ("evidence subject digest (sha256) mismatch"). Sorting alone puts cilock's
// https://aflock.ai/... tree roots ahead of a user's artifact. Verifiers that
// match by digest set are unaffected by the order.
func NewStatementV1WithLeadingSubjects(predicateType string, predicate []byte, subjects map[string]cryptoutil.DigestSet, leading []string) (Statement, error) {
	statement, err := newStatement(predicateType, predicate, subjects, leading)
	statement.Type = StatementTypeV1
	return statement, err
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

func NewStatement(predicateType string, predicate []byte, subjects map[string]cryptoutil.DigestSet) (Statement, error) {
	return newStatement(predicateType, predicate, subjects, nil)
}

func newStatement(predicateType string, predicate []byte, subjects map[string]cryptoutil.DigestSet, leading []string) (Statement, error) {
	if !json.Valid(predicate) {
		return Statement{}, fmt.Errorf("predicate must be valid JSON")
	}

	// in-toto Attestation Framework v1, statement.md: predicateType is a
	// required TypeURI and predicate is an object (optional, so a caller with
	// nothing to say passes {}). This is the one constructor every signed
	// statement goes through, so it refuses rather than signs what the spec
	// forbids.
	if predicateType == "" {
		return Statement{}, fmt.Errorf("predicate type is required")
	}
	if trimmed := bytes.TrimLeft(predicate, " \t\r\n"); len(trimmed) == 0 || trimmed[0] != '{' {
		return Statement{}, fmt.Errorf("predicate must be a JSON object")
	}

	statement := Statement{
		Type:          StatementType,
		PredicateType: predicateType,
		Subject:       make([]Subject, 0, len(subjects)),
		Predicate:     predicate,
	}

	// Leading names first in the caller's order, then the rest sorted, for
	// deterministic output. Go map iteration is non-deterministic, so without
	// a fixed order the same inputs would produce different JSON payloads and
	// therefore different DSSE signatures.
	names := make([]string, 0, len(subjects))
	placed := make(map[string]bool, len(leading))
	for _, name := range leading {
		if _, ok := subjects[name]; ok && !placed[name] {
			placed[name] = true
			names = append(names, name)
		}
	}
	rest := make([]string, 0, len(subjects)-len(names))
	for name := range subjects {
		if !placed[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	names = append(names, rest...)

	for _, name := range names {
		ds := subjects[name]
		// statement.md: every subject "MUST have digest set".
		if len(ds) == 0 {
			return Statement{}, fmt.Errorf("subject %q has no digest", name)
		}
		subj, err := DigestSetToSubject(name, ds)
		if err != nil {
			return statement, err
		}

		statement.Subject = append(statement.Subject, subj)
	}

	return statement, nil
}

func DigestSetToSubject(name string, ds cryptoutil.DigestSet) (Subject, error) {
	subj := Subject{
		Name: name,
	}

	digestsByName, err := ds.ToNameMap()
	if err != nil {
		return subj, err
	}

	subj.Digest = digestsByName
	return subj, nil
}
