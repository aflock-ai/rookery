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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

const (
	StatementType = "https://in-toto.io/Statement/v0.1"
	PayloadType   = "application/vnd.in-toto+json"
)

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
	if !json.Valid(predicate) {
		return Statement{}, fmt.Errorf("predicate must be valid JSON")
	}

	statement := Statement{
		Type:          StatementType,
		PredicateType: predicateType,
		Subject:       make([]Subject, 0, len(subjects)),
		Predicate:     predicate,
	}

	// Sort subject names for deterministic output. Go map iteration is
	// non-deterministic, so without sorting, the same inputs would produce
	// different JSON payloads and therefore different DSSE signatures.
	names := make([]string, 0, len(subjects))
	for name := range subjects {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		ds := subjects[name]
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
