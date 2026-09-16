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

package workflow

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Statement size limit.
//
// Every attestation this package signs is an in-toto statement: the predicate
// (a collection, or one exported attestor) framed with its type and subjects,
// marshalled to JSON, then base64-encoded into a DSSE envelope. The statement
// JSON is what a consumer decodes and parses, so it is the unit the limit is
// measured in, and it is measured on the exact bytes handed to dsse.Sign.
//
// Why a limit at all: the platform's push evaluation downloads and parses
// every envelope that matches the commit, three times, and only caches
// envelopes under 512 KiB. Measured 2026-09-15 at about 0.4 s per MB: a
// commit with no large envelope evaluates in 0.95 s, one 45 MB envelope
// takes 18.6 s, two take 32 s, against a 25 s edge timeout. The regression
// that produced those envelopes was a command-run attestor carrying a whole
// `go test -json` stream. The limit turns the next such regression into a
// refusal at mint time instead of a timeout at push time.
//
// The library default is unlimited so existing callers keep their behaviour;
// the cilock CLI sets its own default (4 MiB) and passes it in.

// MaxStatementContributors bounds the per-attestor breakdown carried by a
// StatementTooLargeError: the largest five is enough to say what to fix.
const MaxStatementContributors = 5

// RunWithMaxStatementBytes refuses to sign any statement whose JSON encoding
// is larger than n bytes. Zero (the default) or a negative value disables the
// check. It applies to the collection and to every exported attestor
// envelope; companions (CompanionExporter: detached file inventories and
// material manifests) are exempt, because they are keyed by tree root, never
// opened by a commit-keyed evaluation, and carry their own ceiling and their
// own upload consent.
func RunWithMaxStatementBytes(n int) RunOption {
	return func(ro *runOptions) {
		ro.maxStatementBytes = n
	}
}

// StatementContributor is one predicate's share of an oversized statement.
// For a collection statement it is one attestor entry (Type is the attestor's
// predicate type URI); for a single-predicate statement it is the predicate.
type StatementContributor struct {
	Type  string
	Bytes int
}

// StatementTooLargeError is returned instead of a signed envelope when a
// statement exceeds the configured limit. Nothing has been signed, written
// or uploaded when it is returned.
type StatementTooLargeError struct {
	// PredicateType is the statement's predicate type (the collection type,
	// or the exported attestor's type).
	PredicateType string
	// Bytes is the measured size of the statement JSON; Limit the ceiling.
	Bytes int
	Limit int
	// Contributors lists the largest predicates in the statement, largest
	// first, at most MaxStatementContributors entries.
	Contributors []StatementContributor
}

func (e *StatementTooLargeError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "attestation too large: the %s statement is %d bytes, over the %d byte limit; refusing to sign it", e.PredicateType, e.Bytes, e.Limit)
	for _, c := range e.Contributors {
		fmt.Fprintf(&b, "\n  %d bytes  %s", c.Bytes, c.Type)
	}
	return b.String()
}

// CheckStatementSize returns a StatementTooLargeError when stmtJSON is over
// limit bytes. A limit of zero or less is unlimited. predicateType only
// labels the error.
func CheckStatementSize(stmtJSON []byte, predicateType string, limit int) error {
	if limit <= 0 || len(stmtJSON) <= limit {
		return nil
	}
	return &StatementTooLargeError{
		PredicateType: predicateType,
		Bytes:         len(stmtJSON),
		Limit:         limit,
		Contributors:  StatementContributors(stmtJSON),
	}
}

// StatementContributors measures the predicates inside a statement's JSON
// and returns the largest MaxStatementContributors of them, largest first.
// It works on the bytes rather than a typed collection so `cilock sign` can
// explain a statement it was handed as a file with the same code as `cilock
// run` uses for one it built, and so no attestor is marshalled a second time
// on the success path: this runs only once a statement has already been
// refused. Bytes that do not parse as a statement yield no contributors.
func StatementContributors(stmtJSON []byte) []StatementContributor {
	var stmt struct {
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(stmtJSON, &stmt); err != nil || len(stmt.Predicate) == 0 {
		return nil
	}
	var collection struct {
		Attestations []struct {
			Type        string          `json:"type"`
			Attestation json.RawMessage `json:"attestation"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(stmt.Predicate, &collection); err != nil || len(collection.Attestations) == 0 {
		return []StatementContributor{{Type: stmt.PredicateType, Bytes: len(stmt.Predicate)}}
	}
	contributors := make([]StatementContributor, 0, len(collection.Attestations))
	for _, entry := range collection.Attestations {
		contributors = append(contributors, StatementContributor{Type: entry.Type, Bytes: len(entry.Attestation)})
	}
	// Largest first; ties broken by type so the order is stable across runs.
	sort.SliceStable(contributors, func(i, j int) bool {
		if contributors[i].Bytes != contributors[j].Bytes {
			return contributors[i].Bytes > contributors[j].Bytes
		}
		return contributors[i].Type < contributors[j].Type
	})
	if len(contributors) > MaxStatementContributors {
		contributors = contributors[:MaxStatementContributors]
	}
	return contributors
}
