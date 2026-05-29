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

package testkit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// recordedAttestation is the parsed view of a real cilock attestation
// collection (a DSSE envelope wrapping an in-toto collection statement) that a
// fixture recorded from a real tool run. The SDK reads it to prove the
// catalog contract against REAL evidence — the documented invocation actually
// produced these subjects, at the recorded tool version.
type recordedAttestation struct {
	PayloadType    string                     // DSSE envelope payloadType
	SignatureCount int                        // number of DSSE signatures (a genuine signed envelope has >=1)
	Subjects       []string                   // collection subject names (namespaced: "<predType>/<key>")
	Argv           []string                   // command-run argv
	ByType         map[string]json.RawMessage // attestor predicate-type -> its sub-attestation
}

// types returns the recorded attestation's predicate types, sorted.
func (r *recordedAttestation) types() []string {
	out := make([]string, 0, len(r.ByType))
	for k := range r.ByType {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadRecordedAttestation decodes a DSSE envelope's payload into the in-toto
// collection statement and extracts subjects, the command-run argv, and each
// embedded attestation keyed by type.
func loadRecordedAttestation(path string) (*recordedAttestation, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // path from the fixture manifest
	if err != nil {
		return nil, err
	}
	var env struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig   string `json:"sig"`
			KeyID string `json:"keyid"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parse DSSE envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	var stmt struct {
		Subject []struct {
			Name string `json:"name"`
		} `json:"subject"`
		Predicate struct {
			Attestations []struct {
				Type        string          `json:"type"`
				Attestation json.RawMessage `json:"attestation"`
			} `json:"attestations"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}
	rec := &recordedAttestation{
		ByType:         make(map[string]json.RawMessage),
		PayloadType:    env.PayloadType,
		SignatureCount: len(env.Signatures),
	}
	for _, s := range stmt.Subject {
		rec.Subjects = append(rec.Subjects, s.Name)
	}
	for _, a := range stmt.Predicate.Attestations {
		rec.ByType[a.Type] = a.Attestation
		if strings.HasSuffix(a.Type, "command-run/v0.1") {
			var cr struct {
				Cmd []string `json:"cmd"`
			}
			_ = json.Unmarshal(a.Attestation, &cr)
			rec.Argv = cr.Cmd
		}
	}
	return rec, nil
}

// hasSubjectMatching reports whether any collection subject name contains the
// wanted key family. Collection subjects are namespaced "<predType>/<key>", so
// the contract prefix (e.g. "trivy:cve:") appears as a substring.
func (r *recordedAttestation) hasSubjectMatching(want string) bool {
	for _, s := range r.Subjects {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}
