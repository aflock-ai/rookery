// Copyright 2022 The Witness Contributors
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

type ErrDuplicateReference string

func (e ErrDuplicateReference) Error() string {
	return fmt.Sprintf("references may only appear once in a memory source: %v", string(e))
}

type MemorySource struct {
	mu                         sync.RWMutex
	envelopesByReference       map[string]CollectionEnvelope
	referencesByCollectionName map[string][]string
	subjectDigestsByReference  map[string]map[string]struct{}
	attestationsByReference    map[string]map[string]struct{}
}

func NewMemorySource() *MemorySource {
	return &MemorySource{
		envelopesByReference:       make(map[string]CollectionEnvelope),
		referencesByCollectionName: make(map[string][]string),
		subjectDigestsByReference:  make(map[string]map[string]struct{}),
		attestationsByReference:    make(map[string]map[string]struct{}),
	}
}

func (s *MemorySource) LoadFile(path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: path is provided by the caller
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()
	return s.LoadReader(path, f)
}

func (s *MemorySource) LoadReader(reference string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	return s.LoadBytes(reference, data)
}

func (s *MemorySource) LoadBytes(reference string, data []byte) error {
	env := dsse.Envelope{}
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}

	return s.LoadEnvelope(reference, env)
}

func (s *MemorySource) LoadEnvelope(reference string, env dsse.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.envelopesByReference[reference]; ok {
		return ErrDuplicateReference(reference)
	}

	collEnv, err := envelopeToCollectionEnvelope(reference, env)
	if err != nil {
		return err
	}

	s.envelopesByReference[reference] = collEnv
	s.referencesByCollectionName[collEnv.Collection.Name] = append(s.referencesByCollectionName[collEnv.Collection.Name], reference)
	subDigestIndex := make(map[string]struct{})
	for _, sub := range collEnv.Statement.Subject {
		for _, digest := range sub.Digest {
			subDigestIndex[digest] = struct{}{}
		}
	}

	s.subjectDigestsByReference[reference] = subDigestIndex
	attestationIndex := make(map[string]struct{})
	for _, att := range collEnv.Collection.Attestations {
		attType := att.Type
		attestationIndex[attType] = struct{}{}
		// Also index the alternate URI so that policies using either
		// witness.dev or aflock.ai URIs can find the attestation.
		if alt := attestation.LegacyAlternate(attType); alt != "" {
			attestationIndex[alt] = struct{}{}
		}
	}

	s.attestationsByReference[reference] = attestationIndex
	return nil
}

func (s *MemorySource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matches := make([]CollectionEnvelope, 0)
	for _, potentialMatchReference := range s.referencesByCollectionName[collectionName] {
		env, ok := s.envelopesByReference[potentialMatchReference]
		if !ok {
			continue
		}

		// make sure at least one of the subjects digests exists on the potential matches.
		// If the collection has no subjects (e.g. trace attestations without
		// material/product subjects), skip the subject check and match on
		// step name + attestation types alone.
		indexSubjects := s.subjectDigestsByReference[potentialMatchReference]
		if len(indexSubjects) > 0 {
			subjectMatchFound := false
			for _, checkDigest := range subjectDigests {
				if _, ok := indexSubjects[checkDigest]; ok {
					subjectMatchFound = true
					break
				}
			}

			if !subjectMatchFound {
				continue
			}
		}

		// make sure all the expected attestations appear in the collection
		attestationsMatched := true
		indexAttestations := s.attestationsByReference[potentialMatchReference]
		for _, checkAttestation := range attestations {
			if _, ok := indexAttestations[checkAttestation]; !ok {
				attestationsMatched = false
				break
			}
		}

		if !attestationsMatched {
			continue
		}

		matches = append(matches, env)
	}

	return matches, nil
}
