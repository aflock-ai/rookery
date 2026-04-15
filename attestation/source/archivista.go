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
	"sync"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/intoto"
	log "github.com/sirupsen/logrus"
)

// ArchivistaSource implements Sourcer backed by an Archivista server.
type ArchivistaSource struct {
	client      *archivista.Client
	mu          sync.Mutex
	seenGitoids []string
}

// NewArchivistaSource creates a new source backed by an Archivista client.
func NewArchivistaSource(client *archivista.Client) *ArchivistaSource {
	return &ArchivistaSource{
		client:      client,
		seenGitoids: make([]string, 0),
	}
}

// NewArchvistSource is a deprecated alias preserved for backward compatibility
// with go-witness. Use NewArchivistaSource instead.
//
// Deprecated: Use NewArchivistaSource.
func NewArchvistSource(client *archivista.Client) *ArchivistaSource {
	return NewArchivistaSource(client)
}

func (s *ArchivistaSource) Search(ctx context.Context, collectionName string, subjectDigests, attestations []string) ([]CollectionEnvelope, error) {
	s.mu.Lock()
	excludeGitoids := make([]string, len(s.seenGitoids))
	copy(excludeGitoids, s.seenGitoids)
	s.mu.Unlock()

	gitoids, err := s.client.SearchGitoids(ctx, archivista.SearchGitoidVariables{
		CollectionName: collectionName,
		SubjectDigests: subjectDigests,
		Attestations:   attestations,
		ExcludeGitoids: excludeGitoids,
	})
	if err != nil {
		return []CollectionEnvelope{}, err
	}

	envelopes := make([]CollectionEnvelope, 0, len(gitoids))
	processedGitoids := make([]string, 0, len(gitoids))
	for _, gitoid := range gitoids {
		env, err := s.client.Download(ctx, gitoid)
		if err != nil {
			// Skip envelopes that can't be downloaded (may be non-collection DSSEs)
			log.Debugf("archivista source: skipping gitoid %s: download failed: %v", gitoid, err)
			processedGitoids = append(processedGitoids, gitoid) // still mark as seen to avoid retrying
			continue
		}

		collectionEnv, err := envelopeToCollectionEnvelope(gitoid, env)
		if err != nil {
			// Skip non-collection envelopes (policy DSSEs, VSAs, etc.)
			log.Debugf("archivista source: skipping gitoid %s: %v", gitoid, err)
			processedGitoids = append(processedGitoids, gitoid)
			continue
		}

		processedGitoids = append(processedGitoids, gitoid)
		envelopes = append(envelopes, collectionEnv)
	}

	// Only mark gitoids as seen after ALL were successfully processed.
	// This prevents partial updates that break retry semantics: if a
	// download fails mid-batch, no gitoids are excluded on the next search.
	s.mu.Lock()
	s.seenGitoids = append(s.seenGitoids, processedGitoids...)
	s.mu.Unlock()

	return envelopes, nil
}

// SearchByPredicateType queries Archivista for DSSE envelopes whose statement
// predicateType is in predicateTypes AND whose subjects intersect
// subjectDigests. Each matched envelope is downloaded, parsed into an
// intoto.Statement, and wrapped in a StatementEnvelope with either a typed
// attestor (from the registered factory) or a RawAttestation fallback.
//
// No DSSE signature verification happens here — verification is the caller's
// responsibility via Functionary.Validate on StatementEnvelope.Verifiers.
// This implementation returns an empty Verifiers slice; the policy engine's
// external-attestation flow performs its own verification.
//
// See issue #39.
func (s *ArchivistaSource) SearchByPredicateType(ctx context.Context, predicateTypes []string, subjectDigests []string) ([]StatementEnvelope, error) {
	s.mu.Lock()
	excludeGitoids := make([]string, len(s.seenGitoids))
	copy(excludeGitoids, s.seenGitoids)
	s.mu.Unlock()

	gitoids, err := s.client.SearchGitoidsByPredicate(ctx, archivista.SearchGitoidByPredicateVariables{
		PredicateTypes: predicateTypes,
		SubjectDigests: subjectDigests,
		ExcludeGitoids: excludeGitoids,
	})
	if err != nil {
		return nil, err
	}

	envelopes := make([]StatementEnvelope, 0, len(gitoids))
	processedGitoids := make([]string, 0, len(gitoids))
	for _, gitoid := range gitoids {
		env, err := s.client.Download(ctx, gitoid)
		if err != nil {
			log.Debugf("archivista source: SearchByPredicateType skipping gitoid %s: download failed: %v", gitoid, err)
			processedGitoids = append(processedGitoids, gitoid)
			continue
		}

		se := StatementEnvelope{
			Envelope:  env,
			Reference: gitoid,
		}

		if len(env.Payload) == 0 {
			se.Errors = append(se.Errors, fmt.Errorf("envelope %s has empty payload", gitoid))
			envelopes = append(envelopes, se)
			processedGitoids = append(processedGitoids, gitoid)
			continue
		}

		stmt := intoto.Statement{}
		if err := json.Unmarshal(env.Payload, &stmt); err != nil {
			se.Errors = append(se.Errors, fmt.Errorf("envelope %s: failed to unmarshal statement: %w", gitoid, err))
			envelopes = append(envelopes, se)
			processedGitoids = append(processedGitoids, gitoid)
			continue
		}

		se.Statement = stmt

		if factory, ok := attestation.FactoryByType(stmt.PredicateType); ok {
			typed := factory()
			if err := json.Unmarshal(stmt.Predicate, typed); err != nil {
				se.Errors = append(se.Errors, fmt.Errorf("typed factory unmarshal failed for %s, falling back to raw: %w", stmt.PredicateType, err))
				se.Attestor = attestation.NewRawAttestation(stmt.PredicateType, stmt.Predicate)
			} else {
				se.Attestor = typed
			}
		} else {
			se.Attestor = attestation.NewRawAttestation(stmt.PredicateType, stmt.Predicate)
		}

		envelopes = append(envelopes, se)
		processedGitoids = append(processedGitoids, gitoid)
	}

	s.mu.Lock()
	s.seenGitoids = append(s.seenGitoids, processedGitoids...)
	s.mu.Unlock()

	return envelopes, nil
}
