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
	"errors"
	"sync"

	"github.com/aflock-ai/rookery/attestation/archivista"
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

// SearchByPredicateType is a scaffold stub — the real implementation is a
// follow-up PR that will issue an Archivista GraphQL query of the form
// hasStatementWith.predicateIn:[...] + hasSubjectsWith.valueIn:[...]
// (see go-witness issue #595). Returning an explicit error here keeps the
// Sourcer interface contract honest until the query + download plumbing
// lands.
//
// TODO(#39): implement external-attestation search against Archivista.
func (s *ArchivistaSource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]StatementEnvelope, error) {
	return nil, errors.New("ArchivistaSource.SearchByPredicateType: not implemented")
}
