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
	"sync"

	"github.com/aflock-ai/rookery/attestation/archivista"
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
			return nil, err
		}

		collectionEnv, err := envelopeToCollectionEnvelope(gitoid, env)
		if err != nil {
			return nil, err
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
