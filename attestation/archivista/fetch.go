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

package archivista

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// FetchOption configures FetchAllForSubject behaviour.
type FetchOption func(*fetchConfig)

type fetchConfig struct {
	maxEnvelopes int
	maxDepth     int
}

// WithMaxEnvelopes caps the total envelope count FetchAllForSubject will
// return. Defends against runaway recursion on a poisoned Archivista or
// pathological subject graphs.
func WithMaxEnvelopes(n int) FetchOption {
	return func(c *fetchConfig) {
		if n > 0 {
			c.maxEnvelopes = n
		}
	}
}

// WithMaxDepth caps the subject-graph traversal depth. Depth 1 means "only
// envelopes whose subjects match the seed digests"; depth 2 follows one hop
// through newly-discovered subjects, and so on. Default: 5.
func WithMaxDepth(d int) FetchOption {
	return func(c *fetchConfig) {
		if d > 0 {
			c.maxDepth = d
		}
	}
}

// FetchAllForSubject walks the Archivista subject graph starting from the
// given seed subject digests and returns every DSSE envelope reachable.
//
// Algorithm:
//
//  1. Query gitoids whose statement subjects intersect the current frontier
//     (excluding gitoids already downloaded).
//  2. Download each new gitoid as a DSSE envelope.
//  3. Decode the statement and add any new subject digests to the next
//     frontier so downstream attestations sharing a digest with the seed
//     are also collected.
//  4. Repeat until the frontier is empty or limits are hit.
//
// Signatures are not verified here — that is the caller's job during policy
// evaluation. Default limits: 10000 envelopes, depth 5. Override via opts.
func (c *Client) FetchAllForSubject(ctx context.Context, seedSubjects []string, opts ...FetchOption) ([]dsse.Envelope, error) { //nolint:gocognit // graph walk with depth + envelope caps reads more cleanly inline than fanned across helpers
	cfg := fetchConfig{
		maxEnvelopes: 10000,
		maxDepth:     5,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if len(seedSubjects) == 0 {
		return nil, fmt.Errorf("at least one seed subject digest is required")
	}

	seenGitoids := make(map[string]struct{})
	seenSubjects := make(map[string]struct{}, len(seedSubjects))
	for _, s := range seedSubjects {
		seenSubjects[s] = struct{}{}
	}

	frontier := append([]string(nil), seedSubjects...)
	envelopes := make([]dsse.Envelope, 0)

	var depth int
	for depth = 0; depth < cfg.maxDepth && len(frontier) > 0; depth++ {
		excludeList := mapKeys(seenGitoids)
		sort.Strings(excludeList)

		gitoids, err := c.SearchGitoidsBySubjects(ctx, frontier, excludeList)
		if err != nil {
			return nil, fmt.Errorf("archivista search at depth %d: %w", depth, err)
		}

		nextFrontier := make([]string, 0)
		for _, gitoid := range gitoids {
			if _, ok := seenGitoids[gitoid]; ok {
				continue
			}
			if len(envelopes) >= cfg.maxEnvelopes {
				return envelopes, fmt.Errorf("archivista fetch exceeded max envelopes (%d) — pass WithMaxEnvelopes to raise", cfg.maxEnvelopes)
			}

			env, err := c.Download(ctx, gitoid)
			if err != nil {
				return nil, fmt.Errorf("download %s: %w", gitoid, err)
			}
			seenGitoids[gitoid] = struct{}{}
			envelopes = append(envelopes, env)

			for _, sub := range extractSubjectDigests(env) {
				if _, ok := seenSubjects[sub]; ok {
					continue
				}
				seenSubjects[sub] = struct{}{}
				nextFrontier = append(nextFrontier, sub)
			}
		}

		frontier = nextFrontier
	}

	// Loop exited with a non-empty frontier ⇒ we hit maxDepth before
	// exhausting the subject graph. Return what we have plus an error so
	// operators are forced to acknowledge the truncation (silent partial
	// results hide blind spots in verify-time evidence collection).
	if depth >= cfg.maxDepth && len(frontier) > 0 {
		return envelopes, fmt.Errorf("archivista fetch exceeded max depth (%d) with %d unexplored subject(s) — pass WithMaxDepth to raise", cfg.maxDepth, len(frontier))
	}

	return envelopes, nil
}

func extractSubjectDigests(env dsse.Envelope) []string {
	if len(env.Payload) == 0 {
		return nil
	}
	var stmt intoto.Statement
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return nil
	}
	out := make([]string, 0, len(stmt.Subject))
	for _, s := range stmt.Subject {
		for _, digest := range s.Digest {
			out = append(out, digest)
		}
	}
	return out
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
