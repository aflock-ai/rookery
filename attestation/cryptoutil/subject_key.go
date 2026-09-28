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

package cryptoutil

import (
	"sort"
	"strings"
)

// Subject digest keys (#9816).
//
// Subject matching compares (algorithm, value) PAIRS, never bare values. A
// bare-value match let a subject digest under one algorithm satisfy a seed that
// was produced under another with the same string, e.g. {"gitoid:sha256": <64
// hex>} matching a sha256 seed, or {"dirHash": <40 hex>} matching a git commit
// seed without passing the hardened-git SHA-1 gate.
//
// The pair travels through the string-typed Search API as a KEY,
// "<algorithm>:<value>", built on both sides by SubjectDigestKey. Only the
// algorithm names in subjectKeyAlgorithms are ever produced or parsed, and
// none of them is a prefix of another followed by ':', so the split is
// unambiguous even though gitoid names and values themselves contain ':'.

// subjectKeyAlgorithms lists the algorithm names a key may carry, longest
// first so the "gitoid:" names win over a shorter prefix.
var subjectKeyAlgorithms = []string{
	digestNameGitOIDSHA256,
	digestNameGitOIDSHA1,
	digestNameSHA256,
	digestNameDirHash,
	digestNameSHA1,
}

// SubjectDigestKey returns the match key for one subject digest.
func SubjectDigestKey(algorithm, value string) string {
	return algorithm + ":" + value
}

// ParseSubjectDigestKey splits a key built by SubjectDigestKey. It reports
// false for a bare value, an unknown algorithm or an empty value.
func ParseSubjectDigestKey(key string) (algorithm, value string, ok bool) {
	for _, alg := range subjectKeyAlgorithms {
		if v, found := strings.CutPrefix(key, alg+":"); found && v != "" {
			return alg, v, true
		}
	}
	return "", "", false
}

// NormalizeSubjectSeed turns one caller-supplied seed into a match key.
//
// A seed that is already a key is returned unchanged. A BARE value (the
// pre-#9816 form, still sent by older callers and by the Judge policy test
// API) is bound to the one algorithm its shape proves, through this explicit
// table and nothing else:
//
//	64 hex characters          -> sha256
//	40 hex characters          -> sha1 (only a hardened git commit subject
//	                              is matchable under sha1, so this cannot
//	                              reach any other kind of subject)
//	"gitoid:blob:sha256:..."   -> gitoid:sha256
//	"gitoid:blob:sha1:..."     -> gitoid:sha1
//	"h1:..."                   -> dirHash
//
// No bare value maps to two algorithms, so the table cannot recreate the
// cross-algorithm match this type exists to remove. Anything else is returned
// unchanged: an opaque string can only equal an identical opaque string and
// never a real subject key, so it fails closed.
func NormalizeSubjectSeed(seed string) string {
	if _, _, ok := ParseSubjectDigestKey(seed); ok {
		return seed
	}
	switch {
	case len(seed) == 64 && isHexString(seed):
		return SubjectDigestKey(digestNameSHA256, seed)
	case len(seed) == 40 && isHexString(seed):
		return SubjectDigestKey(digestNameSHA1, seed)
	case strings.HasPrefix(seed, "gitoid:blob:sha256:"):
		return SubjectDigestKey(digestNameGitOIDSHA256, seed)
	case strings.HasPrefix(seed, "gitoid:blob:sha1:"):
		return SubjectDigestKey(digestNameGitOIDSHA1, seed)
	case strings.HasPrefix(seed, "h1:"):
		return SubjectDigestKey(digestNameDirHash, seed)
	}
	return seed
}

// NormalizeSubjectSeeds normalizes every seed, dropping duplicates while
// keeping first-seen order. It returns nil for an empty input so "no seeds"
// keeps its meaning (a subject-agnostic query) for every Sourcer.
func NormalizeSubjectSeeds(seeds []string) []string {
	if len(seeds) == 0 {
		return nil
	}
	out := make([]string, 0, len(seeds))
	seen := make(map[string]struct{}, len(seeds))
	for _, s := range seeds {
		k := NormalizeSubjectSeed(s)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// SubjectDigestValues returns the distinct VALUE halves of the given keys, for
// a remote store (Archivista, Judge's database) whose index is value-keyed.
// Such a store is only a pre-filter: every candidate is re-checked on
// (algorithm, value) against the signed payload by VerifiedSource. Opaque
// seeds pass through unchanged.
func SubjectDigestValues(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		v := k
		if _, val, ok := ParseSubjectDigestKey(k); ok {
			v = val
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// DigestSetSubjectKeys returns the match keys for every digest in ds, sorted.
func DigestSetSubjectKeys(ds DigestSet) ([]string, error) {
	named, err := ds.ToNameMap()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(named))
	for alg, val := range named {
		out = append(out, SubjectDigestKey(alg, val))
	}
	sort.Strings(out)
	return out, nil
}
