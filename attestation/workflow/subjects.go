// Copyright 2025 The Aflock Authors
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
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// ParseSubjectFlags converts raw CLI/action values into a subject map suitable
// for RunWithAdditionalSubjects. Two forms are accepted per value:
//
//   - Bare name, e.g. "product:62ee1b9d-..."
//     A deterministic sha256 digest over the UTF-8 bytes of the name is
//     synthesised. This matches the existing witness/TestifySec convention
//     for identifier-style subjects consumed by subscriber auto-linking.
//
//   - "name=<alg>:<hex>", e.g. "binary=sha256:abcdef1234..."
//     The digest is taken verbatim. <alg> must be a hash name understood
//     by cryptoutil.HashFromString (sha256, sha1, sha512, ...).
//
// Duplicate names are rejected — collisions within the user's own flag set
// almost always indicate a typo rather than intent.
func ParseSubjectFlags(raw []string) (map[string]cryptoutil.DigestSet, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	out := make(map[string]cryptoutil.DigestSet, len(raw))
	for _, entry := range raw {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}

		name, digest, err := parseSubjectEntry(trimmed)
		if err != nil {
			return nil, fmt.Errorf("subject %q: %w", entry, err)
		}

		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("subject %q: duplicate name %q", entry, name)
		}
		out[name] = digest
	}

	return out, nil
}

func parseSubjectEntry(entry string) (string, cryptoutil.DigestSet, error) {
	// Split on the first '=' — subject names may contain ':'.
	if eq := strings.Index(entry, "="); eq >= 0 {
		name := strings.TrimSpace(entry[:eq])
		digestSpec := strings.TrimSpace(entry[eq+1:])
		if name == "" {
			return "", nil, fmt.Errorf("empty subject name before '='")
		}
		if digestSpec == "" {
			return "", nil, fmt.Errorf("empty digest after '='")
		}

		ds, err := parseDigestSpec(digestSpec)
		if err != nil {
			return "", nil, err
		}
		return name, ds, nil
	}

	return entry, syntheticDigestForName(entry), nil
}

func parseDigestSpec(spec string) (cryptoutil.DigestSet, error) {
	colon := strings.Index(spec, ":")
	if colon <= 0 {
		return nil, fmt.Errorf("digest %q must be of the form '<alg>:<hex>'", spec)
	}

	alg := strings.ToLower(strings.TrimSpace(spec[:colon]))
	hexDigest := strings.TrimSpace(spec[colon+1:])
	if hexDigest == "" {
		return nil, fmt.Errorf("digest %q has an empty hex value", spec)
	}
	decoded, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("digest %q is not valid hex: %w", spec, err)
	}

	hashAlg, err := cryptoutil.HashFromString(alg)
	if err != nil {
		return nil, fmt.Errorf("digest algorithm %q not supported: %w", alg, err)
	}

	// Guard against truncated/padded digests that would otherwise produce a
	// malformed in-toto subject. Size() returns 0 for crypto.Hash values whose
	// implementation isn't linked into the binary; for those we can only
	// trust the hex parse above (no length information available).
	if size := hashAlg.Size(); size > 0 && len(decoded) != size {
		return nil, fmt.Errorf("digest %q: expected %d bytes for %s, got %d", spec, size, alg, len(decoded))
	}

	return cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: hashAlg}: hexDigest,
	}, nil
}

func syntheticDigestForName(name string) cryptoutil.DigestSet {
	sum := sha256.Sum256([]byte(name))
	return cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA256}: hex.EncodeToString(sum[:]),
	}
}
