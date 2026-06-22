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

package cryptoutil

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"

	"golang.org/x/mod/sumdb/dirhash"
)

var (
	hashNames = map[DigestValue]string{
		{
			Hash:    crypto.SHA256,
			GitOID:  false,
			DirHash: false,
		}: "sha256",
		{
			Hash:    crypto.SHA1,
			GitOID:  false,
			DirHash: false,
		}: "sha1",
		{
			Hash:    crypto.SHA256,
			GitOID:  true,
			DirHash: false,
		}: "gitoid:sha256",
		{
			Hash:    crypto.SHA1,
			GitOID:  true,
			DirHash: false,
		}: "gitoid:sha1",
		{
			Hash:    crypto.SHA256,
			GitOID:  false,
			DirHash: true,
		}: "dirHash",
	}

	hashesByName = map[string]DigestValue{
		"sha256": {
			crypto.SHA256,
			false,
			false,
		},
		"sha1": {
			crypto.SHA1,
			false,
			false,
		},
		"gitoid:sha256": {
			crypto.SHA256,
			true,
			false,
		},
		"gitoid:sha1": {
			crypto.SHA1,
			true,
			false,
		},
		"dirHash": {
			crypto.SHA256,
			false,
			true,
		},
	}
)

type ErrUnsupportedHash string

func (e ErrUnsupportedHash) Error() string {
	return fmt.Sprintf("unsupported hash function: %v", string(e))
}

type DigestValue struct {
	crypto.Hash `jsonschema:"title=Hash Algorithm,description=Cryptographic hash function to use for digest calculation"`
	GitOID      bool `jsonschema:"title=Git OID,description=Whether to calculate Git Object ID format digest,default=false"`
	DirHash     bool `jsonschema:"title=Directory Hash,description=Whether to calculate directory hash using Go module dirhash format,default=false"`
}

func (dv DigestValue) New() hash.Hash {
	if dv.GitOID {
		return &gitoidHasher{hash: dv.Hash, buf: &bytes.Buffer{}}
	}

	return dv.Hash.New()
}

type DigestSet map[DigestValue]string

func HashToString(h crypto.Hash) (string, error) {
	if name, ok := hashNames[DigestValue{Hash: h}]; ok {
		return name, nil
	}

	return "", ErrUnsupportedHash(h.String())
}

func HashFromString(name string) (crypto.Hash, error) {
	if hash, ok := hashesByName[name]; ok {
		return hash.Hash, nil
	}

	return crypto.Hash(0), ErrUnsupportedHash(name)
}

// matchableSubjectAlgorithms is the allowlist of digest-algorithm names whose
// values are safe to use as a subject-match key when resolving "does this
// collection attest THIS artifact?".
//
// Two properties are required to be on this list:
//
//  1. Collision resistance. Subject matching is an equality check on the
//     digest value; if an attacker can craft two distinct artifacts that share
//     a digest, a collection legitimately signed over one can be replayed to
//     "verify" the other. SHA-1 is omitted for exactly this reason — it has
//     practical chosen-prefix collisions and must NOT anchor a subject match.
//
//  2. A known fixed value length, so a malformed or wrong-length value can be
//     rejected before it is indexed. The value is the number of hex characters
//     a well-formed digest must have; 0 means the value is not a plain hex
//     digest (e.g. a gitoid URI or a dirhash "h1:..." string) and only the
//     algorithm allowlist applies.
var matchableSubjectAlgorithms = map[string]int{
	"sha256":        2 * (256 / 8), // 64 hex chars
	"gitoid:sha256": 0,             // gitoid URI string, not plain hex
	"dirHash":       0,             // dirhash h1: string, not plain hex
}

// isHexString reports whether s is non-empty and composed solely of hex
// characters (0-9, a-f, A-F). Allocation-free; used to reject malformed digest
// values before they are indexed for subject matching.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// IsMatchableSubjectDigest reports whether a subject digest under the given
// algorithm name, with the given value, may be used as a subject-match key.
//
// It returns false for:
//   - unknown algorithm names,
//   - non-collision-resistant algorithms (notably "sha1" / "gitoid:sha1"),
//   - plain-hex algorithms whose value is not the exact expected hex length OR
//     contains non-hex characters (a 64-char string of "z" is the right length
//     but is not a real sha256 — it must not anchor a match).
//
// Callers that build a subject index (e.g. attestation/source) use this to keep
// SHA-1 and malformed digests out of the matchable set, closing a subject /
// artifact-substitution avenue. See finding S1.
func IsMatchableSubjectDigest(algorithm, value string) bool {
	wantHexLen, ok := matchableSubjectAlgorithms[algorithm]
	if !ok {
		return false
	}
	if wantHexLen != 0 {
		// Plain-hex algorithm: enforce exact length AND hex-ness.
		return len(value) == wantHexLen && isHexString(value)
	}
	// Non-hex value (gitoid URI / dirhash string): the algorithm allowlist is
	// the gate; only require a non-empty value.
	return value != ""
}

// digestSize returns the digest length in bytes for a recognized DigestValue,
// and ok=false for any unknown or zero-value DigestValue. It gates calls to
// crypto.Hash.Size(), which panics for an unregistered/zero hash: only the
// algorithms in hashNames (sha256/sha1 and their gitoid/dirhash variants) reach
// Size(), and those are always registered.
func digestSize(dv DigestValue) (int, bool) {
	if _, ok := hashNames[dv]; !ok {
		return 0, false
	}
	return dv.Size(), true
}

// Equal returns true if every digest for hash functions both artifacts have in common are equal.
// If the two artifacts don't have any digests from common hash functions, equal will return false.
// If any digest from common hash functions differ between the two artifacts, equal will return false.
//
// Equality must not be allowed to silently downgrade to the weakest shared hash: an attacker who
// omits the strong digest could otherwise force a match on a weak one (GHSA-pgpm-j729-qcvh).
// Equality therefore additionally requires that the strongest algorithm present on either side is
// carried by both sides and agrees. If the strongest available algorithm is absent from one side,
// the sets are not equal.
func (ds *DigestSet) Equal(second DigestSet) bool {
	maxSize := strongestRecognizedSize(*ds, second)
	if maxSize < 0 {
		// Both sets are empty, or neither carries a recognized algorithm; there is
		// nothing we can compare strength on, so they are not equal.
		return false
	}
	if !strongestClassAgrees(*ds, second, maxSize) {
		return false
	}
	return noRecognizedSharedDisagrees(*ds, second)
}

// strongestRecognizedSize returns the largest digest size (larger size ==
// stronger) among recognized algorithms across either set, or -1 if neither has
// one. Unknown / zero-value keys are skipped, so crypto.Hash.Size() is never
// called on an unregistered hash, which would panic — a DoS vector for a caller
// that hand-builds a DigestSet with a zero-value key (GHSA-pgpm-j729-qcvh).
func strongestRecognizedSize(a, b DigestSet) int {
	maxSize := -1
	for _, set := range []DigestSet{a, b} {
		for dv := range set {
			if n, ok := digestSize(dv); ok && n > maxSize {
				maxSize = n
			}
		}
	}
	return maxSize
}

// strongestClassAgrees reports whether at least one algorithm in the
// strongest-size class is shared by both sides and every shared algorithm in
// that class agrees. This prevents one side from dropping the strong digest to
// force comparison onto a weaker shared algorithm (GHSA-pgpm-j729-qcvh).
//
// Tie semantics (intentional): when two algorithms tie at the strongest size, a
// match on EITHER satisfies equality, so Equal is not strictly transitive across
// the tie (e.g. {sha256:x} == {sha256:x, gitoid:sha256:y} and
// {sha256:x, gitoid:sha256:y} == {gitoid:sha256:y}, but
// {sha256:x} != {gitoid:sha256:y}). This leniency is deliberate and matches
// upstream go-witness: it lets attestors that record different strong-algorithm
// subsets still compare equal. It is not a downgrade vector — every
// strongest-size algorithm here is a 32-byte SHA-256 variant, so matching any
// one requires reproducing the actual content. Requiring ALL strongest-size
// algorithms on both sides would restore transitivity but reject legitimate
// cross-attestor comparisons, so it is intentionally not done.
func strongestClassAgrees(a, b DigestSet, maxSize int) bool {
	shared := false
	for hash, digest := range a {
		if n, ok := digestSize(hash); !ok || n != maxSize {
			continue
		}
		other, ok := b[hash]
		if !ok {
			continue
		}
		if digest != other {
			return false
		}
		shared = true
	}
	return shared
}

// noRecognizedSharedDisagrees reports whether no shared RECOGNIZED algorithm of
// any strength disagrees. Unknown keys are ignored so equality stays a proper
// equivalence relation over recognized algorithms: two sets that agree on every
// recognized algorithm are not made unequal by differing on an unrecognized key.
func noRecognizedSharedDisagrees(a, b DigestSet) bool {
	for hash, digest := range a {
		if _, ok := digestSize(hash); !ok {
			continue
		}
		if other, ok := b[hash]; ok && digest != other {
			return false
		}
	}
	return true
}

func (ds *DigestSet) ToNameMap() (map[string]string, error) {
	nameMap := make(map[string]string)
	for hash, digest := range *ds {
		name, ok := hashNames[hash]
		if !ok {
			return nameMap, ErrUnsupportedHash(hash.String())
		}

		nameMap[name] = digest
	}

	return nameMap, nil
}

func NewDigestSet(digestsByName map[string]string) (DigestSet, error) {
	ds := make(DigestSet)
	for hashName, digest := range digestsByName {
		hash, ok := hashesByName[hashName]
		if !ok {
			return ds, ErrUnsupportedHash(hashName)
		}

		ds[hash] = digest
	}

	return ds, nil
}

func CalculateDigestSet(r io.Reader, digestValues []DigestValue) (DigestSet, error) {
	digestSet := make(DigestSet)
	writers := make([]io.Writer, 0, len(digestValues))
	hashfuncs := map[DigestValue]hash.Hash{}
	for _, digestValue := range digestValues {
		hashfunc := digestValue.New()
		hashfuncs[digestValue] = hashfunc
		writers = append(writers, hashfunc)
	}

	multiwriter := io.MultiWriter(writers...)
	if _, err := io.Copy(multiwriter, r); err != nil {
		return digestSet, err
	}

	for digestValue, hashfunc := range hashfuncs {
		// gitoids are somewhat special... we're using a custom implementation of hash.Hash
		// to wrap the gitoid library. Sum will return a gitoid URI, so we don't want to hex
		// encode it as it's already a string with a hex encoded hash.
		if digestValue.GitOID {
			digestSet[digestValue] = string(hashfunc.Sum(nil))
			continue
		}

		digestSet[digestValue] = string(HexEncode(hashfunc.Sum(nil)))
	}

	return digestSet, nil
}

func CalculateDigestSetFromBytes(data []byte, hashes []DigestValue) (DigestSet, error) {
	return CalculateDigestSet(bytes.NewReader(data), hashes)
}

func CalculateDigestSetFromFile(path string, hashes []DigestValue) (DigestSet, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is provided by the caller
	if err != nil {
		return DigestSet{}, err
	}
	defer func() { _ = file.Close() }()

	hashable, err := isHashableFile(file)
	if err != nil {
		return DigestSet{}, err
	}

	if !hashable {
		return DigestSet{}, fmt.Errorf("%s is not a hashable file", path)
	}

	return CalculateDigestSet(file, hashes)
}

func CalculateDigestSetFromDir(dir string, hashes []DigestValue) (DigestSet, error) {

	dirHash, err := dirhash.HashDir(dir, "", DirhHashSha256)
	if err != nil {
		return nil, err
	}

	digestSetByName := make(map[string]string)
	digestSetByName["dirHash"] = dirHash

	return NewDigestSet(digestSetByName)
}

func (ds DigestSet) MarshalJSON() ([]byte, error) {
	nameMap, err := ds.ToNameMap()
	if err != nil {
		return nil, err
	}

	return json.Marshal(nameMap)
}

func (ds *DigestSet) UnmarshalJSON(data []byte) error {
	nameMap := make(map[string]string)
	err := json.Unmarshal(data, &nameMap)
	if err != nil {
		return err
	}

	newDs, err := NewDigestSet(nameMap)
	if err != nil {
		return err
	}

	*ds = newDs
	return nil
}

func isHashableFile(f *os.File) (bool, error) {
	stat, err := f.Stat()
	if err != nil {
		return false, err
	}

	mode := stat.Mode()

	isSpecial := stat.Mode()&os.ModeCharDevice != 0

	if isSpecial {
		return false, nil
	}

	if mode.IsRegular() {
		return true, nil
	}

	if mode.Perm().IsDir() {
		return true, nil
	}

	if mode&os.ModeSymlink != 0 {
		return true, nil
	}

	return false, nil
}
