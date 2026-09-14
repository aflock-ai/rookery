// Copyright 2025 The Witness Contributors
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

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
)

// errCompanionTooLarge is returned when a companion file or stream exceeds
// the ceiling derived from inclusionproof.MaxManifestBytes — the limit the
// producer honoured on the compact predicate, carried through the encoding
// (see companionCeilings) — so anything above it was never emitted by a
// conformant producer and is refused BEFORE it is read, decoded, compacted or
// hashed.
var errCompanionTooLarge = errors.New("companion exceeds the ceiling derived from inclusionproof.MaxManifestBytes")

// The producer's limit is on ONE thing: the compact predicate bytes
// (inclusionproof.MaxManifestBytes, enforced by material.checkManifestSize).
// On its way to a bundle that predicate is framed in an in-toto statement,
// base64-encoded into the DSSE payload, and wrapped in an envelope carrying
// signatures, certificate chains and timestamps. A consumer ceiling must be
// the predicate limit CARRIED THROUGH that encoding — reusing the predicate
// number as a byte count in a different unit (the file on disk) refused every
// conforming manifest above roughly three quarters of the limit, because
// base64 alone expands the bytes by 4/3.
const (
	// companionStatementFraming bounds the statement around the predicate:
	// _type, predicateType, and the single tree:materials subject.
	companionStatementFraming = 4096
	// companionEnvelopeSlack bounds everything in the envelope that is not the
	// payload: payloadType, and the signatures with their PEM certificate
	// chains and RFC 3161 tokens (~5 KiB per signer in practice). 1 MiB
	// leaves room for many signers and is noise against the payload.
	companionEnvelopeSlack = 1 << 20
)

// companionCeilings derives the payload and file ceilings for a given compact
// predicate limit. It is the ONLY place the encoding arithmetic lives, so the
// production values and the tests' scaled-down values cannot disagree.
func companionCeilings(predicateLimit int) (payload int, file int64) {
	payload = base64.StdEncoding.EncodedLen(predicateLimit + companionStatementFraming)
	file = int64(payload) + companionEnvelopeSlack
	return payload, file
}

// Companion size ceilings. Package variables (not constants) ONLY so the tests
// can drive the real read/index paths over the limit with kilobytes instead of
// half a gigabyte; production code never assigns them.
var (
	// companionPredicateLimit bounds the raw predicate bytes of an already
	// loaded envelope before they are compacted and hashed: the producer's
	// limit, in the producer's unit.
	companionPredicateLimit = inclusionproof.MaxManifestBytes
	// companionPayloadLimit bounds the envelope payload before base64 decoding;
	// companionFileLimit bounds a companion file on disk (stat, then a
	// LimitReader so a file that grows between stat and read is still caught).
	// Both are derived from the predicate limit through the encoding.
	companionPayloadLimit, companionFileLimit = companionCeilings(inclusionproof.MaxManifestBytes)
)

// readCompanionFile reads a companion file discovered next to a bundle,
// refusing by size before reading. The size is checked from the inode first
// (no bytes read), and the read itself is bounded, so a file that grows after
// the stat cannot exceed the limit either.
func readCompanionFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path came from the sidecar discovery walk
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > companionFileLimit {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", errCompanionTooLarge, path, st.Size(), companionFileLimit)
	}
	data, err := readBounded(f, companionFileLimit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return data, nil
}

// readBounded reads at most limit bytes from r and refuses when r holds more:
// the reader is capped at limit+1 so an overflow is detected by one extra
// byte, never by reading the whole stream.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", errCompanionTooLarge, limit)
	}
	return data, nil
}

// manifestIndex maps a legacy manifest or modern inventory SHA-256 to its body.
// Legacy bodies use compact JSON; modern inventory bytes must stay exact.
//
// KEYED BY CONTENT, deliberately. A manifest is matched to the collection that
// references it by the digest inside that collection's SIGNED predicate — never
// by filename, directory adjacency, or "it was in the same bundle". That is
// what stops an unrelated (or attacker-supplied) manifest sitting alongside the
// real one from being substituted: to be used at all, its bytes must hash to
// the value a signed envelope already committed to.
type manifestIndex map[string][]byte

// indexMaterialManifests collects every material-manifest predicate carried by
// the given envelopes and keys it by content digest.
//
// Envelopes that are not manifests, or that do not decode, are skipped
// silently: this is an opportunistic index built over whatever the verifier
// already loaded, and a bundle containing unrelated envelopes is normal. A
// manifest that is genuinely needed and genuinely missing surfaces later, as a
// "not found" from the consumer that wanted it — which is a distinct, reported
// state rather than a silent pass.
func indexMaterialManifests(envelopes []dsse.Envelope) manifestIndex {
	ix := manifestIndex{}
	for _, env := range envelopes {
		body, digest, ok := manifestPredicateFromEnvelope(env)
		if !ok {
			continue
		}
		ix[digest] = body
	}
	return ix
}

// manifestPredicateFromEnvelope extracts the compact manifest predicate bytes
// and their sha256 from one envelope, reporting false for anything that is not
// a well-formed material manifest.
func manifestPredicateFromEnvelope(env dsse.Envelope) (body []byte, digest string, ok bool) {
	if env.PayloadType != intoto.PayloadType {
		return nil, "", false
	}
	// Bound the work before doing any of it: a payload that cannot hold a
	// manifest within the shared limit is not indexed, whatever it claims to
	// be. Nothing here allocates a second copy of an oversized body.
	if len(env.Payload) > companionPayloadLimit {
		log.Debugf("material manifest index: skipping a %d-byte payload over the companion limit", len(env.Payload))
		return nil, "", false
	}
	payload := env.Payload
	// A DSSE payload is base64 on the wire, but some in-process paths hand back
	// already-decoded bytes. Try the decode and fall back to the raw payload
	// rather than rejecting a valid envelope on encoding alone.
	if decoded, err := base64.StdEncoding.DecodeString(string(env.Payload)); err == nil {
		payload = decoded
	}

	var stmt intoto.Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, "", false
	}
	if stmt.PredicateType == fileinventory.Type {
		if len(stmt.Predicate) > fileinventory.MaxBytes {
			return nil, "", false
		}
		sum := sha256.Sum256(stmt.Predicate)
		return stmt.Predicate, hex.EncodeToString(sum[:]), true
	}
	if stmt.PredicateType != material.ManifestType {
		return nil, "", false
	}
	if len(stmt.Predicate) > companionPredicateLimit {
		log.Debugf("material manifest index: skipping a %d-byte manifest predicate over the companion limit %d", len(stmt.Predicate), companionPredicateLimit)
		return nil, "", false
	}

	// Re-compact before hashing. The producer hashed the compact encoding, and
	// a pretty-printing intermediary anywhere in transit would otherwise change
	// the digest of bytes that are semantically identical.
	var compact bytes.Buffer
	if err := json.Compact(&compact, stmt.Predicate); err != nil {
		return nil, "", false
	}
	b := compact.Bytes()
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), true
}

// sidecarManifests builds an index from sidecars discovered on disk next to a
// bundle. Only entries whose predicate type is the manifest type are read, and
// each is still keyed by its own content digest, so discovery-by-filename
// narrows the candidate set without ever being what authorizes a match.
func sidecarManifests(sidecars []sidecarSummary) manifestIndex {
	ix := manifestIndex{}
	for _, s := range sidecars {
		if s.predicateType != material.ManifestType && s.predicateType != fileinventory.Type {
			continue
		}
		raw, err := readCompanionFile(s.path)
		if err != nil {
			log.Debugf("material manifest sidecar %s: %v", s.path, err)
			continue
		}
		var env dsse.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		body, digest, ok := manifestPredicateFromEnvelope(env)
		if !ok {
			continue
		}
		ix[digest] = body
	}
	return ix
}

// companionPublished reports whether a leaf-less predicate's SIGNED
// manifestUploaded field authorises reading a companion manifest AT ALL. It is
// the single gate every CLI consumer of a companion goes through
// (detachedLeafDigests, expandSubjectsWithInclusionProofs), and it mirrors the
// engine's material.Attestor.ManifestState, which attempts a resolution only in
// ManifestPublished.
//
//	true  — published. Read the companion; failing to is the caller's finding.
//	false — withheld. A SIGNED statement that the leaves were not published.
//	        A companion that happens to match, sitting next to the bundle or
//	        among the loaded envelopes, is NOT evidence against that
//	        statement: the predicate stays leaf-less and the companion is
//	        never opened.
//	nil   — legacy or stripped: the key predates the feature or was removed.
//	        Read as "decide from leaves", never as true — so a leaf-less nil
//	        predicate is leaf-less, full stop, exactly as the engine treats
//	        ManifestLegacyLeafless. (A pre-feature producer never emitted a
//	        manifest reference either, so nil WITH a reference is a stripped
//	        field, and a stripped field must not be promoted to a claim.)
//
// Matching by content digest (manifestIndex) proves a companion IS the
// manifest the predicate named; it says nothing about whether the producer
// asserted it exists. Only the signed value does, which is why the digest
// lookup is never consulted until this returns true.
func companionPublished(uploaded *bool) bool {
	return uploaded != nil && *uploaded
}

// lookup implements the resolver the policy engine and the CLI consumers share.
func (ix manifestIndex) lookup(digest string) ([]byte, bool) {
	if len(ix) == 0 || digest == "" {
		return nil, false
	}
	body, ok := ix[digest]
	return body, ok
}

// sidecarFor returns the parsed, ROOT-VERIFIED sidecar for a manifest digest.
//
// The caller supplies the root it expects (the one the signed collection
// committed to). The sidecar is rebuilt and its recomputed root compared to
// that expectation — comparing the sidecar's own claimed root would prove
// nothing, since the sidecar is the untrusted half of this pair.
func (ix manifestIndex) sidecarFor(digest, wantRoot string) (inclusionproof.Sidecar, bool) {
	body, ok := ix.lookup(digest)
	if !ok {
		return inclusionproof.Sidecar{}, false
	}
	side, err := inclusionproof.ReadSidecar(bytes.NewReader(body))
	if err != nil {
		log.Debugf("material manifest %s: unreadable: %v", digest, err)
		return inclusionproof.Sidecar{}, false
	}
	if _, _, err := side.Reconstruct(); err != nil {
		log.Debugf("material manifest %s: leaves do not rebuild its own root: %v", digest, err)
		return inclusionproof.Sidecar{}, false
	}
	if wantRoot != "" && side.MerkleRoot != wantRoot {
		log.Debugf("material manifest %s rebuilds root %s, not the signed root %s; ignoring", digest, side.MerkleRoot, wantRoot)
		return inclusionproof.Sidecar{}, false
	}
	return side, true
}
