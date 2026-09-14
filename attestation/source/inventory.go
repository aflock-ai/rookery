package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
)

// MaxInventoryCandidates bounds inspection, not the number of valid wrappers a
// store may hold for one content-addressed inventory.
const MaxInventoryCandidates = 16

// MaxInventoryEnvelopeBytes carries the 64 MiB predicate cap through in-toto
// framing (4 KiB), base64 expansion, and DSSE signature/certificate slack (1 MiB).
const MaxInventoryEnvelopeBytes int64 = ((fileinventory.MaxBytes + 4096 + 2) / 3 * 4) + (1 << 20)

func validInventoryDigest(digest string) bool {
	if len(digest) != 64 || digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

// InventoryPredicate checks a candidate's exact bytes and digest subject. It
// grants no signer authority; callers must still verify the parent reference,
// schema, purpose, root, size and path count before exposing file data.
func InventoryPredicate(env dsse.Envelope, digest string) ([]byte, bool) {
	stmt, ok := inventoryStatement(env, digest)
	return stmt.Predicate, ok
}

func inventoryStatement(env dsse.Envelope, digest string) (intoto.Statement, bool) {
	if env.PayloadType != intoto.PayloadType || len(env.Payload) > fileinventory.MaxBytes+4096 {
		return intoto.Statement{}, false
	}
	var stmt intoto.Statement
	if err := json.Unmarshal(env.Payload, &stmt); err != nil || stmt.PredicateType != fileinventory.Type || len(stmt.Predicate) > fileinventory.MaxBytes {
		return intoto.Statement{}, false
	}
	sum := sha256.Sum256(stmt.Predicate)
	if hex.EncodeToString(sum[:]) != digest {
		return intoto.Statement{}, false
	}
	for _, subject := range stmt.Subject {
		if subject.Digest["sha256"] == digest {
			return stmt, true
		}
	}
	return intoto.Statement{}, false
}

// Inventory lookup is content-addressed, not an exhaustive predicate walk. It
// never consults or updates either shared seen-set: another query cannot consume
// the only available companion. The discovery ID list retains the client's
// existing response cap; envelopes are fetched sequentially with a tighter cap.
func (s *ArchivistaSource) searchInventory(ctx context.Context, digest string) ([]StatementEnvelope, error) {
	ids, err := s.client.SearchGitoidsByPredicate(ctx, archivista.SearchGitoidByPredicateVariables{
		PredicateTypes: []string{fileinventory.Type}, SubjectDigests: []string{digest},
	})
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var lastErr error
	for _, id := range ids[:min(len(ids), MaxInventoryCandidates)] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		env, err := s.client.DownloadBounded(ctx, id, MaxInventoryEnvelopeBytes)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			lastErr = err
			continue
		}
		if stmt, ok := inventoryStatement(env, digest); ok {
			return []StatementEnvelope{{Envelope: env, Statement: stmt, Reference: id, Attestor: attestation.NewRawAttestation(fileinventory.Type, stmt.Predicate)}}, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("inventory %s: no exact match within %d downloads: %w", digest, min(len(ids), MaxInventoryCandidates), lastErr)
	}
	return nil, fmt.Errorf("inventory %s: no exact match within %d downloads", digest, min(len(ids), MaxInventoryCandidates))
}

// InventoryLookup uses the existing, caller-scoped source, never a URL from
// evidence. Companion signatures grant no authority: the consumer must verify
// the exact predicate against the signed parent's reference and tree commitment.
// A verification gets at most 128 distinct lookups and 64 MiB of cached bodies.
// ArchivistaSource specializes this exact request to bounded, stop-at-first-match
// downloads. Other Sourcers retain their own fetch limits. We independently
// inspect at most 16 candidates and recheck bytes even on the specialized path.
func InventoryLookup(ctx context.Context, src Sourcer) func(string) ([]byte, bool) {
	cache := map[string][]byte{}
	retained := 0
	return func(digest string) ([]byte, bool) {
		if body, seen := cache[digest]; seen {
			return body, body != nil
		}
		if src == nil || len(cache) >= 128 || !validInventoryDigest(digest) {
			return nil, false
		}
		cache[digest] = nil
		candidates, err := src.SearchByPredicateType(ctx, []string{fileinventory.Type}, []string{digest})
		if err != nil {
			log.Debugf("file inventory lookup %s: %v", digest, err)
			return nil, false
		}
		for _, candidate := range candidates[:min(len(candidates), MaxInventoryCandidates)] {
			if body, ok := InventoryPredicate(candidate.Envelope, digest); ok {
				if len(body) > fileinventory.MaxBytes-retained {
					log.Debugf("file inventory lookup %s: predicate cache byte limit exceeded", digest)
					return nil, false
				}
				cache[digest] = body
				retained += len(body)
				return body, true
			}
		}
		log.Debugf("file inventory lookup %s: no exact match among %d inspected candidates (limit %d)", digest, min(len(candidates), MaxInventoryCandidates), MaxInventoryCandidates)
		return nil, false
	}
}
