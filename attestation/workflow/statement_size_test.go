// jade:ring local
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

package workflow

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// The size limit exists because one attestor (command-run, since #9276) put
// the whole `go test -json` stream into the collection: 45.6 MB and 47.1 MB
// per envelope, measured 2026-09-15. The platform parses every envelope that
// matches a commit three times, uncached above 512 KiB, at about 0.4 s per
// MB against a 25 s edge budget. The limit is measured on the exact bytes that
// are signed — the in-toto statement JSON — because that is what the platform
// parses, and it is checked BEFORE dsse.Sign so an oversized statement is
// never signed, written or uploaded.

// bulkAttestor is a stand-in for any attestor whose predicate is large. Its
// predicate is a single JSON string so the statement size is controlled by
// the caller to the byte.
type bulkAttestor struct {
	name    string
	typeURI string
	body    string
}

func (b *bulkAttestor) Name() string                                 { return b.name }
func (b *bulkAttestor) Type() string                                 { return b.typeURI }
func (b *bulkAttestor) RunType() attestation.RunType                 { return attestation.PostProductRunType }
func (b *bulkAttestor) Attest(*attestation.AttestationContext) error { return nil }
func (b *bulkAttestor) Schema() *jsonschema.Schema                   { return nil }
func (b *bulkAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"body": b.body})
}

func sizeTestSigner(t *testing.T) cryptoutil.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
	require.NoError(t, err)
	return signer
}

// statementBytes runs the step once with no limit and returns the exact size
// of the collection statement that would be signed, so the limit tests can
// sit one byte on either side of it instead of guessing at framing.
func statementBytes(t *testing.T, signer cryptoutil.Signer, attestors ...attestation.Attestor) int {
	t.Helper()
	result, err := Run("size-probe", RunWithSigners(signer), RunWithAttestors(attestors))
	require.NoError(t, err)
	require.NotEmpty(t, result.SignedEnvelope.Payload)
	return len(result.SignedEnvelope.Payload)
}

func TestMaxStatementBytesRefusesOneByteOverAndSignsAtTheLimit(t *testing.T) {
	signer := sizeTestSigner(t)
	big := &bulkAttestor{name: "bulk", typeURI: "https://example.test/attestations/bulk/v0.1", body: strings.Repeat("x", 4096)}
	small := &bulkAttestor{name: "tiny", typeURI: "https://example.test/attestations/tiny/v0.1", body: "y"}
	exact := statementBytes(t, signer, big, small)
	// The collection carries RFC 3339 nanosecond timestamps whose trailing
	// zeros are trimmed, so two runs of the same step differ by a few bytes.
	// The run-level tests sit a margin either side of the probe; the exact
	// at-the-limit boundary is pinned on the pure check in TestCheckStatementSize.
	const jitter = 64

	// Just under the limit: signs.
	result, err := Run("size-probe", RunWithSigners(signer), RunWithAttestors([]attestation.Attestor{big, small}), RunWithMaxStatementBytes(exact+jitter))
	require.NoError(t, err, "a statement under the limit must sign")
	require.Len(t, result.SignedEnvelope.Signatures, 1)

	// Just over the limit: refused, unsigned, with the numbers and the breakdown.
	result, err = Run("size-probe", RunWithSigners(signer), RunWithAttestors([]attestation.Attestor{big, small}), RunWithMaxStatementBytes(exact-jitter))
	require.Error(t, err)
	var tooLarge *StatementTooLargeError
	require.True(t, errors.As(err, &tooLarge), "the refusal must be typed so the CLI can format remedies: %v", err)
	require.InDelta(t, exact, tooLarge.Bytes, jitter/2, "the error must name the measured statement size")
	require.Equal(t, exact-jitter, tooLarge.Limit, "the error must name the limit")
	require.Equal(t, attestation.CollectionType, tooLarge.PredicateType)
	require.Empty(t, result.SignedEnvelope.Signatures, "an oversized statement must never be signed")
	require.Empty(t, result.SignedEnvelope.Payload)

	require.Len(t, tooLarge.Contributors, 2)
	require.Equal(t, big.typeURI, tooLarge.Contributors[0].Type, "largest contributor first")
	require.Equal(t, small.typeURI, tooLarge.Contributors[1].Type)
	require.Greater(t, tooLarge.Contributors[0].Bytes, 4096)
	require.Less(t, tooLarge.Contributors[1].Bytes, 512)

	msg := err.Error()
	require.Contains(t, msg, "attestation too large")
	require.Contains(t, msg, big.typeURI)
}

func TestMaxStatementBytesZeroIsUnlimited(t *testing.T) {
	signer := sizeTestSigner(t)
	big := &bulkAttestor{name: "bulk", typeURI: "https://example.test/attestations/bulk/v0.1", body: strings.Repeat("x", 1<<16)}
	result, err := Run("size-probe", RunWithSigners(signer), RunWithAttestors([]attestation.Attestor{big}), RunWithMaxStatementBytes(0))
	require.NoError(t, err)
	require.Len(t, result.SignedEnvelope.Signatures, 1)

	// And the option's absence is the same as zero: library callers that
	// never heard of the limit (cilock-action, verify's inner Run) keep
	// signing whatever they built. The CLI default lives in the CLI.
	result, err = Run("size-probe", RunWithSigners(signer), RunWithAttestors([]attestation.Attestor{big}))
	require.NoError(t, err)
	require.Len(t, result.SignedEnvelope.Signatures, 1)
}

// An attestor that exports its own envelope is measured on its own statement,
// not the collection's: the exported statement is what the platform opens
// when it searches by the commit the parent subjects carry.
type exportedBulkAttestor struct {
	bulkAttestor
}

func (e *exportedBulkAttestor) Export() bool                              { return true }
func (e *exportedBulkAttestor) Subjects() map[string]cryptoutil.DigestSet { return nil }

func TestMaxStatementBytesAppliesToExportedEnvelopes(t *testing.T) {
	signer := sizeTestSigner(t)
	exported := &exportedBulkAttestor{bulkAttestor{name: "sbomish", typeURI: "https://example.test/attestations/exported/v0.1", body: strings.Repeat("x", 8192)}}
	results, err := RunWithExports("size-probe", RunWithSigners(signer), RunWithAttestors([]attestation.Attestor{exported}), RunWithMaxStatementBytes(4096))
	require.Error(t, err)
	var tooLarge *StatementTooLargeError
	require.True(t, errors.As(err, &tooLarge), "%v", err)
	require.Equal(t, exported.typeURI, tooLarge.PredicateType)
	require.Len(t, tooLarge.Contributors, 1, "a single-predicate statement has one contributor")
	require.Equal(t, exported.typeURI, tooLarge.Contributors[0].Type)
	for _, r := range results {
		require.Empty(t, r.SignedEnvelope.Signatures, "nothing signed once a statement is refused")
	}
}

// Companions are exempt. They are keyed by their tree root and deliberately
// unreachable from a commit-keyed lookup (see CompanionExporter), so the
// platform never opens one during a push evaluation, and each kind carries
// its own ceiling (fileinventory.MaxBytes, 64 MiB; the material manifest's
// inclusionproof.MaxManifestBytes, 512 MiB) with its own upload consent.
// Applying a 4 MiB ceiling to them would break --material-manifest for any
// repository with more than a few thousand files.
type inventoryCompanion struct {
	body string
}

func (c *inventoryCompanion) Name() string                                 { return "material-inventory" }
func (c *inventoryCompanion) Type() string                                 { return fileinventory.Type }
func (c *inventoryCompanion) RunType() attestation.RunType                 { return attestation.MaterialRunType }
func (c *inventoryCompanion) Attest(*attestation.AttestationContext) error { return nil }
func (c *inventoryCompanion) Schema() *jsonschema.Schema                   { return nil }
func (c *inventoryCompanion) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"schema": fileinventory.Type, "body": c.body})
}

type companionParent struct {
	bulkAttestor
	companions []attestation.Attestor
}

func (p *companionParent) Companions() []attestation.Attestor { return p.companions }

func TestMaxStatementBytesExemptsCompanions(t *testing.T) {
	signer := sizeTestSigner(t)
	inventory := &inventoryCompanion{body: strings.Repeat("x", 1<<16)}
	manifest := &bulkAttestor{name: "manifest", typeURI: "https://example.test/attestations/material-manifest/v0.1", body: strings.Repeat("x", 1<<16)}
	parent := &companionParent{
		bulkAttestor: bulkAttestor{name: "material", typeURI: "https://example.test/attestations/material/v0.3", body: "compact"},
		companions:   []attestation.Attestor{inventory, manifest},
	}
	results, err := RunWithExports("size-probe", RunWithSigners(signer), RunWithAttestors([]attestation.Attestor{parent}), RunWithMaxStatementBytes(4096))
	require.NoError(t, err, "64 KiB companions must not trip a 4 KiB statement limit")
	require.Len(t, results, 3, "two companions + collection")
	for i, r := range results {
		require.Len(t, r.SignedEnvelope.Signatures, 1, "result %d is still signed", i)
	}
	require.Greater(t, len(results[0].SignedEnvelope.Payload), 4096, "the companion really was over the limit")

	// The exemption is the companion path, nothing wider: the same bytes as
	// the parent's own predicate are refused.
	inline := &bulkAttestor{name: "material", typeURI: "https://example.test/attestations/material/v0.3", body: strings.Repeat("x", 1<<16)}
	_, err = RunWithExports("size-probe", RunWithSigners(signer), RunWithAttestors([]attestation.Attestor{inline}), RunWithMaxStatementBytes(4096))
	var tooLarge *StatementTooLargeError
	require.True(t, errors.As(err, &tooLarge), "an inline predicate over the limit is refused: %v", err)
}

// The breakdown is computed from the statement bytes, so `cilock sign` can
// explain an oversized statement it was handed as a file with the same code
// path `cilock run` uses for one it built.
func TestStatementContributorsRanksTheLargestFive(t *testing.T) {
	type entry struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
	}
	sizes := map[string]int{"a": 10, "b": 700, "c": 30, "d": 5000, "e": 200, "f": 90, "g": 400}
	names := []string{"a", "b", "c", "d", "e", "f", "g"}
	entries := make([]entry, 0, len(names))
	for _, name := range names {
		body, err := json.Marshal(map[string]string{"x": strings.Repeat("z", sizes[name])})
		require.NoError(t, err)
		entries = append(entries, entry{Type: "https://example.test/" + name, Attestation: body})
	}
	predicate, err := json.Marshal(map[string]any{"name": "step", "attestations": entries})
	require.NoError(t, err)
	stmt, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": attestation.CollectionType,
		"subject":       []any{},
		"predicate":     json.RawMessage(predicate),
	})
	require.NoError(t, err)

	got := StatementContributors(stmt)
	require.Len(t, got, MaxStatementContributors)
	require.Equal(t, 5, MaxStatementContributors)
	order := make([]string, 0, len(got))
	for _, c := range got {
		order = append(order, strings.TrimPrefix(c.Type, "https://example.test/"))
	}
	require.Equal(t, []string{"d", "b", "g", "e", "f"}, order, "largest first, smallest two dropped")
	require.Greater(t, got[0].Bytes, 5000)
	require.Less(t, got[0].Bytes, 5100, "an entry is measured as its own JSON, not the whole statement")

	// A statement whose predicate is not a collection is one contributor:
	// the predicate itself.
	single, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://example.test/single",
		"subject":       []any{},
		"predicate":     map[string]string{"x": strings.Repeat("z", 1000)},
	})
	require.NoError(t, err)
	got = StatementContributors(single)
	require.Len(t, got, 1)
	require.Equal(t, "https://example.test/single", got[0].Type)
	require.Greater(t, got[0].Bytes, 1000)

	// Bytes that are not a statement at all still produce an answer, so the
	// refusal never hides behind a parse error.
	require.Empty(t, StatementContributors([]byte("not json")))
}

func TestCheckStatementSize(t *testing.T) {
	stmt := []byte(strings.Repeat("s", 100))
	require.NoError(t, CheckStatementSize(stmt, "https://example.test/t", 100), "at the limit passes")
	require.NoError(t, CheckStatementSize(stmt, "https://example.test/t", 0), "zero is unlimited")
	require.NoError(t, CheckStatementSize(stmt, "https://example.test/t", -1), "negative is unlimited too; the CLI rejects it before it gets here")
	err := CheckStatementSize(stmt, "https://example.test/t", 99)
	var tooLarge *StatementTooLargeError
	require.True(t, errors.As(err, &tooLarge))
	require.Equal(t, 100, tooLarge.Bytes)
	require.Equal(t, 99, tooLarge.Limit)
}
