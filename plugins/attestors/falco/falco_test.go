// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package falco

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real Falco JSON output (3 events, 3 distinct rules, mixed priorities).
// Drawn from upstream Falco's docs/concepts/outputs/formatting example shape.
const sampleEvents = `{"time":"2026-05-23T10:00:01.000Z","rule":"Terminal shell in container","priority":"Notice","source":"syscall","hostname":"node-1","output":"A shell was used as the entrypoint","output_fields":{"proc.name":"bash","container.id":"abc123","container.image.repository":"nginx"},"tags":["container","shell","mitre_execution"]}
{"time":"2026-05-23T10:00:05.000Z","rule":"Write below etc","priority":"Error","source":"syscall","hostname":"node-1","output":"File below /etc opened for writing","output_fields":{"proc.name":"vi","fd.name":"/etc/passwd"},"tags":["filesystem","mitre_persistence"]}
{"time":"2026-05-23T10:00:09.000Z","rule":"Terminal shell in container","priority":"Notice","source":"syscall","hostname":"node-2","output":"A shell was used as the entrypoint","output_fields":{"proc.name":"sh","container.id":"def456"}}
`

func TestParseEvents(t *testing.T) {
	events, err := parseEvents([]byte(sampleEvents))
	require.NoError(t, err)
	require.Len(t, events, 3)

	assert.Equal(t, "Terminal shell in container", events[0].Rule)
	assert.Equal(t, "Notice", events[0].Priority)
	assert.Equal(t, "node-1", events[0].Hostname)
	assert.Contains(t, events[0].OutputFields, "container.id")

	assert.Equal(t, "Write below etc", events[1].Rule)
	assert.Equal(t, "Error", events[1].Priority)

	assert.Equal(t, "node-2", events[2].Hostname)
}

func TestParseEventsSkipsBlanksAndMalformed(t *testing.T) {
	input := `
{"rule":"r1","priority":"Notice"}

not valid json
{"rule":"r2","priority":"Critical"}
{}
`
	events, err := parseEvents([]byte(input))
	require.NoError(t, err)
	// {} has no Rule so it's dropped; "not valid json" is malformed → skipped
	require.Len(t, events, 2)
	assert.Equal(t, "r1", events[0].Rule)
	assert.Equal(t, "r2", events[1].Rule)
}

func TestPopulateSummary(t *testing.T) {
	events, err := parseEvents([]byte(sampleEvents))
	require.NoError(t, err)

	a := &Attestor{Events: events}
	a.populateSummary()

	assert.Equal(t, 3, a.Summary.TotalEvents)
	assert.Equal(t, 2, a.Summary.Priorities.Notice)
	assert.Equal(t, 1, a.Summary.Priorities.Error)
	assert.Equal(t, 3, a.Summary.Priorities.Total())
	assert.Equal(t, 2, a.Summary.DistinctRules)
	assert.Equal(t, 2, a.Summary.DistinctHosts)
	assert.Equal(t, "2026-05-23T10:00:01.000Z", a.Summary.WindowStart)
	assert.Equal(t, "2026-05-23T10:00:09.000Z", a.Summary.WindowEnd)

	// One rule fired twice (Terminal shell), one once (Write below etc).
	require.Len(t, a.Summary.RuleHits, 2)
	hits := map[string]RuleHit{}
	for _, h := range a.Summary.RuleHits {
		hits[h.Rule] = h
	}
	assert.Equal(t, 2, hits["Terminal shell in container"].Count)
	assert.Equal(t, 1, hits["Write below etc"].Count)
	assert.Equal(t, "Error", hits["Write below etc"].HighestPriority)
}

func TestPriorityRankAndField(t *testing.T) {
	assert.Equal(t, 6, priorityRank("Critical"))
	assert.Equal(t, 6, priorityRank("critical"))
	assert.Equal(t, 2, priorityRank("info"))
	assert.Equal(t, 0, priorityRank("not-a-priority"))

	var pc PriorityCounts
	*priorityField(&pc, "Critical") = 5
	*priorityField(&pc, "Info") = 7
	assert.Equal(t, 5, pc.Critical)
	assert.Equal(t, 7, pc.Informational)
	assert.Nil(t, priorityField(&pc, "garbage"))
}

func TestLooksLikeFalco(t *testing.T) {
	assert.True(t, looksLikeFalco([]byte(`{"rule":"x","priority":"Notice"}`)))
	assert.True(t, looksLikeFalco([]byte(sampleEvents)))
	assert.False(t, looksLikeFalco([]byte(`{"foo":"bar"}`)))
	assert.False(t, looksLikeFalco([]byte(`[]`)))
}

func TestAttestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "falco-events.jsonl")
	require.NoError(t, os.WriteFile(reportPath, []byte(sampleEvents), 0o600))

	// Build an attestation context with the file as a product (mime + digest).
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	digest, err := cryptoutil.CalculateDigestSetFromFile(reportPath, hashes)
	require.NoError(t, err)
	require.NotNil(t, digest)

	a := New()
	a.hashes = hashes

	ctx := newTestContextWithProduct(t, reportPath, digest, "application/x-ndjson")
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, reportPath, a.ReportFile)
	assert.Equal(t, 3, a.Summary.TotalEvents)
	assert.Equal(t, 2, a.Summary.DistinctRules)
	subs := a.Subjects()
	assert.NotEmpty(t, subs)
	// Report-file subject is keyed on the path, value is the product digest.
	assert.Equal(t, digest, subs["report_file:"+reportPath])
}

func TestAttestNoProducts(t *testing.T) {
	a := New()
	ctx, err := attestation.NewContext("step", nil)
	require.NoError(t, err)
	err = a.Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no products to attest")
}

func TestAttestProductIsNotFalco(t *testing.T) {
	dir := t.TempDir()
	notFalco := filepath.Join(dir, "sbom.cdx.json")
	require.NoError(t, os.WriteFile(notFalco, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`), 0o600))

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	digest, err := cryptoutil.CalculateDigestSetFromFile(notFalco, hashes)
	require.NoError(t, err)

	a := New()
	a.hashes = hashes
	ctx := newTestContextWithProduct(t, notFalco, digest, "application/json")
	err = a.Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no falco event file found")
}

func TestSchemaRoundTrip(t *testing.T) {
	a := New()
	schema := a.Schema()
	require.NotNil(t, schema)
	// Schema must at least mention our top-level summary field.
	b, err := json.Marshal(schema)
	require.NoError(t, err)
	assert.Contains(t, string(b), "summary")
	assert.Contains(t, string(b), "events")
}

func TestRegistered(t *testing.T) {
	factory, ok := attestation.FactoryByType(Type)
	require.True(t, ok, "falco attestor must be registered by init()")
	a := factory()
	require.NotNil(t, a)
	assert.Equal(t, Name, a.Name())
	assert.Equal(t, Type, a.Type())
	assert.Equal(t, RunType, a.RunType())
}

// --- helpers ---

// newTestContextWithProduct constructs an AttestationContext containing a
// single product (path → MimeType+Digest). We can't easily call
// ctx.addProducts directly (it's unexported), so we use the public
// AttestationContext API: register a fake "producer" attestor, run it, then
// return the context with the product table populated.
func newTestContextWithProduct(t *testing.T, path string, digest cryptoutil.DigestSet, mime string) *attestation.AttestationContext {
	t.Helper()
	producer := &fakeProducer{product: attestation.Product{
		MimeType: mime,
		Digest:   digest,
	}, path: path}
	ctx, err := attestation.NewContext("test", []attestation.Attestor{producer})
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

type fakeProducer struct {
	product attestation.Product
	path    string
}

func (f *fakeProducer) Name() string                                   { return "fake-producer" }
func (f *fakeProducer) Type() string                                   { return "https://example/fake/v0.1" }
func (f *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (f *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fakeProducer) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(f) }
func (f *fakeProducer) Products() map[string]attestation.Product {
	return map[string]attestation.Product{f.path: f.product}
}
