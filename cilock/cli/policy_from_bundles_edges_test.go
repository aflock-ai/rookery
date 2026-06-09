// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/policy"
)

func digestSet(ds ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(ds))
	for _, d := range ds {
		m[d] = struct{}{}
	}
	return m
}

// TestWireProvenanceEdges_DetectsFlow proves that when a consumer step's
// materials include a producer step's product digest, an artifactsFrom edge is
// wired between them (rec #4 auto-detect).
func TestWireProvenanceEdges_DetectsFlow(t *testing.T) {
	const widget = "6f42fdfbd2689cc842513fd88e27161d9b4fc765e5d0e291edc6483a50222720"
	summaries := []bundleSummary{
		{stepName: "build", productDigests: digestSet(widget), materialDigests: digestSet("src111")},
		{stepName: "release", productDigests: digestSet("rel222"), materialDigests: digestSet(widget, "src111")},
	}
	p := &policy.Policy{Steps: map[string]policy.Step{
		"build":   {Name: "build"},
		"release": {Name: "release"},
	}}

	n := wireProvenanceEdges(p, summaries)
	if n != 1 {
		t.Fatalf("expected 1 edge emitted, got %d", n)
	}
	got := p.Steps["release"].ArtifactsFrom
	if len(got) != 1 || got[0] != "build" {
		t.Errorf("release should consume build, got artifactsFrom=%v", got)
	}
	if len(p.Steps["build"].ArtifactsFrom) != 0 {
		t.Errorf("build should have no upstream, got %v", p.Steps["build"].ArtifactsFrom)
	}
}

// TestWireProvenanceEdges_NoOverlapNoEdges proves independent steps (no
// product→material overlap) get no edges.
func TestWireProvenanceEdges_NoOverlapNoEdges(t *testing.T) {
	summaries := []bundleSummary{
		{stepName: "a", productDigests: digestSet("pa"), materialDigests: digestSet("ma")},
		{stepName: "b", productDigests: digestSet("pb"), materialDigests: digestSet("mb")},
	}
	p := &policy.Policy{Steps: map[string]policy.Step{
		"a": {Name: "a"},
		"b": {Name: "b"},
	}}
	if n := wireProvenanceEdges(p, summaries); n != 0 {
		t.Fatalf("independent steps should produce no edges, got %d", n)
	}
}

// TestWireProvenanceEdges_NoSelfEdge proves a step consuming its own product
// (its product digest also appears in its materials) does not get a self-edge.
func TestWireProvenanceEdges_NoSelfEdge(t *testing.T) {
	const d = "deadbeef"
	summaries := []bundleSummary{
		{stepName: "solo", productDigests: digestSet(d), materialDigests: digestSet(d)},
	}
	p := &policy.Policy{Steps: map[string]policy.Step{"solo": {Name: "solo"}}}
	if n := wireProvenanceEdges(p, summaries); n != 0 {
		t.Fatalf("a step must not reference itself, got %d edges", n)
	}
	if len(p.Steps["solo"].ArtifactsFrom) != 0 {
		t.Errorf("solo should have no self-edge, got %v", p.Steps["solo"].ArtifactsFrom)
	}
}

// TestWarnMissingProvenanceEdges_FiresOnMultiStepNoEdge proves the warning
// fires only for a multi-step policy with zero cross-step edges (rec #4
// must-have).
func TestWarnMissingProvenanceEdges_FiresOnMultiStepNoEdge(t *testing.T) {
	p := &policy.Policy{Steps: map[string]policy.Step{"a": {}, "b": {}}}

	var buf bytes.Buffer
	warnMissingProvenanceEdges(&buf, p, 0)
	out := buf.String()
	if !strings.Contains(out, "no cross-step provenance edges") {
		t.Errorf("expected the missing-edges warning, got: %q", out)
	}
	if !strings.Contains(out, "artifactsFrom") {
		t.Errorf("warning should point at artifactsFrom inline-leaf chaining, got: %q", out)
	}

	// With an edge emitted, no warning.
	buf.Reset()
	warnMissingProvenanceEdges(&buf, p, 1)
	if buf.Len() != 0 {
		t.Errorf("no warning expected when an edge was emitted, got: %q", buf.String())
	}

	// Single-step policy: no warning regardless.
	buf.Reset()
	warnMissingProvenanceEdges(&buf, &policy.Policy{Steps: map[string]policy.Step{"only": {}}}, 0)
	if buf.Len() != 0 {
		t.Errorf("single-step policy should not warn, got: %q", buf.String())
	}
}

// TestBuildStarterPolicy_WiresEdgesAndQuietsWarning is an integration check on
// buildStarterPolicy: when a consumer step's materials include a producer's
// product, the edge is wired AND the missing-edge warning is suppressed.
func TestBuildStarterPolicy_WiresEdgesAndQuietsWarning(t *testing.T) {
	const widget = "6f42fdfbd2689cc842513fd88e27161d9b4fc765e5d0e291edc6483a50222720"
	summaries := []bundleSummary{
		{stepName: "build", outerPredicateType: collectionPredicateURI, productDigests: digestSet(widget), materialDigests: digestSet()},
		{stepName: "release", outerPredicateType: collectionPredicateURI, productDigests: digestSet(), materialDigests: digestSet(widget)},
	}
	var stderr bytes.Buffer
	p, err := buildStarterPolicy(&stderr, summaries, map[string][]byte{}, time.Hour)
	if err != nil {
		t.Fatalf("buildStarterPolicy: %v", err)
	}
	if got := p.Steps["release"].ArtifactsFrom; len(got) != 1 || got[0] != "build" {
		t.Errorf("release should consume build, got %v", got)
	}
	if strings.Contains(stderr.String(), "no cross-step provenance edges") {
		t.Errorf("warning should be suppressed once an edge is wired, got: %q", stderr.String())
	}
}
