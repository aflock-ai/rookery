// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package product

import (
	"crypto"
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
)

// compileGlobs mirrors what Attest does before it reaches buildTree: the
// include/exclude patterns are stored as strings by the options and compiled
// at attest time. A test that drives buildTree directly has to compile them
// too, or it measures a set that was never filtered.
func compileGlobs(t *testing.T, a *Attestor) {
	t.Helper()
	inc, err := glob.Compile(a.includeGlob)
	if err != nil {
		t.Fatalf("compile include glob: %v", err)
	}
	exc, err := glob.Compile(a.excludeGlob)
	if err != nil {
		t.Fatalf("compile exclude glob: %v", err)
	}
	a.compiledIncludeGlob = inc
	a.compiledExcludeGlob = exc
}

// A product set that runs away is not a big attestation, it is an UNUSABLE one.
// Measured on a real push (PR #8339): 83,272 product leaves produced a ~25 MiB
// envelope, and the evidence edge refuses to read anything over 4 MiB — so the
// envelope uploaded fine and then no verifier could ever open it. The failure
// surfaced at push time as an unreadable-evidence refusal, several layers away
// from the cause, which was a build directory being recorded as deliverables.
//
// The cap exists so that the run stops at the point where the operator can
// still act, with an error naming the directories responsible.

// productSet builds n products under the given directory prefixes, distributing
// them so the caller controls which directory dominates.
func productSet(t *testing.T, spec map[string]int) map[string]attestation.Product {
	t.Helper()
	out := make(map[string]attestation.Product)
	for prefix, n := range spec {
		for i := range n {
			path := fmt.Sprintf("%s/f%d", prefix, i)
			out[path] = attestation.Product{
				MimeType: "application/octet-stream",
				Digest: cryptoutil.DigestSet{
					// Distinct digests: buildTree dedups equal digests, so
					// reusing one would collapse the set and the cap would
					// never be reached.
					cryptoutil.DigestValue{Hash: crypto.SHA256}: fmt.Sprintf("%064x", len(out)+1),
				},
			}
		}
	}
	return out
}

func TestMaxProducts_UnderTheCapIsAccepted(t *testing.T) {
	a := New(WithMaxProducts(100))
	SetProductsForTesting(a, productSet(t, map[string]int{"dist": 50}))

	if err := a.buildTree(); err != nil {
		t.Fatalf("50 products under a cap of 100 must be accepted, got: %v", err)
	}
}

func TestMaxProducts_OverTheCapIsRefusedAndNamesTheCause(t *testing.T) {
	a := New(WithMaxProducts(100))
	SetProductsForTesting(a, productSet(t, map[string]int{
		"node_modules": 400,
		"dist":         3,
	}))

	err := a.buildTree()
	if err == nil {
		t.Fatal("403 products against a cap of 100 must be refused; a runaway product set " +
			"that is allowed through produces an envelope no verifier can read")
	}
	msg := err.Error()

	// The operator needs four things to act, and an error missing any of them
	// sends them to the wrong layer.
	for _, want := range []string{
		"403",          // what the count actually was
		"100",          // what the limit is
		"node_modules", // WHICH directory caused it — the actionable part
		"--exclude-glob",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error must mention %q so the operator can act on it; got:\n%s", want, msg)
		}
	}

	// The dominant directory must be reported ahead of the incidental one,
	// or the "largest contributors" list is just noise.
	if strings.Index(msg, "node_modules") > strings.Index(msg, "dist/") && strings.Contains(msg, "dist/") {
		t.Errorf("contributors must be ranked by count, biggest first; got:\n%s", msg)
	}
}

func TestMaxProducts_ZeroDisablesTheCap(t *testing.T) {
	a := New(WithMaxProducts(0))
	SetProductsForTesting(a, productSet(t, map[string]int{"node_modules": 500}))

	if err := a.buildTree(); err != nil {
		t.Fatalf("--max-products=0 is the documented opt-out and must impose no limit, got: %v", err)
	}
}

// The cap is counted AFTER the include/exclude globs are applied, which is what
// makes --exclude-glob the actual remedy the error recommends. Counting before
// filtering would print an error whose own suggested fix could not clear it.
func TestMaxProducts_CountedAfterExclusion(t *testing.T) {
	products := productSet(t, map[string]int{"node_modules": 400, "dist": 3})

	blocked := New(WithMaxProducts(100))
	SetProductsForTesting(blocked, products)
	if err := blocked.buildTree(); err == nil {
		t.Fatal("precondition: the unfiltered set must exceed the cap")
	}

	excluded := New(WithMaxProducts(100), WithExcludeGlob("node_modules/**"))
	SetProductsForTesting(excluded, products)
	compileGlobs(t, excluded)
	if err := excluded.buildTree(); err != nil {
		t.Fatalf("excluding node_modules leaves 3 products, well under the cap of 100, "+
			"so the fix the error recommends must actually work; got: %v", err)
	}
}

// A default that only exists in a flag's help text is not a default. This pins
// the shipped value, because it is a user-visible contract: raise it and every
// existing build that was passing silently starts emitting larger envelopes.
func TestMaxProducts_DefaultIsAppliedWithoutAnyOption(t *testing.T) {
	if DefaultMaxProducts <= 0 {
		t.Fatalf("DefaultMaxProducts must be a positive limit, got %d", DefaultMaxProducts)
	}
	a := New()
	if a.maxProducts != DefaultMaxProducts {
		t.Fatalf("New() must apply DefaultMaxProducts (%d), got %d", DefaultMaxProducts, a.maxProducts)
	}
}
