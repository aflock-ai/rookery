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

package cli

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// VerifyVerdict is the machine-readable result of a passing `cilock verify`,
// emitted as a single JSON object on stdout under --format json. It answers the
// question a green verify otherwise leaves implicit: WHICH artifact bound, and
// to WHICH step's subject. An agent gating a release can branch on `passed`
// without parsing logr prose (though the exit code remains the canonical gate).
type VerifyVerdict struct {
	Passed bool `json:"passed"`
	// Step is the (first) policy step whose collection passed and bound the
	// supplied artifact. Empty when no supplied artifact digest matched a
	// passing step's subject (e.g. the policy passed on a subject the operator
	// did not name on the command line).
	Step string `json:"step,omitempty"`
	// MatchedSubject is the sha256 digest (sha256:<hex>) of the supplied
	// artifact that bound, paired with the observed subject name it matched.
	MatchedSubject string `json:"matchedSubject,omitempty"`
	// ObservedSubjectName is the in-toto subject name in the passing
	// collection that the supplied digest bound to.
	ObservedSubjectName string `json:"observedSubjectName,omitempty"`
}

// subjectBinding records one supplied-artifact → passing-step binding for the
// human + JSON verdict.
type subjectBinding struct {
	digestHex   string // raw sha256 hex of the supplied artifact
	step        string // passing step whose collection it bound to
	subjectName string // observed subject name, or product/material leaf path
	viaLeaf     bool   // true when bound as a root-verified Merkle leaf, not a top-level subject
}

// suppliedSHA256 extracts the raw sha256 hex from a DigestSet, if present. The
// supplied-artifact and --subjects digest sets are sha256 by construction, so
// this is the digest the operator asked cilock to bind.
func suppliedSHA256(ds cryptoutil.DigestSet) string {
	if h, ok := ds[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}]; ok {
		return h
	}
	return ""
}

// suppliedSet returns the non-empty supplied digests as a lookup set.
func suppliedSet(supplied []string) map[string]struct{} {
	want := make(map[string]struct{}, len(supplied))
	for _, h := range supplied {
		if h != "" {
			want[h] = struct{}{}
		}
	}
	return want
}

// matchedBindings correlates the operator-supplied artifact digests against each
// passing step collection and returns one binding per supplied digest that
// PROVABLY bound — either to a top-level subject, or to a product/material Merkle
// leaf whose inline leaves were verified to reconstruct the signed root. It does
// NOT bind a digest merely because some step passed: a supplied artifact that
// matches neither a subject nor a verified leaf yields no binding (the previous
// behaviour falsely reported any passing step as an inclusion-proof binding).
// Bindings are sorted by step then digest for deterministic output.
func matchedBindings(supplied []string, stepResults map[string]policy.StepResult) []subjectBinding {
	want := suppliedSet(supplied)
	if len(want) == 0 {
		return nil
	}
	var out []subjectBinding
	seen := make(map[string]struct{}, len(want))
	for step, res := range stepResults {
		for i := range res.Passed {
			out = appendCollectionBindings(out, seen, want, step, res.Passed[i])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].step != out[j].step {
			return out[i].step < out[j].step
		}
		return out[i].digestHex < out[j].digestHex
	})
	return out
}

// appendCollectionBindings adds, to out, every supplied-digest binding found in
// one passing collection: first its top-level subjects, then — only after the
// collection's inline Merkle leaves are verified to reconstruct the signed root
// (VerifyInlineLeaves) — its product/material leaf digests. The root check is
// what makes a leaf binding a real inclusion proof rather than a guess: a leaf
// set that does not fold to the signed root is ignored, never bound.
func appendCollectionBindings(out []subjectBinding, seen, want map[string]struct{}, step string, pc policy.PassedCollection) []subjectBinding {
	add := func(digestHex, name string, viaLeaf bool) {
		if _, isWanted := want[digestHex]; !isWanted {
			return
		}
		key := step + "\x00" + digestHex
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, subjectBinding{digestHex: digestHex, step: step, subjectName: name, viaLeaf: viaLeaf})
	}
	for _, subj := range pc.Collection.Statement.Subject {
		if h := subj.Digest["sha256"]; h != "" {
			add(h, subj.Name, false)
		}
	}
	// Trust product/material leaves only when they provably reconstruct the
	// signed Merkle root — otherwise a tampered or inconsistent leaf set could
	// forge a binding for an artifact the producer never actually built.
	coll := pc.Collection.Collection
	if coll.VerifyInlineLeaves() == nil {
		for path, ds := range coll.Artifacts() {
			if h := suppliedSHA256(ds); h != "" {
				add(h, path, true)
			}
		}
	}
	return out
}

// buildVerifyVerdict assembles the verdict from the supplied artifact digests
// and the passing step results. Pure given its inputs so the binding logic is
// unit-testable without a live verify. When no supplied digest provably bound,
// the binding fields are left EMPTY — the policy still passed (Passed=true) on
// its own subjects, but cilock does not claim the operator's artifact bound when
// it did not.
func buildVerifyVerdict(supplied []string, stepResults map[string]policy.StepResult) VerifyVerdict {
	v := VerifyVerdict{Passed: true}
	if b := matchedBindings(supplied, stepResults); len(b) > 0 {
		v.Step = b[0].step
		v.MatchedSubject = "sha256:" + b[0].digestHex
		v.ObservedSubjectName = b[0].subjectName
	}
	return v
}

// writeVerifyBindingLines prints one "verified: <digest> bound to step ..." line
// per supplied artifact that PROVABLY bound (a top-level subject, or a
// root-verified product/material leaf), so a passing verify confirms the binding
// was to the operator's file at a glance. A supplied artifact that bound to
// neither gets an explicit "did NOT match" note instead of a fabricated binding
// — falsely reporting an artifact binding in a supply-chain verifier is
// evidence-integrity critical. Written to stderr alongside the evidence log.
func writeVerifyBindingLines(w io.Writer, supplied []string, stepResults map[string]policy.StepResult) {
	if len(supplied) == 0 {
		return
	}
	bound := make(map[string]struct{}, len(supplied))
	for _, b := range matchedBindings(supplied, stepResults) {
		bound[b.digestHex] = struct{}{}
		if b.viaLeaf {
			_, _ = fmt.Fprintf(w, "verified: sha256:%s bound to step %q as a product/material leaf %q (Merkle inclusion, root-verified)\n", b.digestHex, b.step, shortSubjectName(b.subjectName)) //nolint:gosec // CLI verdict to stderr, not an HTTP/HTML sink — G705 taint false positive.
		} else {
			_, _ = fmt.Fprintf(w, "verified: sha256:%s bound to step %q subject %q\n", b.digestHex, b.step, shortSubjectName(b.subjectName)) //nolint:gosec // CLI verdict to stderr, not an HTTP/HTML sink — G705 taint false positive.
		}
	}
	for _, h := range supplied {
		if h == "" {
			continue
		}
		if _, ok := bound[h]; ok {
			continue
		}
		_, _ = fmt.Fprintf(w, "note: supplied artifact sha256:%s did NOT match any verified subject or product/material leaf — verify passed on the policy's other evidence; confirm you are verifying the intended file\n", h) //nolint:gosec // CLI verdict to stderr, not an HTTP/HTML sink — G705 taint false positive.
	}
}

// shortSubjectName trims the common attestation predicate-URI prefix from a
// subject name for the human verdict line, mirroring the run summary so a
// "git/v0.1/remote:..." reads instead of the full URI. Names without the prefix
// are returned unchanged.
func shortSubjectName(name string) string {
	const prefix = "https://aflock.ai/attestations/"
	if rest, ok := strings.CutPrefix(name, prefix); ok {
		return rest
	}
	return name
}

// writeVerifyVerdictJSON emits the verdict as a single indented JSON object plus
// newline. This is the only thing written to stdout under --format json.
func writeVerifyVerdictJSON(w io.Writer, v VerifyVerdict) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal verify verdict: %w", err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write verify verdict: %w", err)
	}
	return nil
}
