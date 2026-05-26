// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"errors"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
)

// untrackedMaterialsAllowed inspects the materials a downstream step
// claims to have consumed and returns an error when one of them is
// NOT covered by either:
//
//   - the chain sidecar's MaterialProofs (the `proven` set, the
//     cryptographically attested materials), or
//   - the step's AllowedUntracked glob patterns (the policy-declared
//     escape hatch for system files that no upstream step attests to).
//
// An uncovered material means the downstream step consumed something
// the policy can't prove came from an upstream attestation AND
// hasn't explicitly allowed. The verifier fails closed.
//
// Empty AllowedUntracked + non-empty `mats` set + missing proofs is
// the strict-mode default and the correct behavior for hermetic
// builds. Real CI on managed runners typically allows some system
// paths via glob.
//
// All AllowedUntracked patterns are compiled once and applied to the
// material path; gobwas/glob match semantics (the same library the
// product attestor uses for include-globs).
func untrackedMaterialsAllowed(step Step, mats map[string]cryptoutil.DigestSet, proven map[string]struct{}) error {
	if len(mats) == 0 {
		// Nothing to check. v0.3 attestations often have an empty
		// in-process Materials() map (data lives in sidecar). When
		// that's the case the chain sidecar IS the source of truth
		// and there's nothing the policy can complain about here.
		return nil
	}

	matchers, err := compileAllowedUntracked(step.AllowedUntracked)
	if err != nil {
		return err
	}

	var uncovered []string
	for path := range mats {
		if _, ok := proven[path]; ok {
			continue // chain sidecar attests this material
		}
		if allowed(matchers, path) {
			continue
		}
		uncovered = append(uncovered, path)
	}
	if len(uncovered) == 0 {
		return nil
	}
	sort.Strings(uncovered)
	const sampleLimit = 5
	sample := uncovered
	suffix := ""
	if len(sample) > sampleLimit {
		sample = sample[:sampleLimit]
		suffix = fmt.Sprintf(" (showing %d of %d)", sampleLimit, len(uncovered))
	}
	return fmt.Errorf("step %q has %d material(s) without chain-of-custody proof and not covered by allowedUntracked%s: %v",
		step.Name, len(uncovered), suffix, sample)
}

// overbroadPatterns are globs that match every conceivable material
// path. Allowing one in allowedUntracked silently disables
// chain-of-custody verification for the step — the policy says
// "anything from anywhere is fine" — which defeats the entire
// point of the feature. We reject them at compile time with a
// clear error so the policy author has to be explicit about which
// directories they trust.
var overbroadPatterns = map[string]struct{}{
	"**":    {},
	"**/*":  {},
	"/**":   {},
	"/**/*": {},
	"*":     {},
	"*/**":  {},
}

func compileAllowedUntracked(patterns []string) ([]glob.Glob, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	out := make([]glob.Glob, 0, len(patterns))
	for _, p := range patterns {
		if p == "" {
			return nil, errors.New("allowedUntracked: empty glob pattern is not allowed (use specific paths)")
		}
		if _, isOverbroad := overbroadPatterns[p]; isOverbroad {
			return nil, fmt.Errorf("allowedUntracked: pattern %q matches every path and silently disables chain-of-custody verification; use specific directory globs like '/usr/lib/**' instead", p)
		}
		g, err := glob.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("allowedUntracked: pattern %q: %w", p, err)
		}
		out = append(out, g)
	}
	return out, nil
}

func allowed(matchers []glob.Glob, path string) bool {
	for _, m := range matchers {
		if m.Match(path) {
			return true
		}
	}
	return false
}
