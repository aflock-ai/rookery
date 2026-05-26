// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/rookery/attestation/chain"
)

// FilesystemChainSidecarSource resolves chain sidecars by name from a
// local directory. The naming convention is
// `<downstreamStep>.chain.json`. The sidecar's
// SourceStep.EnvelopeDigest is checked against the caller-supplied
// upstreamEnvelopeDigest so an attacker who plants the wrong sidecar
// in the directory cannot get a false-positive verification.
//
// This is the air-gapped / offline-friendly source: drop the sidecar
// next to the signed envelopes on disk and the verifier picks it up.
// Matches the DSSE bundle conventions where attestation + signature +
// sidecar travel as a set.
type FilesystemChainSidecarSource struct {
	// Dir is the directory the source searches for chain sidecars.
	// Empty Dir disables the source: LookupChainSidecar returns (nil, nil)
	// — the verifier treats that as "no chain sidecar for this pair"
	// and falls through to legacy comparison.
	Dir string
}

// NewFilesystemChainSidecarSource is the constructor; Dir must be an
// existing readable directory or LookupChainSidecar returns an error.
// Passing an empty Dir is allowed and short-circuits to "no sidecar."
func NewFilesystemChainSidecarSource(dir string) *FilesystemChainSidecarSource {
	return &FilesystemChainSidecarSource{Dir: dir}
}

// LookupChainSidecar reads `<Dir>/<downstreamStep>.chain.json` and
// returns its contents. Returns (nil, nil) when:
//
//   - Dir is empty (source is disabled)
//   - the file doesn't exist (no sidecar published for this step)
//
// Returns an error when the file exists but is malformed, or when
// the sidecar references a different upstream envelope than the
// caller supplied — that mismatch is a strong signal that someone
// is trying to chain a downstream step to an unrelated upstream
// attestation (cross-step proof replay, threat-model D1).
func (s *FilesystemChainSidecarSource) LookupChainSidecar(_ context.Context, downstreamStep, upstreamStep, upstreamEnvelopeDigest string) (*chain.ChainSidecar, error) {
	if s == nil || s.Dir == "" {
		return nil, nil //nolint:nilnil // explicit "no source" signal
	}
	if downstreamStep == "" {
		return nil, errors.New("filesystem chain sidecar source: downstreamStep is required")
	}
	// Defence in depth: refuse path-traversal in the step name. The
	// step name comes from the policy, which is signed, but a
	// hostile policy could try '../' to read arbitrary files.
	if strings.Contains(downstreamStep, "/") || strings.Contains(downstreamStep, "..") {
		return nil, fmt.Errorf("filesystem chain sidecar source: refusing path-bearing step name %q", downstreamStep)
	}
	path := filepath.Join(s.Dir, downstreamStep+".chain.json")
	body, err := os.ReadFile(path) //nolint:gosec // step name path-traversal-guarded above
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil //nolint:nilnil // no sidecar present
		}
		return nil, fmt.Errorf("read chain sidecar at %s: %w", path, err)
	}
	var sidecar chain.ChainSidecar
	if err := json.Unmarshal(body, &sidecar); err != nil {
		return nil, fmt.Errorf("decode chain sidecar at %s: %w", path, err)
	}

	// Sanity check the sidecar's claimed source-step name against the
	// policy-edge upstream name. Mismatch means the sidecar is for a
	// different chain edge than the policy is currently verifying.
	if sidecar.SourceStep.StepName != "" && sidecar.SourceStep.StepName != upstreamStep {
		return nil, fmt.Errorf("filesystem chain sidecar at %s declares sourceStep=%q but policy edge expects %q",
			path, sidecar.SourceStep.StepName, upstreamStep)
	}

	// Envelope-digest binding is enforced again by the verifier, but
	// catching it here gives the operator a precise filename + reason.
	if upstreamEnvelopeDigest != "" && sidecar.SourceStep.EnvelopeDigest != "" &&
		sidecar.SourceStep.EnvelopeDigest != upstreamEnvelopeDigest {
		return nil, fmt.Errorf("filesystem chain sidecar at %s binds to envelope %s but policy edge upstream envelope is %s",
			path, sidecar.SourceStep.EnvelopeDigest, upstreamEnvelopeDigest)
	}

	return &sidecar, nil
}
