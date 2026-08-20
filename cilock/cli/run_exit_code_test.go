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
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/stretchr/testify/assert"
)

// Regression coverage for finding #221: cilock used to exit 0 for some
// attestor errors and 1 for others, both at level=error, with no way for
// CI to distinguish. The classifier now splits soft (attestor had nothing
// to do — exit 0) from fatal (contract violation — exit 1).

// TestRunExitCode_SoftAttestorError_ExitsZeroWithWarnings pins the soft
// path. The CLI must demote a SoftError-wrapped attestor leg to a warning
// and let the process exit 0.
func TestRunExitCode_SoftAttestorError_ExitsZeroWithWarnings(t *testing.T) {
	soft := attestation.NewSoftError("no SBOM file found")
	wrapped := fmt.Errorf("attestor sbom failed: %w", soft)
	agg := &workflow.AttestorRunErrors{
		Legs: []workflow.AttestorErrorLeg{
			{Attestor: "sbom", Err: wrapped},
		},
	}

	got := classifyAttestorRunError(agg)
	assert.NoError(t, got, "soft-only aggregate must demote to nil (exit 0)")
}

// TestRunExitCode_FatalAttestorError_ExitsOne pins the fatal path. A
// non-SoftError leg (e.g. commandrun "tracing not supported") must
// propagate and produce a non-zero exit.
func TestRunExitCode_FatalAttestorError_ExitsOne(t *testing.T) {
	fatal := errors.New("tracing not supported on this platform")
	wrapped := fmt.Errorf("attestor command-run failed: %w", fatal)
	agg := &workflow.AttestorRunErrors{
		Legs: []workflow.AttestorErrorLeg{
			{Attestor: "command-run", Err: wrapped},
		},
	}

	got := classifyAttestorRunError(agg)
	assert.Error(t, got, "fatal-only aggregate must propagate (exit 1)")
}

// TestRunExitCode_MixedFatalAndSoft_ExitsOneWithBothLogged covers the
// case both classes fire in the same run. The fatal class still drives
// exit code 1; the soft legs are still surfaced as warnings.
func TestRunExitCode_MixedFatalAndSoft_ExitsOneWithBothLogged(t *testing.T) {
	soft := attestation.NewSoftError("no products to attest")
	softWrapped := fmt.Errorf("attestor sbom failed: %w", soft)
	fatal := errors.New("tracing not supported on this platform")
	fatalWrapped := fmt.Errorf("attestor command-run failed: %w", fatal)

	agg := &workflow.AttestorRunErrors{
		Legs: []workflow.AttestorErrorLeg{
			{Attestor: "sbom", Err: softWrapped},
			{Attestor: "command-run", Err: fatalWrapped},
		},
	}

	got := classifyAttestorRunError(agg)
	assert.Error(t, got, "mixed aggregate with any fatal leg must propagate")

	// The returned error should contain only the fatal legs so the
	// final exit-code message reflects what actually failed.
	var ret *workflow.AttestorRunErrors
	if assert.True(t, errors.As(got, &ret), "returned error must be AttestorRunErrors") {
		assert.Len(t, ret.Legs, 1, "only fatal legs survive in the returned aggregate")
		assert.Equal(t, "command-run", ret.Legs[0].Attestor)
	}
}

// TestRunExitCode_NonAggregateError_PropagatesUnchanged ensures errors
// that are not workflow.AttestorRunErrors (e.g. signer load failures
// returned before attestors run) flow through unchanged.
func TestRunExitCode_NonAggregateError_PropagatesUnchanged(t *testing.T) {
	raw := errors.New("failed to load signers: not a valid key")
	got := classifyAttestorRunError(raw)
	assert.Same(t, raw, got, "non-aggregate errors must propagate by identity")
}

// TestSoftError_IsErrorsAsCompatible asserts the public IsSoftError /
// errors.As path works on a wrapped SoftError — this is the contract
// the classifier and any downstream consumer relies on.
func TestSoftError_IsErrorsAsCompatible(t *testing.T) {
	soft := attestation.NewSoftError("nothing to do")
	wrapped := fmt.Errorf("attestor x failed: %w", soft)
	assert.True(t, attestation.IsSoftError(wrapped), "wrapped SoftError must be detectable")

	bare := errors.New("real failure")
	assert.False(t, attestation.IsSoftError(bare), "plain errors must not be classified soft")

	// Errors.As traversal must reach the SoftError through fmt.Errorf wrap.
	var s attestation.SoftError
	assert.True(t, errors.As(wrapped, &s))
	assert.Equal(t, "nothing to do", s.Reason)
}

// TestRunExitCode_DetectionError_StillExitsOne is the exit-code half of the
// secretscan error-contract fix, and it exists to be unambiguous about a
// change that is easy to read backwards.
//
// secretscan used to return a PLAIN error when it FOUND secrets. That looked
// like a strong failure signal, but workflow.run() drops any attestor with a
// non-nil Error from the collection, so "I found secrets" deleted its own
// evidence — a findings-positive scan became indistinguishable from a scan
// that never ran. THAT was the fail-open. The fix reports a detection as
// attestation.DetectionError so the findings stay in the signed collection.
//
// The obvious worry about that change is "you softened the failure — does
// --attestor-secretscan-fail-on-detection still fail the build?" This test
// answers it in the classifier that actually decides the process exit code:
// a DetectionError is NOT a SoftError, so it lands in FatalLegs and
// classifyAttestorRunError still returns non-nil. Exit 1, unchanged.
func TestRunExitCode_DetectionError_StillExitsOne(t *testing.T) {
	detection := attestation.NewDetectionError("secret scanning failed: found 2 secrets")
	wrapped := fmt.Errorf("attestor secretscan failed: %w", detection)
	agg := &workflow.AttestorRunErrors{
		Legs: []workflow.AttestorErrorLeg{
			{Attestor: "secretscan", Err: wrapped},
		},
	}

	got := classifyAttestorRunError(agg)
	assert.Error(t, got,
		"a detected secret must still fail the build — preserving the evidence "+
			"must not downgrade --attestor-secretscan-fail-on-detection to exit 0")

	assert.False(t, attestation.IsSoftError(wrapped),
		"a detection is not a 'nothing to do' outcome; if it were classified soft the CLI would exit 0")
	assert.NotEmpty(t, agg.FatalLegs(), "the detection leg must be fatal")
	assert.Empty(t, agg.SoftLegs(), "the detection leg must not be demoted to a warning")
}

// TestDetectionError_IsErrorsAsCompatible pins the classification contract
// itself: DetectionError must survive fmt.Errorf wrapping (the workflow wraps
// every leg as "attestor X failed: %w"), and must be kept strictly distinct
// from both plain errors and SoftErrors. Collapsing any two of those three
// channels reintroduces the bug.
func TestDetectionError_IsErrorsAsCompatible(t *testing.T) {
	detection := attestation.NewDetectionError("found 2 secrets")
	wrapped := fmt.Errorf("attestor secretscan failed: %w", detection)

	assert.True(t, attestation.IsDetectionError(wrapped),
		"wrapped DetectionError must be detectable — the workflow only ever sees the wrapped form")

	// A failure to OBSERVE is not a detection. This is the distinction that
	// keeps a crashed scanner's partial payload out of the collection.
	bare := errors.New("gitleaks crashed: could not observe")
	assert.False(t, attestation.IsDetectionError(bare),
		"a plain error means 'I could not observe' and must never be read as a finding")

	// A detection is not soft, and a soft error is not a detection.
	assert.False(t, attestation.IsSoftError(wrapped))
	assert.False(t, attestation.IsDetectionError(attestation.NewSoftError("nothing to do")))

	var d attestation.DetectionError
	assert.True(t, errors.As(wrapped, &d))
	assert.Equal(t, "found 2 secrets", d.Reason)
}
