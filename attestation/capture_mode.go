// Copyright 2026 The Rookery Contributors
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

package attestation

import "fmt"

// CaptureMode controls where the material + product attestors get their
// data. The default ("auto") detects what's available on the host and
// picks the fastest + most accurate option:
//
//  1. trace (when CILOCK_TRACE_MODE=ebpf can attach kprobes)
//  2. walk  (always available; legacy v0.1 behavior)
//
// Future modes:
//   - "ima"   — read /sys/kernel/security/ima/ascii_runtime_measurements
//   - "hybrid" — walk + trace cross-check for defense-in-depth
//
// The on-the-wire attestation shape is unchanged regardless of mode —
// material/v0.3 + product/v0.3 still serialize the same way. The mode
// only affects WHERE the digests come from. Each attestor records its
// source in a `capture_source` field so downstream verifiers can
// distinguish kernel-trusted (ima/ebpf) from filesystem-snapshot (walk)
// without changing existing policy rules.
type CaptureMode string

const (
	// CaptureAuto is the default. The framework detects the best
	// available mode at attestor-run time. Most CI environments will
	// resolve to "trace" (eBPF kprobes available) or fall through to
	// "walk" on constrained hosts.
	CaptureAuto CaptureMode = "auto"

	// CaptureWalk is the legacy v0.1 behavior — material and product
	// attestors walk the working directory before/after the tracee
	// and hash every file they find. Race-prone for fast builds
	// (file content can change between the pre-walk and the tracee
	// open), but works without any kernel features.
	CaptureWalk CaptureMode = "walk"

	// CaptureTrace derives materials and products from the trace
	// events the command-run attestor already collects (eBPF kprobes
	// or ptrace). Captures exactly the files the tracee actually
	// touched — not the entire working dir — and uses the read-tap
	// digests already computed during the trace. Race-free for
	// content (the kernel copies bytes to userspace once; the
	// read-tap captures the bytes the tracee saw).
	CaptureTrace CaptureMode = "trace"

	// CaptureIMA reads the kernel IMA log for measurements. Only
	// available on hosts with CONFIG_IMA enabled and an active
	// measurement policy. Kernel-computed digests, signed into the
	// TPM PCR-10 when IMA-audit is configured. Strongest trust
	// level but narrowest availability.
	CaptureIMA CaptureMode = "ima"
)

// Validate returns nil for known modes (including the empty string
// which resolves to CaptureAuto). Unknown values fail loudly per the
// "no silent downgrades" design — operators should know exactly which
// data source produced their attestation.
func (m CaptureMode) Validate() error {
	switch m {
	case "", CaptureAuto, CaptureWalk, CaptureTrace, CaptureIMA:
		return nil
	}
	return fmt.Errorf("unknown capture mode %q (valid: auto, walk, trace, ima)", string(m))
}

// Normalize maps "" → CaptureAuto and returns the result. Use this
// in attestor entry points so a missing/empty value behaves like the
// documented default.
func (m CaptureMode) Normalize() CaptureMode {
	if m == "" {
		return CaptureAuto
	}
	return m
}

// WithCaptureMode sets the capture mode on the AttestationContext.
// Empty string and "auto" both resolve to auto-detect at runtime.
func WithCaptureMode(m CaptureMode) AttestationContextOption {
	return func(ctx *AttestationContext) {
		ctx.captureMode = m.Normalize()
	}
}

// WithCachePatternOptions sets the cache classification pattern
// options on the context. Operators control this via CLI flags
// (--cache-add-pattern, --cache-allow-pattern,
// --cache-disable-defaults, --cache-disable-system-query) which
// the cilock CLI translates into a CachePatternOptions value.
func WithCachePatternOptions(o CachePatternOptions) AttestationContextOption {
	return func(ctx *AttestationContext) {
		ctx.cachePatternOpts = o
	}
}

// CaptureProbe is implemented by attestors that can produce
// trace-derived materials/products. The framework asks each completed
// attestor whether it can supply the requested mode; the first to say
// yes wins. Used by the material + product attestors to resolve
// CaptureAuto to a concrete data source at run time.
//
// Implementations should be cheap — this is called during the
// material/product Attest pass, not on every file.
type CaptureProbe interface {
	// CanProvide returns true if this attestor has data captured in
	// the requested mode (e.g., the command-run attestor returns true
	// for "trace" when its eBPF tracer ran successfully).
	CanProvide(mode CaptureMode) bool

	// TraceInputs returns the set of files the tracee READ during
	// execution, keyed by absolute path. Called when the resolved
	// capture mode is "trace" and the framework wants materials.
	TraceInputs() map[string]CaptureEntry

	// TraceOutputs returns the set of files the tracee WROTE during
	// execution, keyed by absolute path. Called when the resolved
	// capture mode is "trace" and the framework wants products.
	TraceOutputs() map[string]CaptureEntry
}

// CaptureEntry is a single file's record from the trace, intentionally
// shaped so material + product attestors can consume it directly into
// their existing DigestSet-keyed maps.
type CaptureEntry struct {
	// Digest is the file's content digest (sha256 minimum). May be nil
	// if the trace failed to capture content (e.g., file was deleted
	// before path-hash fallback could run, fd reuse race, etc.).
	Digest map[string]string

	// Source records how this digest was obtained — "read-tap" for
	// in-kernel streaming hash, "path-hash" for fallback re-read,
	// "ima" for kernel measurement, etc. Emitted into the attestation
	// so verifiers can distinguish trust levels.
	Source string
}

// ResolveCaptureMode picks a concrete data source for an auto-mode
// AttestationContext. Called by material/product attestors at run
// time. Walks two attestor lists: `completed` (attestors that have
// already run, exposing live data) and `registered` (everything
// registered with the context, including not-yet-run attestors).
//
// Resolution order for CaptureAuto:
//  1. trace (any attestor that CanProvide(CaptureTrace) — either
//     completed or merely registered with the intent to provide)
//  2. walk (always available; nil provider; caller falls back to
//     its existing directory-walk path)
//
// The two-list design lets early-running attestors (material runs
// before command-run) honor an "auto" choice that resolves to trace
// even though the trace data isn't captured yet. The caller still
// gets a non-nil provider when one exists in `completed` and a nil
// provider (with non-nil resolved mode) when only `registered` is
// available — material attestor short-circuits its walk in either
// case; product attestor (running later) gets the live data.
//
// For non-auto modes, ResolveCaptureMode requires an exact match
// and returns an error rather than silently falling back. That is
// the "fail loudly" contract — operators who asked for IMA shouldn't
// quietly get a walk-based attestation.
//
//nolint:gocognit,gocyclo // mode dispatch + provider probe + fail-loud paths are inherently wide
func ResolveCaptureMode(
	requested CaptureMode,
	completed []CompletedAttestor,
	registered []Attestor,
) (resolved CaptureMode, provider CaptureProbe, err error) {
	requested = requested.Normalize()

	findCompletedProvider := func(mode CaptureMode) CaptureProbe {
		for _, c := range completed {
			if c.Attestor == nil {
				continue
			}
			probe, ok := c.Attestor.(CaptureProbe)
			if !ok {
				continue
			}
			if probe.CanProvide(mode) {
				return probe
			}
		}
		return nil
	}

	findRegisteredProvider := func(mode CaptureMode) bool {
		for _, a := range registered {
			probe, ok := a.(CaptureProbe)
			if !ok {
				continue
			}
			if probe.CanProvide(mode) {
				return true
			}
		}
		return false
	}

	switch requested {
	case CaptureWalk:
		return CaptureWalk, nil, nil
	case CaptureTrace:
		if p := findCompletedProvider(CaptureTrace); p != nil {
			return CaptureTrace, p, nil
		}
		if findRegisteredProvider(CaptureTrace) {
			return CaptureTrace, nil, nil
		}
		return "", nil, fmt.Errorf(
			"capture-mode=trace requested but no attestor can provide trace data " +
				"(is the command-run attestor configured with --trace?)")
	case CaptureIMA:
		if p := findCompletedProvider(CaptureIMA); p != nil {
			return CaptureIMA, p, nil
		}
		if findRegisteredProvider(CaptureIMA) {
			return CaptureIMA, nil, nil
		}
		return "", nil, fmt.Errorf(
			"capture-mode=ima requested but no attestor can provide IMA data " +
				"(is IMA enabled in the kernel with an active measurement policy?)")
	case CaptureAuto:
		if p := findCompletedProvider(CaptureTrace); p != nil {
			return CaptureTrace, p, nil
		}
		if findRegisteredProvider(CaptureTrace) {
			return CaptureTrace, nil, nil
		}
		return CaptureWalk, nil, nil
	}
	return "", nil, fmt.Errorf("unknown capture mode %q", string(requested))
}
