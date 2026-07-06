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

package policy

// HardeningOptions gates the opt-in ENFORCEMENT of the policy-verification
// hardening findings tracked in issue #6266. Every field defaults to false: with
// the zero value the verifier behaves exactly as it always has and only a loud
// WARN fires for each dangerous configuration (the warnings shipped in #6276).
// Setting a field to true turns the corresponding WARN into a hard rejection.
//
// Why a process-wide toggle rather than a per-Verify option: the affected checks
// live in Functionary.Validate, checkCertConstraint, EvaluateRegoPolicy and
// Policy.Validate. Those functions are reached from many call sites — including
// direct callers in the embedding application (Judge, cilock) and the detector
// tests — none of which carry a verifyOptions value. Threading an options struct
// through every one of those signatures would churn the public API for a set of
// flags that are ALL off by default. Instead an embedder opts in ONCE at startup
// via SetHardening, and flipping a default here is the single-line change to make
// enforcement the default. This matches Cole's warn-first doctrine on #6266:
// warn autonomously now, enforce only on explicit direction.
//
// NOT covered here: R3_201 (cross-step rego input reshaping) is warn-only by
// design — the issue itself blesses "a WARNING on detected legacy input refs" as
// the fix, and turning it into a hard reject would require statically detecting
// which rego modules reference the old top-level input shape. That warning ships
// unconditionally in buildRegoInput; there is no flag for it.
type HardeningOptions struct {
	// EnforceCertConstraintOnKeyIDMatch (R3_184) runs CertConstraint.Check even
	// when a functionary's PublicKeyID matches the verifier's key ID. Today the
	// key-ID match short-circuits Functionary.Validate BEFORE the constraint runs,
	// so a functionary that sets BOTH fields has its certificate constraint
	// silently ignored on a key-ID match — a spec violation. When enforced, a raw
	// public-key verifier cannot satisfy an X.509 constraint, so a CertConstraint
	// set alongside a PublicKeyID on a non-X509 verifier fails closed.
	EnforceCertConstraintOnKeyIDMatch bool

	// RejectEmptyConstraintEmptyField (R3_181) rejects an empty SAN constraint
	// matched against an empty cert field instead of treating it as a no-op pass.
	// On its own the no-op pass is benign, but combined with permissive roots
	// (Roots=["*"]) it makes identity verification vacuous.
	RejectEmptyConstraintEmptyField bool

	// RejectDuplicateRegoPackage (R3_183) rejects a set of rego modules in which
	// two modules declare the same package name. OPA merges same-package modules,
	// so a second module can add or shadow rules (e.g. redefine a helper to always
	// pass) in the merged package. Policies are signed/trusted input so this is a
	// footgun rather than a live bypass, but enforcing it removes the footgun.
	RejectDuplicateRegoPackage bool

	// EnforceStepNameCoherence (R3_185 / R3_187 / R3_209) rejects, at
	// Policy.Validate time, any step whose Name is empty or disagrees with its map
	// key. The map key is authoritative during search/result-merge while Step.Name
	// drives the collection-name filter and artifact lookup; when they disagree the
	// policy fails LATER at verify with a misleading "no passed collections" error.
	// Enforcing turns that into a clear load-time error. Real policies always set
	// Name == key (see cilock policy_from_bundles.go), so enforcement only rejects
	// genuinely misconfigured policies.
	EnforceStepNameCoherence bool
}

// hardening holds the process-wide hardening options. Its zero value is the
// warn-first default: no enforcement, behavior identical to pre-#6266.
var hardening HardeningOptions

// Hardening returns the process-wide hardening options currently in effect.
func Hardening() HardeningOptions { return hardening }

// SetHardening replaces the process-wide hardening options. Intended to be called
// once at application startup to opt in to enforcement, and by tests. It is NOT
// safe to call concurrently with verification.
func SetHardening(h HardeningOptions) { hardening = h }
