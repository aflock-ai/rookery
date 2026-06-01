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

package detection

import (
	"fmt"
	"strings"
)

// OutputContract is the machine-checkable OUTPUT contract for an attestor —
// the THIRD face of a detector.yaml (detect -> run -> what you get). The
// detection gates (Pre/Post) say WHEN an attestor fires; the contract says
// WHAT it produces, in terms that map 1:1 to the attestation interfaces
// (Attestor.Type/RunType, Subjecter, Materialer, Producer, Exporter,
// MultiExporter, BackReffer, Finalizer, Schema). Every field is proven by the
// verification loop: the testkit SDK drives the attestor against a recorded
// fixture and asserts each claim.
//
// NOTE: the contract does NOT duplicate the rest of detector.yaml. Category,
// PrimaryCategory, Upstream (tool/license/vendor), EmitsFormats,
// RecommendedTrace, Description, and the detection gates/warnings/llm_hints all
// live on the parent DetectorYAML and continue to power auto step-name
// inference (stepinfer), error feedback (cilock plan), and detection. The
// contract is purely additive — it adds the output facet, it replaces nothing.
//
// Contract is optional. Detection-only entries (detection_only: true) and
// not-yet-migrated plugins omit it; the gate runs warn-only over attestors
// without a contract until they opt in.
type OutputContract struct {
	// PredicateType is the canonical/primary in-toto predicate URI the
	// attestor emits (the default when it emits one). MUST be one of the
	// attestor's registered types. The highest-value claim — a typo here
	// silently breaks every verifier policy keyed on the URI.
	PredicateType string `yaml:"predicate_type" json:"predicate_type"`

	// PredicateTypes is the FULL set of predicate URIs the attestor may emit
	// when it registers more than one (RegisterAttestationWithTypes — e.g.
	// sbom emits sbom/v0.1, SPDX, and CycloneDX and selects at run time).
	// Optional; when set it MUST contain PredicateType. The testkit asserts
	// the run's Attestor.Type() is a member. Without this a multi-type
	// attestor's alternate URIs would be invisible to the catalog.
	PredicateTypes []string `yaml:"predicate_types,omitempty" json:"predicate_types,omitempty"`

	// Tier is the adoption tier from the attestor concepts doc, so the catalog
	// can be presented most-popular-first: foundation | recommended | maturity
	// | extended. foundation = always-on core evidence (git, command-run,
	// material, product, environment); recommended = common security/build
	// evidence (sbom, sarif, oci, docker, trivy); maturity = advanced
	// (policyverify, trace, slsa); extended = specialized/niche scanners
	// (prowler, steampipe, kube-bench, oscap, …) typically only in a
	// custom cilock build. Optional.
	Tier string `yaml:"tier,omitempty" json:"tier,omitempty"`

	// RunType is the lifecycle phase. MUST equal Attestor.RunType(). Today the
	// contract supports prematerial|material|product|postproduct (the
	// fixture-driveable phases). execute + verify are rejected by
	// validateOutputContract until the testkit gains their drivers (recorded
	// trace / input-attestations) — a contract on those phases would auto-skip
	// and falsely report "covered".
	RunType string `yaml:"run_type" json:"run_type"`

	// Exports records the attestor's Export() behavior. nil = not an Exporter
	// / never exports; a non-nil value is the export setting of the canonical
	// fixture's configuration. Pair with ExportConfigurable to distinguish
	// "always exports" (steampipe) from "exports only when configured"
	// (sbom/link/slsa, default false) — a static bool conflates the two.
	Exports *bool `yaml:"exports,omitempty" json:"exports,omitempty"`

	// ExportConfigurable is true when Export() is driven by a config option
	// (so Exports records the DEFAULT, not an invariant).
	ExportConfigurable bool `yaml:"export_configurable,omitempty" json:"export_configurable,omitempty"`

	// Subjects describes the in-toto subjects the attestor contributes via
	// Subjecter.Subjects(). Each entry is a stable key PREFIX — subject keys
	// carry dynamic tails (a digest, an id), so the contract asserts the
	// prefix family, not the exact key.
	Subjects []SubjectClaim `yaml:"subjects,omitempty" json:"subjects,omitempty"`

	// EmitsMaterials / EmitsProducts assert the attestor implements the
	// Materialer / Producer interface and populates it for the canonical
	// fixture. Existence claims, not exhaustive enumeration.
	EmitsMaterials bool `yaml:"emits_materials,omitempty" json:"emits_materials,omitempty"`
	EmitsProducts  bool `yaml:"emits_products,omitempty"  json:"emits_products,omitempty"`

	// Finalizes asserts the attestor implements Finalizer (a second pass after
	// all attestors complete — e.g. material in trace mode consuming
	// commandrun's trace output).
	Finalizes bool `yaml:"finalizes,omitempty" json:"finalizes,omitempty"`

	// MultiExported lists the predicate types an attestor emits per-item via
	// MultiExporter.ExportedAttestations() (one envelope per artifact). Empty
	// for the common case; present-and-non-empty marks a MultiExporter.
	MultiExported []string `yaml:"multi_exported,omitempty" json:"multi_exported,omitempty"`

	// BackRefSubjects lists the subject-key prefixes the attestor exposes via
	// BackReffer.BackRefs(). Must be a subset of Subjects prefixes; empty means
	// the attestor is not a BackReffer.
	BackRefSubjects []string `yaml:"backref_subjects,omitempty" json:"backref_subjects,omitempty"`

	// SchemaRequired, when true, asserts Attestor.Schema() returns a non-nil
	// schema. The JSON-shape gate.
	SchemaRequired bool `yaml:"schema_required,omitempty" json:"schema_required,omitempty"`

	// ExitBehavior declares the attestor's failure contract when it finds no
	// evidence (e.g. "no products to attest"). Verified by a fixture-driven
	// Attest() run over a negative fixture.
	ExitBehavior *ExitBehaviorClaim `yaml:"exit_behavior,omitempty" json:"exit_behavior,omitempty"`

	// Invocation is the canonical, validated command that produces the
	// canonical fixture. Mirrors the prose "Validated invocation" doc section
	// in structured form so the doc table can be generated from it.
	Invocation *Invocation `yaml:"validated_invocation,omitempty" json:"validated_invocation,omitempty"`

	// Credentials is the MINIMAL credential set the attestor needs to produce
	// its evidence — documented by type + minimal scope, NEVER as secret
	// values. Empty means the attestor needs no credentials (e.g. it signs a
	// local file). This tells an operator exactly what to provision to use the
	// attestor, records what was needed to capture the fixture, and drives the
	// generated "Credentials" doc section. The point of least-privilege: a
	// stale prose doc routinely over-asks (admin instead of read-only); the
	// contract pins the floor.
	Credentials []CredentialReq `yaml:"credentials,omitempty" json:"credentials,omitempty"`

	// Stability documents how reproducible the underlying tool's output is —
	// the PRECONDITION for a verifiable contract. The loop records a real run
	// as a fixture and re-checks it; if the tool's output is non-deterministic
	// (unstable ordering, ubiquitous timestamps, unversioned schema) the
	// fixture can't be reproduced and the contract can't be PROVEN. An attestor
	// whose tool can't reach at least best-effort stability should stay
	// declared-only (or carry no contract). nil = unspecified.
	Stability *OutputStability `yaml:"stability,omitempty" json:"stability,omitempty"`

	// Fixtures names the fixture cases (dirs under the plugin's
	// testdata/fixtures/) that PROVE this contract against recorded real-tool
	// evidence, each with a role. OPTIONAL: a contract with no fixtures is
	// "declared" — statically cross-checked against the live attestor
	// interfaces but not yet proven by a real run (see Proven). If fixtures are
	// listed, at least one must be canonical; an ExitBehavior claim requires a
	// negative fixture.
	Fixtures []FixtureRef `yaml:"fixtures,omitempty" json:"fixtures,omitempty"`
}

// Proven reports whether the contract is backed by a canonical fixture (a
// recorded real-tool run) rather than merely declared (static interface
// cross-check only). The CI gate uses this to report the declared-but-unproven
// coverage gap honestly instead of letting a static-only pass masquerade as
// full verification.
func (c *OutputContract) Proven() bool {
	for _, f := range c.Fixtures {
		if f.Role == "" || f.Role == FixtureCanonical {
			return true
		}
	}
	return false
}

// SubjectClaim is one declared subject-key family.
type SubjectClaim struct {
	// Prefix is the stable leading segment of the subject key, INCLUDING any
	// trailing separator (e.g. "slack:team:", "imagedigest:"). The verifier
	// asserts at least one subject key in the fixture starts with this prefix.
	Prefix string `yaml:"prefix" json:"prefix"`
	// Description is one line of human text; feeds the generated doc table.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// DigestAlgs lists digest algorithms expected in the DigestSet for this
	// subject (e.g. ["sha256"]). Optional; checked when present.
	DigestAlgs []string `yaml:"digest_algs,omitempty" json:"digest_algs,omitempty"`
}

// FixtureRef names one fixture case + its role in proving the contract.
type FixtureRef struct {
	// Name is the fixture case directory under the plugin's testdata/fixtures/.
	Name string `yaml:"name" json:"name"`
	// Role is canonical (the happy-path proof; >=1 required), negative (proves
	// ExitBehavior / no-evidence), or variant (an additional case). Empty
	// defaults to canonical.
	Role string `yaml:"role,omitempty" json:"role,omitempty"`
}

// ExitBehaviorClaim mirrors the runtime no-evidence failure contract.
type ExitBehaviorClaim struct {
	// OnNoEvidence is the documented behavior when the attestor finds nothing
	// to attest: ContractExitError (Attest returns an error) or
	// ContractExitEmpty (Attest succeeds with empty output).
	OnNoEvidence string `yaml:"on_no_evidence" json:"on_no_evidence"`
	// ErrorContains, when OnNoEvidence==error, is a substring the returned
	// error must contain (e.g. "no products to attest").
	ErrorContains string `yaml:"error_contains,omitempty" json:"error_contains,omitempty"`
}

// Invocation is the validated command that generates a fixture.
type Invocation struct {
	Tool         string   `yaml:"tool" json:"tool"`
	Argv         []string `yaml:"argv" json:"argv"`
	Step         string   `yaml:"step,omitempty" json:"step,omitempty"`
	Attestations []string `yaml:"attestations,omitempty" json:"attestations,omitempty"`
}

// OutputStability documents the reproducibility of the underlying tool's
// output — the gating requirement for a verifiable contract.
type OutputStability struct {
	// Level is the stability class (Stability*): stable | versioned-schema |
	// best-effort | unstable.
	Level string `yaml:"level" json:"level"`
	// ToolSchemaVersion is the tool's OWN output-schema version this contract
	// targets (e.g. SARIF "2.1.0", CycloneDX "1.6", SPDX "2.3"), when the tool
	// versions its output. This is the anchor that makes the predicate
	// reliable — the versioned schema the doc calls out.
	ToolSchemaVersion string `yaml:"tool_schema_version,omitempty" json:"tool_schema_version,omitempty"`
	// VolatileFields are predicate paths that legitimately vary run-to-run
	// (scan timestamps, durations, temp paths) and must be redacted before a
	// golden comparison. Documents the "stable except here" boundary.
	VolatileFields []string `yaml:"volatile_fields,omitempty" json:"volatile_fields,omitempty"`
	// Notes is one line on why the output is (or isn't) stable.
	Notes string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

// CredentialReq describes ONE credential the attestor needs to produce its
// evidence — the minimal set, by type and scope, NEVER actual secret values.
type CredentialReq struct {
	// Name is the operator-facing label, e.g. "Slack bot token",
	// "AWS instance role", "Google Workspace admin (read-only)".
	Name string `yaml:"name" json:"name"`
	// Type is the credential category (CredType*).
	Type string `yaml:"type" json:"type"`
	// Provided is how the credential reaches the attestor (CredProvided*).
	Provided string `yaml:"provided,omitempty" json:"provided,omitempty"`
	// EnvVars are the environment variable names that carry it, when
	// Provided == env (names only, never values).
	EnvVars []string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
	// Scopes is the MINIMAL set of permissions/scopes required — the
	// least-privilege floor (e.g. ["channels:read","users:read"] for Slack,
	// ["securityaudit"] for an AWS role). This is the field stale docs get
	// wrong by over-asking.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	// Required is true when the attestor cannot produce evidence without it;
	// false marks a credential that only enriches the output.
	Required bool `yaml:"required,omitempty" json:"required,omitempty"`
	// Description is one line of operator guidance.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Contract run-type values. These mirror attestation.RunType but are declared
// here as plain strings to avoid an import cycle (attestation imports
// detection for the registry, so detection must not import attestation).
const (
	ContractRunPreMaterial = "prematerial"
	ContractRunMaterial    = "material"
	ContractRunExecute     = "execute"
	ContractRunProduct     = "product"
	ContractRunPostProduct = "postproduct"
	ContractRunVerify      = "verify"
)

// Exit-behavior values for ExitBehaviorClaim.OnNoEvidence.
const (
	ContractExitError = "error"
	ContractExitEmpty = "empty"
)

// Fixture roles.
const (
	FixtureCanonical = "canonical"
	FixtureNegative  = "negative"
	FixtureVariant   = "variant"
)

// Output-stability levels (OutputStability.Level).
const (
	StabilityStable          = "stable"           // byte-deterministic output for the same input + tool version
	StabilityVersionedSchema = "versioned-schema" // stable structure under an explicitly versioned schema (SARIF/CycloneDX/SPDX)
	StabilityBestEffort      = "best-effort"      // stable after redacting documented volatile fields
	StabilityUnstable        = "unstable"         // not reproducibly verifiable — should stay declared-only / uncontracted
)

// Adoption tiers (OutputContract.Tier), from the attestor concepts doc.
const (
	TierFoundation  = "foundation"
	TierRecommended = "recommended"
	TierMaturity    = "maturity"
	TierExtended    = "extended"
)

var validStabilityLevels = map[string]bool{
	StabilityStable: true, StabilityVersionedSchema: true,
	StabilityBestEffort: true, StabilityUnstable: true,
}

var validTiers = map[string]bool{
	TierFoundation: true, TierRecommended: true, TierMaturity: true, TierExtended: true,
}

// Credential types (CredentialReq.Type).
const (
	CredTypeNone             = "none"              // explicitly no credential
	CredTypeOIDC             = "oidc"              // an OIDC identity token (keyless signing, CI identity)
	CredTypeAPIToken         = "api-token"         // a service API token (Slack, GitHub API)
	CredTypeCloudRole        = "cloud-role"        // cloud IAM role/credentials (AWS/GCP/Azure data-plane reads)
	CredTypeInstanceIdentity = "instance-identity" // node/instance identity document (IMDS, GCE metadata)
	CredTypeServiceAccount   = "service-account"   // k8s / GCP service account
	CredTypeSigningKey       = "signing-key"       // a private signing key
)

// Credential delivery mechanisms (CredentialReq.Provided).
const (
	CredProvidedEnv              = "env"               // environment variables (names in EnvVars)
	CredProvidedFile             = "file"              // a credentials file on disk
	CredProvidedInstanceMetadata = "instance-metadata" // queried from the metadata endpoint
	CredProvidedOIDCFlow         = "oidc-flow"         // minted via an OIDC exchange
	CredProvidedAmbient          = "ambient"           // default credential chain / ambient cloud identity
)

var validCredTypes = map[string]bool{
	CredTypeNone: true, CredTypeOIDC: true, CredTypeAPIToken: true,
	CredTypeCloudRole: true, CredTypeInstanceIdentity: true,
	CredTypeServiceAccount: true, CredTypeSigningKey: true,
}

var validCredProvided = map[string]bool{
	CredProvidedEnv: true, CredProvidedFile: true, CredProvidedInstanceMetadata: true,
	CredProvidedOIDCFlow: true, CredProvidedAmbient: true,
}

// fixtureDriveable run-types are the phases the testkit can hermetically drive
// today (product / workdir / env modes). execute + verify need recorded-trace
// and input-attestation drivers the testkit lacks, so a contract on those
// phases is rejected rather than allowed to auto-skip (a false "covered").
var fixtureDriveableRunTypes = map[string]bool{
	ContractRunPreMaterial: true,
	ContractRunMaterial:    true,
	ContractRunProduct:     true,
	ContractRunPostProduct: true,
}

// validateOutputContract enforces the internal consistency of a Contract
// block. Like validateDetectorYAML, a returned error is a developer-side bug:
// the contract is authored and embedded at build time.
func validateOutputContract(c *OutputContract, name string) error { //nolint:gocognit,gocyclo // exhaustive field-by-field contract validator: a flat sequence of independent build-time consistency checks; splitting it would scatter the contract's invariants across helpers without reducing real complexity.
	if c == nil {
		return nil
	}
	if strings.TrimSpace(c.PredicateType) == "" {
		return fmt.Errorf("detector.yaml %q: contract.predicate_type is required", name)
	}
	if c.Tier != "" && !validTiers[c.Tier] {
		return fmt.Errorf("detector.yaml %q: contract.tier %q must be one of foundation|recommended|maturity|extended", name, c.Tier)
	}
	if c.Stability != nil && !validStabilityLevels[c.Stability.Level] {
		return fmt.Errorf("detector.yaml %q: contract.stability.level %q must be one of stable|versioned-schema|best-effort|unstable", name, c.Stability.Level)
	}
	if !fixtureDriveableRunTypes[c.RunType] {
		// Distinguish "unknown" from "known but not yet driveable" for a clear
		// author-facing message.
		switch c.RunType {
		case ContractRunExecute, ContractRunVerify:
			return fmt.Errorf("detector.yaml %q: contract.run_type %q is not yet supported (the testkit lacks a %s-mode driver); omit the contract until the mode lands so it isn't a false-green", name, c.RunType, c.RunType)
		default:
			return fmt.Errorf("detector.yaml %q: contract.run_type %q must be one of prematerial|material|product|postproduct", name, c.RunType)
		}
	}
	// PredicateTypes, when set, must contain the canonical PredicateType.
	if len(c.PredicateTypes) > 0 {
		found := false
		for i, pt := range c.PredicateTypes {
			if strings.TrimSpace(pt) == "" {
				return fmt.Errorf("detector.yaml %q: contract.predicate_types[%d] is empty", name, i)
			}
			if pt == c.PredicateType {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("detector.yaml %q: contract.predicate_type %q must appear in contract.predicate_types", name, c.PredicateType)
		}
	}
	prefixes := make(map[string]bool, len(c.Subjects))
	for i, s := range c.Subjects {
		if strings.TrimSpace(s.Prefix) == "" {
			return fmt.Errorf("detector.yaml %q: contract.subjects[%d].prefix is required", name, i)
		}
		prefixes[s.Prefix] = true
	}
	for _, br := range c.BackRefSubjects {
		if !prefixes[br] {
			return fmt.Errorf("detector.yaml %q: contract.backref_subjects %q is not among contract.subjects prefixes", name, br)
		}
	}
	if c.ExitBehavior != nil {
		switch c.ExitBehavior.OnNoEvidence {
		case ContractExitError, ContractExitEmpty:
		default:
			return fmt.Errorf("detector.yaml %q: contract.exit_behavior.on_no_evidence %q must be one of error|empty", name, c.ExitBehavior.OnNoEvidence)
		}
	}
	// Fixtures are OPTIONAL at declaration time. A contract with no fixtures is
	// "declared" — statically cross-checked against the live attestor
	// interfaces (predicate type, run type, Subjecter/Producer/... presence) —
	// but not yet "proven" by a recorded real-tool run (see Proven). This is
	// what lets the whole catalog be migrated to contracts at once and gated by
	// the static cross-check, with real-run fixtures added incrementally. The
	// CI gate reports the declared-but-unproven gap rather than letting a
	// static-only pass masquerade as full verification. If fixtures ARE listed,
	// at least one must be canonical, and an ExitBehavior claim (a runtime
	// behavior) requires a negative fixture to prove it.
	canonical, negative := 0, 0
	for i, f := range c.Fixtures {
		if strings.TrimSpace(f.Name) == "" {
			return fmt.Errorf("detector.yaml %q: contract.fixtures[%d].name is required", name, i)
		}
		switch f.Role {
		case "", FixtureCanonical:
			canonical++
		case FixtureNegative:
			negative++
		case FixtureVariant:
		default:
			return fmt.Errorf("detector.yaml %q: contract.fixtures[%d].role %q must be canonical|negative|variant", name, i, f.Role)
		}
	}
	if len(c.Fixtures) > 0 && canonical == 0 {
		return fmt.Errorf("detector.yaml %q: contract lists fixtures but none has role canonical", name)
	}
	if c.ExitBehavior != nil && negative == 0 {
		return fmt.Errorf("detector.yaml %q: contract declares exit_behavior but has no negative fixture to prove it", name)
	}
	for i, cr := range c.Credentials {
		if strings.TrimSpace(cr.Name) == "" {
			return fmt.Errorf("detector.yaml %q: contract.credentials[%d].name is required", name, i)
		}
		if !validCredTypes[cr.Type] {
			return fmt.Errorf("detector.yaml %q: contract.credentials[%d].type %q must be one of none|oidc|api-token|cloud-role|instance-identity|service-account|signing-key", name, i, cr.Type)
		}
		if cr.Provided != "" && !validCredProvided[cr.Provided] {
			return fmt.Errorf("detector.yaml %q: contract.credentials[%d].provided %q must be one of env|file|instance-metadata|oidc-flow|ambient", name, i, cr.Provided)
		}
	}
	return nil
}
