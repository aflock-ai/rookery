// Copyright 2022 The Witness Contributors
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

// zz_generated.deepcopy.go covers every type in this package marked
// `+kubebuilder:object:generate=true`. Nothing in CI regenerates it, so it is
// on the author to re-run controller-gen after changing one of those types — a
// pointer field added to a type whose generated DeepCopyInto is still
// `*out = *in` produces a copy that ALIASES the original.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/source"
)

// +kubebuilder:object:generate=true
type Step struct {
	Name string `json:"name" jsonschema:"title=Name,description=Unique name for this step in the policy"`
	// Title and Description say in plain language what this step's evidence is for. Documentation
	// only: verification never reads them. The author's signature covers them with the rules, so a
	// countersigner approves the words and the rules together.
	Title            string        `json:"title,omitempty" jsonschema:"title=Title,description=Plain-language name of this step (documentation only)"`
	Description      string        `json:"description,omitempty" jsonschema:"title=Description,description=Plain-language account of what this step's evidence is for (documentation only)"`
	Functionaries    []Functionary `json:"functionaries" jsonschema:"title=Functionaries,description=Authorized signers whose attestations are accepted for this step"`
	Attestations     []Attestation `json:"attestations" jsonschema:"title=Attestations,description=Required attestation types and their associated policies"`
	ArtifactsFrom    []string      `json:"artifactsFrom,omitempty" jsonschema:"title=Artifacts From,description=Other step names whose products must match this step's materials"`
	AttestationsFrom []string      `json:"attestationsFrom,omitempty" jsonschema:"title=Attestations From,description=Other step names whose attestation data is accessible during Rego evaluation"`
	ExternalFrom     []string      `json:"externalFrom,omitempty" jsonschema:"title=External From,description=Names of external attestations (from Policy.ExternalAttestations) whose predicates are accessible during Rego evaluation as input.external.<name>"`

	// AllowedUntracked declares material paths that may appear in this
	// step's collection WITHOUT a chain-of-custody proof binding them
	// to an upstream step. Use sparingly: every entry is a hole in the
	// chain-of-custody guarantee. It only has effect on a step with
	// ArtifactsFrom.
	//
	// Pattern semantics: each entry is a gobwas/glob pattern compiled
	// with '/' as the separator ('*' stays within one path segment, '**'
	// crosses segments). It is matched against the material path exactly
	// as the material attestor recorded it (usually relative to the
	// step's working directory) after a lexical path.Clean, with no
	// absolute/relative normalization: '/vendor/**' does not match
	// 'vendor/a.go'. An invalid or empty pattern fails Policy.Validate.
	//
	// Typical use: toolchain or cache files the policy does not model as
	// separate steps, e.g. 'vendor/**' or '/usr/lib/**' when the
	// material attestor records absolute paths.
	//
	// Enforcement is gated by HardeningOptions.EnforceAllowedUntracked, part
	// of EnforcedHardening (installed by the cilock CLI and by Judge at
	// startup). Only an embedder that never calls SetHardening gets the
	// WARN-only pre-#9815 behavior. When enforced:
	//
	// Empty (the default) means strict mode: every material the step
	// claims to have consumed MUST have been produced by an accepted
	// upstream ArtifactsFrom collection (same path, matching digest).
	// A material that is absent upstream and matches no pattern rejects
	// the collection (ErrUntrackedMaterials, #9815). A pattern never
	// excuses a DIGEST MISMATCH on a path upstream did produce, and the
	// ">= 1 shared path" overlap rule still applies.
	AllowedUntracked []string `json:"allowedUntracked,omitempty" jsonschema:"title=Allowed Untracked,description=Glob patterns for material paths permitted without a chain-of-custody proof (e.g. '/usr/lib/**' for build toolchain). Each entry weakens chain integrity; use sparingly."`

	// RequiredArtifacts names the artifacts this step MUST have consumed from
	// its artifactsFrom steps (#9946). Each entry is a glob (gobwas/glob, '/'
	// separator, matched against the lexically cleaned material path) that at
	// least one of this step's materials must match, where that material's
	// path is also an artifact of an accepted artifactsFrom collection. Such a
	// path's digest was already compared by the artifactsFrom check, so a match
	// proves this step consumed exactly the bytes the upstream step recorded.
	//
	// Without it, artifactsFrom is satisfied by ANY shared path. A release sign
	// step that never recorded the binary, or signed a different one, passed on
	// the shared system libraries alone. It is not gated by any hardening
	// option: a policy that declares it always enforces it, and an
	// absent match fails closed.
	RequiredArtifacts []string `json:"requiredArtifacts,omitempty" jsonschema:"title=Required Artifacts,description=Glob patterns of which each must match a material that an artifactsFrom step produced with an equal digest (e.g. '/tmp/build/cilock{,.exe}'). Fails closed when no such material exists."`

	// TimestampConstraint requires this step's collections to carry an
	// RFC3161 TSA-verified signing time inside the declared window
	// (notBefore/notAfter) and/or within maxAge of verification time.
	// Enforced by the verifier against the TSA-VERIFIED time, never against
	// self-asserted attestor timestamps. Fail-closed: when set, collections
	// without a verified TSA timestamp are rejected. This is the FedRAMP-20x
	// "scan/evidence newer than N days" primitive.
	TimestampConstraint *TimestampConstraint `json:"timestampConstraint,omitempty" jsonschema:"title=Timestamp Constraint,description=Time-interval requirement on the RFC3161 TSA-verified signing time of this step's evidence (notBefore/notAfter window and/or maxAge relative to verification time). Fail-closed when evidence carries no verified TSA timestamp."`

	// About GRANTS the step reach; it is never a requirement. The one value,
	// StepAboutSource, lets the step also take witnesses about the commit the
	// verified artifact was built from, reached through a declared link from
	// the image to the build that produced it and on to that build's commit.
	//
	// It only ever adds candidates. The step keeps every witness it accepts
	// without About (the evidence the caller's seeds find, depth 0), and each
	// candidate must still pass the step's functionaries, attestations and
	// Rego. So About never admits a witness the same step without it would
	// refuse, and never turns a passing step into a failing one.
	//
	// What it admits today: exactly what the step admits without it, the
	// depth-0 witnesses. The link is not implemented yet, so About changes no
	// verdict on its own; a policy that relies on source evidence must still
	// seed the commit (cilock verify -s sha1:<commit>).
	//
	// Where it is refused, before any evidence is read: any value but
	// StepAboutSource (about-unknown-value), and any About on a Policy that
	// DecodePolicyEnvelope did not decode from a PolicyPredicateV02 envelope
	// (about-needs-policy-v0.2), which includes a Policy built in code or
	// decoded with json.Unmarshal. cilock's policy commands choose v0.2 when a
	// step declares About. omitempty keeps every v0.1 document byte-identical.
	About string `json:"about,omitempty" jsonschema:"title=About,enum=source,description=Grants this step reach; never a requirement. 'source' lets the step also accept evidence about the commit the verified artifact was built from; the step keeps every witness it accepts without it. Requires policy predicate type https://aflock.ai/policy/v0.2."`
}

// ExternalAttestation describes a bare-predicate DSSE envelope (non-Collection)
// that the policy engine verifies as first-class evidence alongside step
// collections. External attestations are matched by predicate type + policy
// seed subjects, validated against their own Functionaries and RegoPolicies,
// and do NOT participate in the Collection subject-graph / BackRef traversal.
//
// See issue #39 for the full design.
//
// +kubebuilder:object:generate=true
type ExternalAttestation struct {
	Name          string        `json:"name" jsonschema:"title=Name,description=Unique name for this external attestation; referenced by Step.ExternalFrom"`
	PredicateType string        `json:"predicateType" jsonschema:"title=Predicate Type,description=Statement predicateType URI to match (e.g. https://slsa.dev/provenance/v1)"`
	Functionaries []Functionary `json:"functionaries" jsonschema:"title=Functionaries,description=Authorized signers for this external attestation"`
	RegoPolicies  []RegoPolicy  `json:"regopolicies,omitempty" jsonschema:"title=Rego Policies,description=Rego policies evaluated against the bare predicate (input is the predicate itself)"`
	AiPolicies    []AiPolicy    `json:"aipolicies,omitempty" jsonschema:"title=AI Policies,description=AI policies evaluated against the bare predicate"`
	Required      bool          `json:"required" jsonschema:"title=Required,description=When true (default), verification fails if no envelope matches; when false, absence is tolerated"`

	// CommitSubject is the exact subject-name prefix that names a commit for
	// THIS external, e.g. "https://pushgate.dev/v0.1/commithash:" for a
	// Pushgate VSA. It is an opt-in to the SHA-1 subject arm, scoped to this
	// external alone: a signed subject named exactly <CommitSubject><sha>, with
	// a sha1 digest of that same 40-hex, non-null value, may match a requested
	// commit digest, and under commit binding it binds the envelope to <sha>.
	// The prefix is compared case-exact; only the hex digest is case-folded.
	// It never applies to an attestation collection, and a second external of
	// the same predicate type without it does not inherit it.
	//
	// Shape (cryptoutil.ValidateCommitSubjectPrefix): printable ASCII with no
	// whitespace, at most 256 bytes, ending in "/commithash:", after an
	// absolute URL namespace with a lower-case scheme and a host. Empty (the
	// default) keeps the strict guard: SHA-1 subjects never match.
	CommitSubject string `json:"commitSubject,omitempty" jsonschema:"title=Commit Subject,description=Exact subject-name prefix naming a commit for this external (e.g. https://pushgate.dev/v0.1/commithash:). Opts this external alone into matching a SHA-1 commit subject spelled <prefix><40-hex sha> and binds it under commit binding. Must end in /commithash: after an absolute URL; no whitespace."`

	// ChildPolicyDigest binds a VSA external to one child policy: only envelopes whose
	// predicate.policy.digest.sha256 equals it can decide the external. Without it,
	// externals match on predicate type, so any child's passing VSA satisfies every
	// external of that type. Modeled in formal/cilock-evaluators (Nested.lean).
	ChildPolicyDigest string `json:"childPolicyDigest,omitempty" jsonschema:"title=Child Policy Digest,description=sha256 of the child policy payload; only VSAs produced by that policy can decide this external"`

	// TimestampConstraint admits only envelopes whose functionary-matched signature
	// carries an RFC3161 TSA-verified time inside the window (and not in the future).
	// When it or ChildPolicyDigest is set, the latest admitted envelopes decide: the
	// external passes only if every admitted envelope at the latest verified time
	// passed, so an older passing VSA cannot mask a newer failing one.
	TimestampConstraint *TimestampConstraint `json:"timestampConstraint,omitempty" jsonschema:"title=Timestamp Constraint,description=Time window on the TSA-verified signing time of the external envelope; the latest admitted envelope decides"`
}

// UnmarshalJSON applies the documented default for Required: when the "required"
// key is ABSENT, the external attestation is treated as REQUIRED (fail-closed),
// matching the jsonschema contract ("When true (default), verification fails if
// no envelope matches"). Without this, the Go zero value (false) would silently
// turn a mandatory external (e.g. SLSA provenance or a VSA) into an optional
// one, so a policy author who omits the field per the documented default gets an
// unenforced gate. An explicit "required": false still opts out.
func (e *ExternalAttestation) UnmarshalJSON(data []byte) error {
	type alias ExternalAttestation
	if err := json.Unmarshal(data, (*alias)(e)); err != nil {
		return err
	}
	var probe struct {
		Required *bool `json:"required"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	e.Required = probe.Required == nil || *probe.Required
	return nil
}

// +kubebuilder:object:generate=true
type Functionary struct {
	Type           string         `json:"type" jsonschema:"title=Type,description=Type of functionary (publickey or root)"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty" jsonschema:"title=Certificate Constraint,description=X.509 certificate constraints the functionary must satisfy"`
	PublicKeyID    string         `json:"publickeyid,omitempty" jsonschema:"title=Public Key ID,description=ID of a public key from the policy's publickeys map"`
}

// AiPolicy is a single AI-evaluated assertion about one attestation.
//
// It has two mutually exclusive forms, and a policy MUST pick exactly one:
//
//   - GENERATIVE (Prompt): free text is sent to the model, which answers with
//     {"status":"PASS|FAIL","reason":"..."}. This is the original and only
//     shape the engine can evaluate today.
//   - TYPED DECISION (Decision): the model answers a constrained question —
//     yes/no, a choice from a fixed option set, or an ordinal score — and the
//     POLICY, not the model, decides PASS/FAIL from that answer against
//     explicit assertions.
//
// Field order and JSON tags are load-bearing: policies are SIGNED, so a
// generative policy written before Decision existed must serialize to exactly
// the same bytes afterwards. Everything added here is additive and omitempty.
//
// +kubebuilder:object:generate=true
type AiPolicy struct {
	Name string `json:"name" jsonschema:"title=Name,description=Human-readable name for this AI policy; must be unique within an attestation"`
	// Prompt is the generative form. Mutually exclusive with Decision.
	// It gained omitempty when Decision was introduced, so a decision policy
	// does not carry an empty "prompt" key.
	Prompt   string      `json:"prompt,omitempty" jsonschema:"title=Prompt,description=Prompt text sent to the AI model for evaluation; mutually exclusive with decision"`
	Model    string      `json:"model,omitempty" jsonschema:"title=Model,description=AI model to use for evaluation"`
	Decision *AiDecision `json:"decision,omitempty" jsonschema:"title=Decision,description=Typed decision form; the model answers a constrained question and the policy decides PASS/FAIL from the answer. Mutually exclusive with prompt."`
}

// AiDecision is the typed-decision form of an AI policy. Exactly one of YesNo,
// Choice or Score must be set — the three are different question shapes, not
// composable clauses.
//
// +kubebuilder:object:generate=true
type AiDecision struct {
	// State optionally projects the attestor down to the subset of its data
	// the question is about, using the same Rego machinery as regopolicies.
	// Omitted means the whole attestor is the question's state.
	State *RegoPolicy `json:"state,omitempty" jsonschema:"title=State,description=Optional Rego projection selecting the attestor data the question is asked about; omitted means the whole attestor"`

	YesNo  *AiYesNo  `json:"yesNo,omitempty" jsonschema:"title=Yes/No,description=A boolean question scored as a probability"`
	Choice *AiChoice `json:"choice,omitempty" jsonschema:"title=Choice,description=A single selection from a fixed set of named options"`
	Score  *AiScore  `json:"score,omitempty" jsonschema:"title=Score,description=An ordinal score over a fixed ladder of levels"`
}

// AiYesNo asks a boolean question and asserts on the probability of "yes".
//
// The probability bounds are POINTERS on purpose. `maxProbability: 0.0` is the
// meaningful assertion "this must be impossible"; a bare float64 with omitempty
// would serialize it away and silently turn the strictest assertion in the
// language into no assertion at all.
//
// +kubebuilder:object:generate=true
type AiYesNo struct {
	Instructions   string            `json:"instructions" jsonschema:"title=Instructions,description=The yes/no question put to the model"`
	Criteria       map[string]string `json:"criteria,omitempty" jsonschema:"title=Criteria,description=Named clarifications the model must weigh when answering"`
	MinProbability *float64          `json:"minProbability,omitempty" jsonschema:"title=Min Probability,description=The answer's probability of yes must be at least this (0..1)"`
	MaxProbability *float64          `json:"maxProbability,omitempty" jsonschema:"title=Max Probability,description=The answer's probability of yes must be at most this (0..1); 0 asserts impossibility"`
}

// AiChoice asks the model to pick exactly one of a fixed set of named options
// and asserts on which option may be picked, and with what confidence.
//
// +kubebuilder:object:generate=true
type AiChoice struct {
	Instructions string            `json:"instructions" jsonschema:"title=Instructions,description=The question put to the model"`
	Options      map[string]string `json:"options" jsonschema:"title=Options,description=The selectable options as id -> description; the model must answer with one id"`
	Allow        []string          `json:"allow,omitempty" jsonschema:"title=Allow,description=Option ids that PASS; every entry must be a key of options"`
	Deny         []string          `json:"deny,omitempty" jsonschema:"title=Deny,description=Option ids that FAIL; every entry must be a key of options"`

	// MinConfidence lives on AiChoice and NOT on AiYesNo, and that is a
	// constraint rather than a style choice: a confidence value comes back
	// only with a choice or a score answer, never with a yes/no. A yes/no
	// answer IS a probability, which is what AiYesNo's minProbability and
	// maxProbability assert on. A policy that writes `minConfidence` under a
	// yesNo is refused at decode time (see ai_decode.go) rather than silently
	// dropped, because a dropped assertion reads as a confidence floor while
	// asserting nothing at all.
	MinConfidence *float64 `json:"minConfidence,omitempty" jsonschema:"title=Min Confidence,description=The chosen option's confidence must be at least this (0..1). Only choice and score answers carry a confidence; a yes/no never does."`
}

// AiScore asks the model for an ordinal score over a fixed ladder of levels.
// The score is the INDEX of the chosen level, so valid bounds run from 0 to
// len(Levels)-1.
//
// +kubebuilder:object:generate=true
type AiScore struct {
	Instructions string   `json:"instructions" jsonschema:"title=Instructions,description=The question put to the model"`
	Levels       []string `json:"levels" jsonschema:"title=Levels,description=The ordered ladder of levels, lowest first; the score is an index into this list"`
	MinScore     *float64 `json:"minScore,omitempty" jsonschema:"title=Min Score,description=The score must be at least this; within [0, len(levels)-1]"`
	MaxScore     *float64 `json:"maxScore,omitempty" jsonschema:"title=Max Score,description=The score must be at most this; within [0, len(levels)-1]"`
}

// +kubebuilder:object:generate=true
type Attestation struct {
	Type         string       `json:"type" jsonschema:"title=Type,description=Attestation type URI that must be present in the collection"`
	RegoPolicies []RegoPolicy `json:"regopolicies" jsonschema:"title=Rego Policies,description=Rego policies to evaluate against the attestation data"`
	AiPolicies   []AiPolicy   `json:"aipolicies" jsonschema:"title=AI Policies,description=AI-based policies to evaluate against the attestation data"`
}

// +kubebuilder:object:generate=true
type RegoPolicy struct {
	Module []byte `json:"module" jsonschema:"title=Module,description=Base64-encoded Rego policy module source code"`
	Name   string `json:"name" jsonschema:"title=Name,description=Human-readable name for this Rego policy"`
	// Checks maps each check this module can deny (its "check:<id>" deny messages) to a plain-language
	// statement of what must be true for it to pass. Documentation only: verification never reads it.
	Checks map[string]string `json:"checks,omitempty" jsonschema:"title=Checks,description=Check id to a plain-language statement of what must be true (documentation only)"`
}

// StepResult contains information about the verified collections for each step.
// Passed contains the collections that passed any rego policies and all expected attestations exist.
// Rejected contains the rejected collections and the error that caused them to be rejected.
type StepResult struct {
	Step     string
	Passed   []PassedCollection
	Rejected []RejectedCollection
}

// PassedCollection contains a collection that passed verification along with any AI responses
type PassedCollection struct {
	Collection  source.CollectionVerificationResult
	AiResponses []AiResponse `json:"AiResponses,omitempty"`

	// rawPayload is the verified raw signed payload (the DSSE payload bytes),
	// retained at gate time when the decoded bodies are compacted away
	// (compactPassed). It is the single rehydration source for the
	// post-decision re-readers: verifyCollectionArtifacts' inline-leaf /
	// materials checks and buildStepContext's cross-step Rego input
	// (hydratedCollection). Unexported by design: it never serializes, so the
	// step-results JSON shape is unchanged. Empty for collections that did
	// not travel the byte-retaining VerifiedSource path (e.g. direct test
	// construction) — those keep their full decoded bodies and never
	// rehydrate.
	rawPayload []byte

	// contentKey is the pass-time content identity (payloadContentKey),
	// computed while the verified payload and signer set are in hand so the
	// cross-depth merge never has to re-marshal a multi-MB statement — and
	// never falls into the released-bytes fallback identity. Empty for
	// directly-constructed collections; passedCollectionKeyOf then computes
	// the legacy statement-marshal key instead.
	contentKey string
}

// hydratedCollection returns the full parsed Collection for this passed
// collection. A compacted collection (bodies dropped at gate time) is
// re-decoded from the retained raw signed payload — the same bytes, the same
// in-process attestor registry, therefore the same typed result as the
// original decode. An uncompacted collection is returned as stored.
func (p PassedCollection) hydratedCollection() (attestation.Collection, error) {
	if len(p.Collection.Collection.Attestations) > 0 || len(p.rawPayload) == 0 {
		return p.Collection.Collection, nil
	}
	stmt := intoto.Statement{}
	if err := json.Unmarshal(p.rawPayload, &stmt); err != nil {
		return attestation.Collection{}, fmt.Errorf("rehydrate %s: failed to unmarshal statement: %w", p.Collection.Reference, err)
	}
	coll := attestation.Collection{}
	if err := json.Unmarshal(stmt.Predicate, &coll); err != nil {
		return attestation.Collection{}, fmt.Errorf("rehydrate %s: failed to unmarshal collection: %w", p.Collection.Reference, err)
	}
	return coll, nil
}

// HydratedCollection is the public form of hydratedCollection: the COMPLETE
// typed Collection for this passed collection, re-decoded on demand from the
// retained raw signed payload when pass-time compaction dropped the decoded
// bodies. Callers that read passed-evidence content beyond the compact set
// (subjects, name, references, verifiers) — e.g. inline-leaf inclusion
// proofs, attestor inspection — must go through this accessor rather than
// reading Collection.Collection directly. Lazy by design: the decode cost is
// paid per call, only by consumers that need the bodies, so the verify-time
// memory profile is unchanged.
func (p PassedCollection) HydratedCollection() (attestation.Collection, error) {
	return p.hydratedCollection()
}

// hydratedResult returns the CollectionVerificationResult as it looked
// BEFORE pass-time compaction: full Statement (including the raw Predicate
// message) and full typed Collection, with the envelope bytes still released
// (VerifiedSource dropped payload/signatures from results upstream of the
// gate — that predates compaction and is not undone here). Used by
// MarshalJSON so serialized passed evidence is byte-identical to the
// pre-compaction contract. An uncompacted collection returns as stored.
func (p PassedCollection) hydratedResult() (source.CollectionVerificationResult, error) {
	if len(p.Collection.Collection.Attestations) > 0 || len(p.rawPayload) == 0 {
		return p.Collection, nil
	}
	stmt := intoto.Statement{}
	if err := json.Unmarshal(p.rawPayload, &stmt); err != nil {
		return source.CollectionVerificationResult{}, fmt.Errorf("rehydrate %s: failed to unmarshal statement: %w", p.Collection.Reference, err)
	}
	coll := attestation.Collection{}
	if err := json.Unmarshal(stmt.Predicate, &coll); err != nil {
		return source.CollectionVerificationResult{}, fmt.Errorf("rehydrate %s: failed to unmarshal collection: %w", p.Collection.Reference, err)
	}
	full := p.Collection
	full.Statement = stmt
	full.Collection = coll
	return full, nil
}

// MarshalJSON implements the json.Marshaler interface for PassedCollection.
// A compacted collection serializes from its retained raw payload
// (hydratedResult), so the JSON a caller receives — step results persisted
// by the workflow engine, UI/GraphQL consumers, anything downstream of
// Policy.Verify — carries the FULL statement and typed collection,
// byte-identical to the pre-compaction contract. Compaction is an internal
// memory representation; it must never leak into serialized output.
func (p PassedCollection) MarshalJSON() ([]byte, error) {
	full, err := p.hydratedResult()
	if err != nil {
		// Fail closed: emitting silently-gutted evidence would be worse than
		// a loud serialization error, and the payload decoded successfully
		// once at verification time so this path is not reachable for any
		// collection the gate actually passed.
		return nil, err
	}
	return json.Marshal(&struct {
		Collection  source.CollectionVerificationResult `json:"Collection"`
		AiResponses []AiResponse                        `json:"AiResponses,omitempty"`
	}{
		Collection:  full,
		AiResponses: p.AiResponses,
	})
}

// Analyze inspects the StepResult to determine if the step passed or failed.
// We do this rather than failing at the first point of failure in the verification flow
// in order to save the failure reasons so we can present them all at the end of the verification process.
func (r StepResult) Analyze() bool {
	var pass bool
	if len(r.Passed) > 0 {
		pass = true
	}

	for _, coll := range r.Passed {
		// we don't fail on warnings so we process these under debug logs
		if len(coll.Collection.Warnings) > 0 {
			for _, warn := range coll.Collection.Warnings {
				log.Debug("Warning: Step: %s, Collection: %s, Warning: %s", r.Step, coll.Collection.Collection.Name, warn)
			}
		}

		// Want to ensure that undiscovered errors aren't lurking in the passed collections
		if len(coll.Collection.Errors) > 0 {
			for _, err := range coll.Collection.Errors {
				pass = false
				log.Errorf("Unexpected Error in Passed Collection: Step: %s, Collection: %s, Error: %s", r.Step, coll.Collection.Collection.Name, err)
			}
		}
	}

	return pass
}

func (r StepResult) HasErrors() bool {
	return len(r.Rejected) > 0
}

func (r StepResult) HasPassed() bool {
	return len(r.Passed) > 0
}

func (r StepResult) Error() string {
	errs := make([]string, len(r.Rejected))
	for i, reject := range r.Rejected {
		errs[i] = reject.Reason.Error()
	}

	return fmt.Sprintf("attestations for step %v could not be used due to:\n%v", r.Step, strings.Join(errs, "\n"))
}

type RejectedCollection struct {
	Collection  source.CollectionVerificationResult
	Reason      error
	AiResponses []AiResponse `json:"AiResponses,omitempty"`
}

// ExternalResult contains information about verified external attestations
// for a single Policy.ExternalAttestations entry. Mirrors StepResult but
// carries StatementEnvelopes (bare predicate DSSEs) instead of Collections.
//
// Passed contains envelopes whose functionary matched and whose Rego/AI
// policies all succeeded. Rejected captures mismatches with the reason.
// Skipped is true when the external attestation was not required and no
// matching envelope was found — a legitimate "pass" that nevertheless
// contributes nothing to downstream Rego input.
//
// Unbound holds candidates the search returned that are not about the verify's
// subject: refused by the commit binding or by the verified source's
// substitution guard. They are kept for diagnostics and never count as found,
// so an external whose every candidate is unbound is Skipped (or missing, when
// required) exactly as if the search had returned nothing.
type ExternalResult struct {
	Name     string
	Passed   []PassedExternal
	Rejected []RejectedExternal
	Unbound  []RejectedExternal `json:"Unbound,omitempty"`
	Skipped  bool
}

// PassedExternal holds an external attestation envelope that passed
// functionary and rego/AI policy evaluation.
type PassedExternal struct {
	Envelope    source.StatementEnvelope
	AiResponses []AiResponse `json:"AiResponses,omitempty"`
}

// MarshalJSON implements json.Marshaler for PassedExternal.
func (p PassedExternal) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Envelope    source.StatementEnvelope `json:"Envelope"`
		AiResponses []AiResponse             `json:"AiResponses,omitempty"`
	}{
		Envelope:    p.Envelope,
		AiResponses: p.AiResponses,
	})
}

// RejectedExternal holds an external attestation envelope that failed
// verification along with the reason.
type RejectedExternal struct {
	Envelope    source.StatementEnvelope
	Reason      error
	AiResponses []AiResponse `json:"AiResponses,omitempty"`
}

// MarshalJSON implements json.Marshaler for RejectedExternal so that the
// Reason field (an error interface) serializes to a useful string instead
// of `{}`.
func (r RejectedExternal) MarshalJSON() ([]byte, error) {
	var reasonStr string
	if r.Reason != nil {
		reasonStr = r.Reason.Error()
	}
	return json.Marshal(&struct {
		Envelope    source.StatementEnvelope `json:"Envelope"`
		Reason      string                   `json:"Reason"`
		AiResponses []AiResponse             `json:"AiResponses,omitempty"`
	}{
		Envelope:    r.Envelope,
		Reason:      reasonStr,
		AiResponses: r.AiResponses,
	})
}

// Analyze returns true iff the external attestation is considered satisfied.
// A Skipped (not-required, not-found) external passes. An external with at
// least one Passed envelope passes. Anything else fails.
func (r ExternalResult) Analyze() bool {
	if r.Skipped {
		return true
	}
	return len(r.Passed) > 0
}

// MarshalJSON implements the json.Marshaler interface to properly serialize the Reason field
// which is an error interface that would otherwise serialize to an empty object {}
func (r RejectedCollection) MarshalJSON() ([]byte, error) {
	var reasonStr string
	if r.Reason != nil {
		reasonStr = r.Reason.Error()
	}

	return json.Marshal(&struct {
		Collection  source.CollectionVerificationResult `json:"Collection"`
		Reason      string                              `json:"Reason"`
		AiResponses []AiResponse                        `json:"AiResponses,omitempty"`
	}{
		Collection:  r.Collection,
		Reason:      reasonStr,
		AiResponses: r.AiResponses,
	})
}

func (f Functionary) Validate(verifier cryptoutil.Verifier, trustBundles map[string]TrustBundle) error {
	verifierID, err := verifier.KeyID()
	if err != nil {
		return fmt.Errorf("could not get key id: %w", err)
	}

	if f.PublicKeyID != "" && f.PublicKeyID == verifierID {
		// R3_184 (#6266): the PublicKeyID match short-circuits before
		// CertConstraint.Check runs, so a functionary that sets BOTH fields has
		// its certificate constraint silently ignored on a key-ID match.
		if f.CertConstraint.IsSet() {
			if Hardening().EnforceCertConstraintOnKeyIDMatch {
				return f.enforceCertConstraintAfterKeyIDMatch(verifier, trustBundles, verifierID)
			}
			// Warn-first (default): the constraint is silently ignored on a key-ID
			// match, so surface the misconfiguration loudly instead.
			log.Warn("functionary sets both PublicKeyID and CertConstraint; the certificate constraint is IGNORED when the key ID matches (enforcement tracked in #6266)")
		}
		return nil
	}

	x509Verifier, ok := verifier.(*cryptoutil.X509Verifier)
	if !ok {
		return fmt.Errorf("verifier with ID %v is not a public key verifier or a x509 verifier", verifierID)
	}

	if len(f.CertConstraint.Roots) == 0 {
		return fmt.Errorf("verifier with ID %v is an x509 verifier, but no trusted roots provided in functionary", verifierID)
	}

	if err := f.CertConstraint.Check(x509Verifier, trustBundles); err != nil {
		return fmt.Errorf("verifier with ID %v doesn't meet certificate constraint: %w", verifierID, err)
	}

	return nil
}

// enforceCertConstraintAfterKeyIDMatch runs f.CertConstraint against the verifier
// even though the PublicKeyID already matched (R3_184 enforcement, opt-in via
// HardeningOptions.EnforceCertConstraintOnKeyIDMatch). A raw public-key verifier
// cannot satisfy an X.509 constraint, so a CertConstraint set alongside a
// PublicKeyID on a non-x509 verifier fails closed here.
func (f Functionary) enforceCertConstraintAfterKeyIDMatch(verifier cryptoutil.Verifier, trustBundles map[string]TrustBundle, verifierID string) error {
	x509Verifier, ok := verifier.(*cryptoutil.X509Verifier)
	if !ok {
		return fmt.Errorf("verifier with ID %v matched PublicKeyID but sets an X.509 CertConstraint it cannot satisfy (not an x509 verifier) (#6266)", verifierID)
	}
	if len(f.CertConstraint.Roots) == 0 {
		return fmt.Errorf("verifier with ID %v matched PublicKeyID but its CertConstraint provides no trusted roots (#6266)", verifierID)
	}
	if err := f.CertConstraint.Check(x509Verifier, trustBundles); err != nil {
		return fmt.Errorf("verifier with ID %v matched PublicKeyID but failed its certificate constraint: %w", verifierID, err)
	}
	return nil
}

// buildStepContext extracts attestation data from already-verified steps referenced
// by AttestationsFrom. The result is a map[stepName]->stepData passed into Rego policy
// evaluation as input.steps, where stepData carries two views of the same evidence:
//
//   - input.steps.<step>.collections: a list with one entry per passed collection,
//     {reference, name, attestations{<type>: attestorJSON}}, ordered by collection
//     reference (ties keep discovery order). This is the shape new rules should read;
//     it is complete and its order does not depend on which source answered first.
//   - input.steps.<step>.<type>: the attestor of that type from the FIRST collection in
//     that same order. Kept for existing policies (deprecated; see warnLegacyStepsShape).
//     Before 2026-09-18 "first" meant first discovered, so a step with several passed
//     collections could yield a different value from one verify to the next. F17 (#5746)
//     ruled out last-writer-wins because a later collection could shadow the legitimate
//     one; ordering by reference keeps that property and adds determinism.
func buildStepContext(attestationsFrom []string, resultsByStep map[string]StepResult) map[string]interface{} { //nolint:gocognit
	if len(attestationsFrom) == 0 {
		return nil
	}

	ctx := make(map[string]interface{})
	for _, depStep := range attestationsFrom {
		result, ok := resultsByStep[depStep]
		if !ok || len(result.Passed) == 0 {
			continue
		}

		ordered := make([]PassedCollection, len(result.Passed))
		copy(ordered, result.Passed)
		sort.SliceStable(ordered, func(i, j int) bool {
			return ordered[i].Collection.Reference < ordered[j].Collection.Reference
		})

		stepData := make(map[string]interface{})
		collections := make([]interface{}, 0, len(ordered))
		for _, pc := range ordered {
			// A gate-compacted collection rehydrates its typed attestors from
			// the retained raw payload; an uncompacted one is returned as
			// stored. A rehydration failure is treated exactly like the
			// pre-existing marshal/decode failure modes below: log and skip.
			coll, err := pc.hydratedCollection()
			if err != nil {
				log.Debugf("failed to rehydrate collection %s from step %s for rego context: %v", pc.Collection.Reference, depStep, err)
				continue
			}
			attestors := make(map[string]interface{})
			for _, att := range coll.Attestations {
				// Marshal the attestor to a generic map so Rego can traverse it.
				b, err := json.Marshal(att.Attestation)
				if err != nil {
					log.Debugf("failed to marshal attestation %s from step %s: %v", att.Type, depStep, err)
					continue
				}
				var data interface{}
				dec := json.NewDecoder(bytes.NewReader(b))
				dec.UseNumber()
				if err := dec.Decode(&data); err != nil {
					log.Debugf("failed to decode attestation %s from step %s: %v", att.Type, depStep, err)
					continue
				}
				if _, exists := attestors[att.Type]; !exists {
					attestors[att.Type] = data
				}
				// Legacy per-type key: first collection in reference order wins; later
				// collections never overwrite it (F17, #5746).
				if _, exists := stepData[att.Type]; exists {
					log.Debugf("input.steps.%s[%s]: keeping the first collection in reference order, ignoring %s (use .collections for all of them)", depStep, att.Type, pc.Collection.Reference)
					continue
				}
				stepData[att.Type] = data
			}
			entry := map[string]interface{}{
				"reference":    pc.Collection.Reference,
				"name":         coll.Name,
				"attestations": attestors,
			}
			// The verified TSA time, never a payload field: attestor JSON lives
			// under "attestations", so the signer cannot write this key (#10528).
			if ts, ok := regoTSATime(pc.Collection); ok {
				entry[regoTSATimeKey] = ts
			}
			collections = append(collections, entry)
		}
		// Backward compatibility: a dependency whose passed collections carry no decodable
		// attestor has never appeared under input.steps, so `not input.steps.<step>` rules
		// keep firing for it. The list is attached only when the step key exists at all.
		if len(stepData) > 0 {
			stepData[stepCollectionsKey] = collections
			ctx[depStep] = stepData
		}
	}

	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

// stepCollectionsKey is the key under input.steps.<step> that carries the complete,
// deterministically ordered list of passed collections. Attestation types are URIs, so
// the key cannot collide with a type.
const stepCollectionsKey = "collections"

// buildStepRegoContext combines buildStepContext (for AttestationsFrom) and
// an external-attestation context (for ExternalFrom) into the shape the
// policy engine hands to Rego. When neither *From list is set this returns
// nil so that backward-compatible input = raw attestor JSON applies.
//
// When any *From list is non-empty, the returned map is the union of:
//   - cross-step context under the map itself (consumed by EvaluateRegoPolicy
//     which wraps it under input.steps.<name>.<type>)
//   - external-attestation entries under the magic key
//     externalAttestationsContextKey so EvaluateRegoPolicy can lift them to
//     input.external.<name>.
//
// The external value for a given name is the first Passed envelope's
// attestor marshaled to JSON. When the external was Skipped or has no
// Passed envelope, its entry is omitted so Rego `not input.external.x`
// works as expected.
func buildStepRegoContext(step Step, resultsByStep map[string]StepResult, externalResults map[string]ExternalResult) map[string]interface{} {
	if len(step.AttestationsFrom) == 0 && len(step.ExternalFrom) == 0 {
		return nil
	}

	ctx := make(map[string]interface{})

	if len(step.AttestationsFrom) > 0 {
		if err := checkDependencies(step.AttestationsFrom, resultsByStep); err != nil {
			log.Debugf("step %s: dependency not yet verified: %v", step.Name, err)
		} else {
			stepCtx := buildStepContext(step.AttestationsFrom, resultsByStep)
			for k, v := range stepCtx {
				ctx[k] = v
			}
		}
	}

	if external := collectExternalRegoContext(step, externalResults); len(external) > 0 {
		ctx[externalAttestationsContextKey] = external
	}

	if len(ctx) == 0 {
		// Non-nil empty context so Rego cross-step rules still fire (same
		// reasoning as verifySteps' empty stepCtx fallback).
		return map[string]interface{}{}
	}
	return ctx
}

// collectExternalRegoContext resolves each step.ExternalFrom entry to a
// JSON-decoded map suitable for inclusion under input.external.<name>.
// Missing/empty/error entries are silently skipped so Rego's
// `not input.external.<name>` fires as designed.
func collectExternalRegoContext(step Step, externalResults map[string]ExternalResult) map[string]interface{} {
	if len(step.ExternalFrom) == 0 {
		return nil
	}
	external := make(map[string]interface{}, len(step.ExternalFrom))
	for _, name := range step.ExternalFrom {
		data, ok := externalAttestorAsJSON(step, name, externalResults)
		if !ok {
			continue
		}
		external[name] = data
	}
	return external
}

// externalAttestorAsJSON returns the JSON-decoded form of the first passed
// envelope's attestor for the named external. Returns ok=false when the
// external is missing, has no passes, has a nil attestor, or fails to
// marshal/decode.
func externalAttestorAsJSON(step Step, name string, externalResults map[string]ExternalResult) (interface{}, bool) {
	er, ok := externalResults[name]
	if !ok || len(er.Passed) == 0 {
		return nil, false
	}
	first := er.Passed[0]
	if first.Envelope.Attestor == nil {
		return nil, false
	}
	b, err := json.Marshal(first.Envelope.Attestor)
	if err != nil {
		log.Debugf("step %s: failed to marshal external attestor %q: %v", step.Name, name, err)
		return nil, false
	}
	var data interface{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		log.Debugf("step %s: failed to decode external attestor %q: %v", step.Name, name, err)
		return nil, false
	}
	return data, true
}

// externalAttestationsContextKey is a reserved map key used to carry the
// external-attestation context from buildStepRegoContext to
// EvaluateRegoPolicy. It is not a valid step name (contains characters not
// allowed in step names per the schema) so it cannot collide.
const externalAttestationsContextKey = "__external__"

// checkDependencies verifies that all steps listed in AttestationsFrom have
// at least one passed collection in the results so far. Returns an error if any
// dependency has not been verified yet.
func checkDependencies(attestationsFrom []string, resultsByStep map[string]StepResult) error {
	for _, dep := range attestationsFrom {
		result, ok := resultsByStep[dep]
		if !ok || len(result.Passed) == 0 {
			return ErrDependencyNotVerified{Step: dep}
		}
	}
	return nil
}

// validateAttestations will test each collection against to ensure the expected attestations
// appear in the collection as well as that any rego policies pass for the step.
func (s Step) validateAttestations(collectionResults []source.CollectionVerificationResult, aiServerURL string, stepContext map[string]interface{}) StepResult {
	return s.validateAttestationsContext(context.Background(), collectionResults, aiServerURL, stepContext, nil)
}

func (s Step) validateAttestationsContext(ctx context.Context, collectionResults []source.CollectionVerificationResult, aiServerURL string, stepContext map[string]interface{}, provider AiProvider) StepResult {
	return s.collectGated(collectionResults, func(c source.CollectionVerificationResult) (gateOutcome, PassedCollection, RejectedCollection) {
		return s.gateOneContext(ctx, c, aiServerURL, stepContext, provider)
	})
}

// validateAttestationsBound is the batch arm's gate loop with the verify's
// commit binding in its path (gateBound), so the batch and streamed arms
// apply the same per-collection verdict.
func (s Step) validateAttestationsBound(ctx context.Context, collectionResults []source.CollectionVerificationResult, vo *verifyOptions, stepContext map[string]interface{}) StepResult {
	return s.collectGated(collectionResults, func(c source.CollectionVerificationResult) (gateOutcome, PassedCollection, RejectedCollection) {
		return s.gateBound(ctx, c, vo, stepContext)
	})
}

// collectGated runs gate over each collection and sorts the verdicts into a
// StepResult.
func (s Step) collectGated(collectionResults []source.CollectionVerificationResult, gate func(source.CollectionVerificationResult) (gateOutcome, PassedCollection, RejectedCollection)) StepResult {
	result := StepResult{Step: s.Name}
	if len(collectionResults) <= 0 {
		return result
	}

	for _, collection := range collectionResults {
		switch outcome, pc, rc := gate(collection); outcome {
		case gatePassed:
			result.Passed = append(result.Passed, pc)
		case gateRejected:
			result.Rejected = append(result.Rejected, rc)
		case gateWrongName:
			// Skipped entirely (F10): the collection is not named for this
			// step, so it is neither passed nor rejected here.
		}
	}

	return result
}

// gateOutcome is the per-collection verdict of the step gate (gateOne).
type gateOutcome int

const (
	// gateWrongName: the collection is not named for this step and is skipped
	// entirely — neither passed nor rejected (F10, #5746).
	gateWrongName gateOutcome = iota
	gatePassed
	gateRejected
)

// gateOne runs the step gate's attestation checks against ONE
// functionary-authorized collection: exact step-name match, required
// attestation presence, and Rego/AI policy evaluation, followed by pass-time
// compaction (raw payload retained as the rehydration source, decoded bodies
// dropped) or rejection compaction. Extracted from the validateAttestations
// loop body so the interleaved per-candidate pipeline (verifyStepStreamed)
// and the batch path share one gate implementation and can never diverge on
// a verdict. The returned PassedCollection is valid only for gatePassed, the
// RejectedCollection only for gateRejected.
func (s Step) gateOne(collection source.CollectionVerificationResult, aiServerURL string, stepContext map[string]interface{}) (gateOutcome, PassedCollection, RejectedCollection) {
	return s.gateOneContext(context.Background(), collection, aiServerURL, stepContext, nil)
}

func (s Step) gateOneContext(ctx context.Context, collection source.CollectionVerificationResult, aiServerURL string, stepContext map[string]interface{}, provider AiProvider) (gateOutcome, PassedCollection, RejectedCollection) { //nolint:gocognit,gocyclo,funlen
	// F10 (#5746): require EXACT step-name equality. An empty collection
	// name must NOT match every step — previously `name == ""` was treated
	// as a wildcard, letting a name-less collection bypass the step-name
	// filter. Fail closed: only a collection explicitly named for this step
	// is considered.
	if collection.Collection.Name != s.Name {
		log.Debugf("Skipping collection %s as it is not for step %s", collection.Collection.Name, s.Name)
		return gateWrongName, PassedCollection{}, RejectedCollection{}
	}

	// input.collection.tsaTime: this collection's own verified signing time,
	// lifted by buildRegoInput when the input is wrapped (#10528).
	stepContext = withCurrentCollection(stepContext, collection)

	found := make(map[string][]attestation.CollectionAttestation)
	// []error, not []string: calling .Error() here is what severed every typed
	// cause from the consumer. See ErrCollectionValidationFailed.
	reasons := make([]error, 0)
	passed := true
	var allAiResponses []AiResponse

	// F9 (#5746): a step with NO required attestations is a misconfigured
	// no-op gate. It must NOT silently pass an arbitrary collection — that
	// is fail-open (a gate with no requirements rubber-stamps anything).
	// Reject the collection rather than accept it.
	if len(s.Attestations) == 0 {
		passed = false
		reasons = append(reasons, fmt.Errorf(
			"step %q declares no required attestations; a gate with no requirements rejects all collections (fail closed)",
			s.Name))
	}

	if len(collection.Errors) > 0 {
		passed = false
		for _, err := range collection.Errors {
			reasons = append(reasons, fmt.Errorf("collection verification failed: %w", err))
		}
	}

	// #9827: provenance under the pre-#9827 type is refused by name, and a
	// builder.id claiming a CI workflow identity must be the authorized
	// signer's Fulcio Build Signer URI, or the tenant who wrote the provenance
	// body could claim an isolated builder it never ran on.
	for _, att := range collection.Collection.Attestations {
		if err := checkSLSAProvenance(att.Attestation, collection.ValidFunctionaries, att.Type); err != nil {
			passed = false
			reasons = append(reasons, err)
		}
	}

	// G (#5747): collect ALL attestors per type, not just the last one. A
	// last-writer-wins map let a passing attestor shadow a failing attestor
	// of the same type, so a malicious duplicate could bypass the policy.
	for _, att := range collection.Collection.Attestations {
		found[att.Type] = append(found[att.Type], att)
		// Also register under the alternate URI so that policies
		// written with witness.dev URIs match aflock.ai attestations and
		// vice versa.
		if alt := attestation.LegacyAlternate(att.Type); alt != "" {
			found[alt] = append(found[alt], att)
		}
	}

	for _, expected := range s.Attestations {
		// Try both the original and alternate URI for the expected type.
		attestors, ok := found[expected.Type]
		if !ok {
			if alt := attestation.LegacyAlternate(expected.Type); alt != "" {
				attestors, ok = found[alt]
			}
		}
		if !ok || len(attestors) == 0 {
			passed = false
			reasons = append(reasons, ErrMissingAttestation{
				Step:        s.Name,
				Attestation: expected.Type,
			})
			// Skip policy evaluation — the attestation is missing so there is
			// nothing to evaluate. Continuing would pass a nil attestor to the
			// Rego/AI evaluators.
			continue
		}

		// G (#5747): evaluate EVERY attestor of this type. If ANY fails, the
		// collection fails — a passing duplicate must not shadow a failing
		// one (no last-writer-wins bypass).
		for _, entry := range attestors {
			attestor := entry.Attestation
			if err := EvaluateRegoPolicyForPredicateType(attestor, entry.Type, expected.RegoPolicies, stepContext); err != nil {
				passed = false
				reasons = append(reasons, err)
				// A deterministic rejection cannot be repaired by inference;
				// do not disclose the rejected predicate to an AI provider.
				continue
			}

			aiResponses, err := EvaluateAIPolicyWithProvider(ctx, attestor, expected.AiPolicies, aiServerURL, provider)
			if err != nil {
				passed = false
				reasons = append(reasons, err)
			}

			if len(aiResponses) > 0 { //nolint:nestif
				allAiResponses = append(allAiResponses, aiResponses...)

				if err == nil {
					for i, resp := range aiResponses {
						// Anything but an exact PASS fails the step (#9820):
						// the provider layer already refuses other statuses,
						// and the gate must not pass one if it ever gets here.
						if resp.Status != AiStatusPass {
							policyName := ""
							if i < len(expected.AiPolicies) {
								policyName = expected.AiPolicies[i].Name
							}
							if policyName == "" {
								policyName = fmt.Sprintf("AI Policy %d", i+1)
							}

							reason := fmt.Errorf("AI Policy '%s': %s - %s",
								policyName,
								resp.Status,
								resp.Reason)

							passed = false
							reasons = append(reasons, reason)
						}
					}
				}
			}
		}
	}

	if passed {
		pc := PassedCollection{
			Collection:  collection,
			AiResponses: allAiResponses,
		}
		// Pass-time compaction: when the collection traveled the
		// byte-retaining VerifiedSource path, move the raw payload aside,
		// stamp the content identity, and drop the decoded bodies. A
		// collection without retained payload (direct construction, legacy
		// sources) keeps its full decoded form — no rehydration source, no
		// compaction.
		if len(collection.Envelope.Payload) > 0 {
			pc.contentKey = payloadContentKey(collection)
			pc.rawPayload = collection.Envelope.Payload
			pc.Collection = compactPassed(collection)
		}
		return gatePassed, pc, RejectedCollection{}
	}

	return gateRejected, PassedCollection{}, RejectedCollection{
		Collection:  compactRejected(collection),
		Reason:      ErrCollectionValidationFailed{Reasons: reasons},
		AiResponses: allAiResponses,
	}
}
