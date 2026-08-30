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

package instructionfile

import (
	"fmt"
	"os"
	"sort"

	"github.com/invopop/jsonschema"
	"golang.org/x/term"
)

// SignerKind is the PRINCIPAL CLASS behind the credential that will sign this
// attestation: what sort of identity it belongs to, not what sort of key
// material it uses.
//
// This axis exists because the closest prior art grades something else.
// nono's `signer.kind` is exactly `"keyed"` or `"keyless"` — a closed set,
// and any other value is a hard parse error (nolabs-ai/nono,
// crates/nono/src/trust/dsse.rs:286-336, read from source 2026-08-27). That
// axis grades KEY MATERIAL, not principal.
//
// Read carefully, nono's `keyless` arm is workload-SHAPED: it hard-requires
// `issuer`, `repository`, `workflow_ref`, `subject` and `build_signer_uri`
// (dsse.rs:299-331), which a browser-OIDC session could not satisfy. So the
// problem is NOT that nono lets humans in through the keyless door. It is
// that the vocabulary cannot NAME a principal, and two things follow:
//
//   - A human's interactive session is unrepresentable. Signing locally lands
//     in `keyed`, which conflates "a static keystore key" with "a person".
//   - "Is this a workload?" can only be approximated as "is this keyless?",
//     which couples the check to GitHub-Actions-shaped fields, cannot express
//     a workload on another platform, and cannot say "not a human session".
//
// The case that matters is the ALPS 0.1 gap: an agent launched from a
// signed-in human shell inherits that human's platform session and signs with
// it — no ceremony, no human in the loop at the moment of signing. In
// cilock's own keyless browser-OIDC flow that credential is keyless AND
// human and carries no workflow_ref, so a keyed/keyless axis cannot classify
// it at all. KeyMaterial records nono's axis for interop; SignerKind names
// the principal, which is the thing a policy actually needs to gate on.
type SignerKind string

const (
	// SignerKindUnknown means the principal class was not established. It is
	// the DEFAULT and the common case on a developer machine, and it is not a
	// synonym for "no human involved" — an ALPS-style agent running under an
	// inherited human session with no TTY lands here. Policies must treat it
	// the way they treat interactive-human-session: deny. See the allowlist
	// note on AllSignerKinds.
	SignerKindUnknown SignerKind = "unknown"

	// SignerKindInteractiveHumanSession means the credential derives from a
	// natural person's interactive login — a browser OIDC flow, a device
	// grant, a stored platform session — REGARDLESS of whether a person or an
	// automated agent is driving it at the moment of signing. The hazard is
	// the provenance of the session, not the liveness of the human.
	SignerKindInteractiveHumanSession SignerKind = "interactive-human-session"

	// SignerKindWorkloadIdentity means the credential is a federated,
	// non-interactive machine identity minted for one build (a CI OIDC token,
	// SPIFFE SVID, cloud instance identity) with no natural person's session
	// anywhere in the chain. This is the only kind an ALPS-gated policy should
	// admit, and only when corroborated against the certificate — see
	// PredicateCaveat.
	SignerKindWorkloadIdentity SignerKind = "workload-identity"

	// SignerKindLongLivedKey means a static private key with neither an
	// interactive session nor a federated identity behind it. It is not a
	// human session, but it is also not attributable to a particular run, so
	// it earns none of workload-identity's guarantees.
	SignerKindLongLivedKey SignerKind = "long-lived-key"
)

// signerKindProps classifies one SignerKind. Every kind MUST have an entry:
// signerKindTable is the single table this package's schema, its docs and its
// tests are all derived from, so a kind added without a classification fails
// the sweep in signer_test.go rather than silently defaulting to permissive.
type signerKindProps struct {
	// HumanSession reports whether a natural person's interactive session sits
	// anywhere in this credential's provenance. Deliberately NOT a bare
	// negation: SignerKindUnknown is false here yet must still be denied,
	// which is why policy is written as an ALLOWLIST over kinds rather than as
	// `not HumanSession`.
	HumanSession bool

	// PositivelyEstablished reports whether this kind is a POSITIVE finding
	// about the principal rather than an absence of evidence. Only kinds that
	// are positively established can support any claim at all; `unknown` is
	// the sole kind that is not.
	PositivelyEstablished bool

	// RequiresFederated makes the strong claim structurally inseparable from
	// its evidence: when true, a predicate asserting this kind MUST also carry
	// a Federated block, and the JSON Schema enforces it (see
	// Signer.JSONSchemaExtend). A predicate claiming workload-identity with no
	// federated identity is schema-INVALID, not merely policy-denied.
	RequiresFederated bool

	// Doc is one line of human text, surfaced in the generated catalog.
	Doc string
}

// signerKindTable is the authoritative classification of every SignerKind.
//
// This map — not a hand-written list in a test, not a switch with a default
// arm — is the table. The JSON Schema enum, the catalog documentation and the
// test sweeps are all generated from its keys, so the three cannot drift from
// each other and a new kind cannot be added without classifying it.
var signerKindTable = map[SignerKind]signerKindProps{
	SignerKindUnknown: {
		HumanSession:          false,
		PositivelyEstablished: false,
		RequiresFederated:     false,
		Doc:                   "principal class not established; deny — absence of evidence is not evidence of a workload",
	},
	SignerKindInteractiveHumanSession: {
		HumanSession:          true,
		PositivelyEstablished: true,
		RequiresFederated:     false,
		Doc:                   "credential derives from a natural person's interactive login session",
	},
	SignerKindWorkloadIdentity: {
		HumanSession:          false,
		PositivelyEstablished: true,
		RequiresFederated:     true,
		Doc:                   "federated non-interactive machine identity minted for a single run",
	},
	SignerKindLongLivedKey: {
		HumanSession:          false,
		PositivelyEstablished: true,
		RequiresFederated:     false,
		Doc:                   "static private key with neither an interactive session nor a federated identity",
	},
}

// AllSignerKinds returns every declared SignerKind in sorted order.
//
// Policies MUST be written as an allowlist over this set
// (`kind == "workload-identity"`), never as a denylist. A denylist silently
// admits any kind added later; an allowlist denies it until someone decides
// otherwise. This is the same fail-closed reasoning that makes
// SignerKindUnknown an explicit member rather than an empty string.
func AllSignerKinds() []SignerKind {
	kinds := make([]SignerKind, 0, len(signerKindTable))
	for k := range signerKindTable {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}

// IsInteractiveHumanSession reports whether a human's interactive session sits
// in this kind's credential chain. An UNDECLARED kind reports true: a value
// this package does not recognize is treated as the most dangerous thing it
// could be, so a stale consumer reading a newer predicate fails closed.
func (k SignerKind) IsInteractiveHumanSession() bool {
	props, ok := signerKindTable[k]
	if !ok {
		return true
	}
	return props.HumanSession
}

// KeyMaterial records how the signing key was obtained. This is nono's
// `signer.kind` axis, kept under its own name so the two are never confused:
// it describes the KEY, and says nothing about WHOSE it is.
type KeyMaterial string

const (
	// KeyMaterialUnknown means the key provenance was not established.
	KeyMaterialUnknown KeyMaterial = "unknown"

	// KeyMaterialKeyed means a long-lived key pair from a keystore or file.
	KeyMaterialKeyed KeyMaterial = "keyed"

	// KeyMaterialKeyless means a short-lived certificate issued against an
	// OIDC identity (Fulcio). Note this says nothing about principal class: an
	// interactive browser login is keyless too.
	KeyMaterialKeyless KeyMaterial = "keyless"
)

// AllKeyMaterials returns every declared KeyMaterial in sorted order.
func AllKeyMaterials() []KeyMaterial {
	return []KeyMaterial{KeyMaterialKeyed, KeyMaterialKeyless, KeyMaterialUnknown}
}

// SignerPolicyUse is the only legal value of Signer.PolicyUse. Every signer
// block this attestor emits carries it, and the JSON Schema pins it as a const,
// so a consumer can machine-check that the block is not enforceable rather than
// having to know it from documentation.
const SignerPolicyUse = "observational-only"

// Assurance grades HOW the principal class was determined. It is deliberately
// coarse and deliberately short: this attestor runs at prematerial time,
// before any signing has happened, so it cannot observe a verified token. The
// strongest grade it can honestly reach is environment-observed, and inventing
// a stronger one would be the whole failure this vocabulary exists to prevent.
type Assurance string

const (
	// AssuranceUnknown means nothing decided the value.
	AssuranceUnknown Assurance = "unknown"

	// AssuranceEnvironmentObserved means the value came from environment
	// variables and process state. ANY ancestor process can set these, so this
	// grade is corroborating context, never proof — see PredicateCaveat.
	AssuranceEnvironmentObserved Assurance = "environment-observed"
)

// AllAssurances returns every declared Assurance in sorted order.
func AllAssurances() []Assurance {
	return []Assurance{AssuranceEnvironmentObserved, AssuranceUnknown}
}

// FederatedIdentity carries the workload identity claims observed in the
// environment. Its presence is REQUIRED by the schema whenever Kind is a kind
// whose RequiresFederated is true, so the workload claim cannot be asserted
// without the evidence that would substantiate it.
type FederatedIdentity struct {
	// Provider is the recognized CI platform (e.g. "github-actions").
	Provider string `json:"provider"`

	// Issuer is the expected OIDC issuer URL for that provider. It is a
	// CONSTANT of the provider, not a value read from a token — no token has
	// been minted at prematerial time. A verifier must compare the SIGNING
	// CERTIFICATE's issuer against this, not trust it on its own.
	Issuer string `json:"issuer"`

	// Repository is the source repository the run belongs to, when published.
	Repository string `json:"repository,omitempty"`

	// WorkflowRef identifies the workflow definition, when published.
	WorkflowRef string `json:"workflowRef,omitempty"`

	// RunnerEnvironment distinguishes a hosted from a self-hosted runner when
	// the platform publishes it. A self-hosted runner can be a developer
	// machine, which weakens the workload claim considerably.
	RunnerEnvironment string `json:"runnerEnvironment,omitempty"`

	// TokenEndpointPresent reports whether the ambient machinery to mint a
	// workload OIDC token was actually reachable in this environment. False
	// means the CI variables were set but no token could be issued — which is
	// what spoofed CI variables look like.
	TokenEndpointPresent bool `json:"tokenEndpointPresent"`
}

// Signer is the machine-checkable statement about who will sign this
// attestation.
//
// Kind, KeyMaterial and Assurance are all REQUIRED — none carries `omitempty`.
// That is deliberate: an omitted field reads as an absent constraint, and a
// policy that checks `signer.kind != "interactive-human-session"` against a
// predicate with no signer block at all would PASS. Requiring the fields makes
// a signer-less predicate malformed rather than permissive.
type Signer struct {
	// PolicyUse states, inside the predicate itself, what this block may be
	// used for. It is a CONSTANT — see SignerPolicyUse — and the JSON Schema
	// pins it, so a predicate asserting anything else is schema-invalid.
	//
	// It exists because the alternative is not reachable from here. Binding
	// these fields to the credential that actually signs would require
	// observing the signing certificate, and this attestor runs at PREMATERIAL
	// time (see RunType), before any signing has occurred. There is no
	// certificate to read. Every value below is therefore an observation of the
	// environment and process state, and the honest move is to say so in a
	// field a machine can check rather than only in prose a policy author may
	// not read.
	//
	// The concrete hazard this closes: a CI job whose runner variables are all
	// present, that then signs with a long-lived static key from a secret,
	// would have produced `workload-identity` here. The environment was
	// telling the truth about the runner and nothing about the key. A policy
	// gating on these fields alone can be defeated that way, and by two export
	// lines in any shell. Gate on the certificate; use this block only as the
	// defense-in-depth cross-check that catches a MISMATCH between what the
	// environment claimed and what the certificate proves.
	PolicyUse string `json:"policyUse"`

	// Kind is the OBSERVED principal class. Closed enum; unrecognized values
	// are schema-invalid. Never enforceable on its own — see PolicyUse.
	Kind SignerKind `json:"kind"`

	// KeyMaterial is the orthogonal key-provenance axis (nono's `signer.kind`).
	//
	// It is always `unknown` from this attestor, and that is a statement about
	// what is knowable rather than a gap to be filled in later. Key material is
	// chosen at SIGNING time, after this predicate is produced. A runner with a
	// full OIDC token environment can still sign with a static key, so
	// inferring `keyless` from the presence of CI variables asserted something
	// the evidence never supported. The field stays for interop with nono's
	// vocabulary; the certificate is what answers it.
	KeyMaterial KeyMaterial `json:"keyMaterial"`

	// Assurance grades how Kind was determined.
	Assurance Assurance `json:"assurance"`

	// Federated carries the workload identity claims. Required by the schema
	// when Kind requires it.
	Federated *FederatedIdentity `json:"federated,omitempty"`

	// Evidence names the concrete signals Kind was derived from, so a reader
	// can audit the inference instead of taking it on faith. Sorted.
	Evidence []string `json:"evidence,omitempty"`
}

// JSONSchemaExtend encodes the design property this predicate exists for, as a
// SCHEMA constraint rather than a naming convention:
//
//  1. `kind`, `keyMaterial` and `assurance` are closed enums generated from
//     the tables above, so an unrecognized value fails validation instead of
//     flowing through to a policy that has no case for it.
//
//  2. Every kind whose RequiresFederated is true gets an `if/then` pair
//     requiring the `federated` block. A predicate claiming workload-identity
//     without federated identity claims is SCHEMA-INVALID. The strong claim
//     and its evidence travel together or not at all.
//
// The conditional is generated by iterating signerKindTable, so a future kind
// marked RequiresFederated acquires the constraint automatically.
func (Signer) JSONSchemaExtend(s *jsonschema.Schema) {
	if s.Properties == nil {
		return
	}

	// policyUse is pinned to a constant, so "this block is not enforceable" is
	// a schema fact a verifier can check rather than a convention it has to be
	// told about. A predicate that omits it or claims anything else fails
	// validation.
	if puSchema, ok := s.Properties.Get("policyUse"); ok {
		puSchema.Const = SignerPolicyUse
	}
	if kindSchema, ok := s.Properties.Get("kind"); ok {
		for _, k := range AllSignerKinds() {
			kindSchema.Enum = append(kindSchema.Enum, string(k))
		}
	}
	if kmSchema, ok := s.Properties.Get("keyMaterial"); ok {
		for _, km := range AllKeyMaterials() {
			kmSchema.Enum = append(kmSchema.Enum, string(km))
		}
	}
	if aSchema, ok := s.Properties.Get("assurance"); ok {
		for _, a := range AllAssurances() {
			aSchema.Enum = append(aSchema.Enum, string(a))
		}
	}

	// Generated from the table: claiming a kind implies carrying its evidence.
	for _, k := range AllSignerKinds() {
		if !signerKindTable[k].RequiresFederated {
			continue
		}
		// A one-property `if` clause pinning kind to a constant is how JSON
		// Schema selects a discriminated variant.
		match := jsonschema.NewProperties()
		match.Set("kind", &jsonschema.Schema{Const: string(k)})

		s.AllOf = append(s.AllOf, &jsonschema.Schema{
			If: &jsonschema.Schema{
				Properties: match,
				Required:   []string{"kind"},
			},
			Then: &jsonschema.Schema{
				Required: []string{"federated"},
			},
		})
	}
}

// detectSigner determines the principal class from observable environment and
// process state.
//
// The ordering is fail-closed and the first case is the subtle one:
//
//  1. A recognized workload provider whose required variables are all present
//     AND whose token-request machinery is actually reachable yields
//     workload-identity.
//  2. Otherwise, a controlling terminal yields interactive-human-session — a
//     TTY means a human shell.
//  3. Otherwise UNKNOWN. Critically, this is NOT "therefore a workload". An
//     ALPS-style agent inheriting a human's session runs with no TTY and no CI
//     variables and lands here, which is exactly why unknown must be denied.
//
// # Why the token binding is required, and not merely recorded
//
// The identifying variables are cheap. GITHUB_ACTIONS and GITHUB_REPOSITORY are
// two export lines in any shell, and every ancestor process of this one can set
// them. Nothing about their presence connects them to the credential that will
// sign the attestation, so on their own they cannot support a claim ABOUT that
// credential — they are ambient context and nothing more.
//
// The token-request variables are different in kind rather than in number.
// ACTIONS_ID_TOKEN_REQUEST_TOKEN is itself a bearer credential the runner
// injects; CI_JOB_JWT_V2 is the assertion itself. Their presence is what makes
// an ambient observation into something bound to a mintable workload identity,
// and their absence beside the cheap variables is not a weak signal — it is the
// precise signature of spoofed CI variables, as TokenRequestEnv's own doc
// comment said before anything enforced it.
//
// An earlier revision recorded that mismatch faithfully in
// TokenEndpointPresent and then issued the workload-identity claim anyway. That
// is the failure mode this whole predicate exists to prevent, arriving through
// the predicate's own front door: a human's static-key signature attributed to
// a workload, in a schema-valid attestation an ALPS-gated policy would admit.
// Writing a hazard down is not the same as refusing it.
//
// The ambient observation is still PUBLISHED — see the Federated block, carried
// on every branch below. Fixing a fail-open by discarding what was seen would
// just trade it for a silent omission, and a reader debugging why a real CI run
// graded `unknown` needs exactly that block to tell a spoofed runner from a
// laptop.
func detectSigner(env func(string) string, hasTTY bool) Signer {
	provider, fed, evidence := detectWorkloadProvider(env)

	if provider != "" && fed != nil && fed.TokenEndpointPresent {
		return Signer{
			PolicyUse:   SignerPolicyUse,
			Kind:        SignerKindWorkloadIdentity,
			KeyMaterial: KeyMaterialUnknown,
			Assurance:   AssuranceEnvironmentObserved,
			Federated:   fed,
			Evidence:    evidence,
		}
	}

	if hasTTY {
		// A terminal is evidence AGAINST a non-interactive workload, never for
		// one, so it outranks whatever unbound CI variables happen to be set.
		//
		// Copied rather than appended in place: evidence is returned with spare
		// capacity, so appending to it would write into a backing array the
		// caller can still see.
		ttyEvidence := make([]string, 0, len(evidence)+1)
		ttyEvidence = append(ttyEvidence, evidence...)
		// The evidence string names what was actually measured. It used to say
		// "character-device", which was the mode bit the old probe read and not
		// the property being claimed — /dev/null satisfies that bit and is no
		// terminal. fileIsTerminal now asks the kernel for a terminal line
		// discipline, so the evidence says terminal.
		ttyEvidence = append(ttyEvidence, "process.stdin:terminal")
		sort.Strings(ttyEvidence)
		return Signer{
			PolicyUse:   SignerPolicyUse,
			Kind:        SignerKindInteractiveHumanSession,
			KeyMaterial: KeyMaterialUnknown,
			Assurance:   AssuranceEnvironmentObserved,
			Federated:   fed,
			Evidence:    ttyEvidence,
		}
	}

	return Signer{
		PolicyUse:   SignerPolicyUse,
		Kind:        SignerKindUnknown,
		KeyMaterial: KeyMaterialUnknown,
		Assurance:   AssuranceUnknown,
		Federated:   fed,
		Evidence:    evidence,
	}
}

// workloadProvider describes one recognized CI platform and the environment
// variables that identify it. This is the second table this package sweeps:
// every provider must declare a name, an issuer and at least one required
// variable, or providers_test fails.
type workloadProvider struct {
	// Name is the stable provider identifier recorded in the predicate.
	Name string

	// Issuer is the provider's OIDC issuer URL — a constant, not an observed
	// token claim.
	Issuer string

	// RequiredEnv must ALL be present and non-empty for the provider to match.
	RequiredEnv []string

	// TokenRequestEnv, when all present, means an ambient workload OIDC token
	// could actually be minted. Its ABSENCE while RequiredEnv is present is
	// the signature of spoofed CI variables, and is recorded rather than
	// hidden.
	TokenRequestEnv []string

	// RepositoryEnv / WorkflowRefEnv / RunnerEnvironmentEnv name the variables
	// carrying those claims. Empty means the provider does not publish it.
	RepositoryEnv        string
	WorkflowRefEnv       string
	RunnerEnvironmentEnv string
}

// workloadProviders lists the CI platforms whose workload identity this
// attestor recognizes. Scope is deliberately narrow — a provider is listed
// only when its issuer and variable names have been checked, because a wrong
// entry here manufactures a workload claim out of nothing.
var workloadProviders = []workloadProvider{
	{
		Name:                 "github-actions",
		Issuer:               "https://token.actions.githubusercontent.com",
		RequiredEnv:          []string{"GITHUB_ACTIONS", "GITHUB_REPOSITORY"},
		TokenRequestEnv:      []string{"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"},
		RepositoryEnv:        "GITHUB_REPOSITORY",
		WorkflowRefEnv:       "GITHUB_WORKFLOW_REF",
		RunnerEnvironmentEnv: "RUNNER_ENVIRONMENT",
	},
	{
		Name:            "gitlab-ci",
		Issuer:          "https://gitlab.com",
		RequiredEnv:     []string{"GITLAB_CI", "CI_PROJECT_PATH"},
		TokenRequestEnv: []string{"CI_JOB_JWT_V2"},
		RepositoryEnv:   "CI_PROJECT_PATH",
		WorkflowRefEnv:  "CI_CONFIG_PATH",
	},
}

// detectWorkloadProvider returns the observed provider, its federated claims
// and the evidence trail.
//
// A provider whose token-request binding is COMPLETE is preferred over one that
// merely matched its cheap identifying variables, regardless of table order. A
// machine carrying both GitHub and GitLab variables — an agent shelling out
// inside a runner, a developer with stale exports — should be graded on the one
// that can actually mint a token, not on whichever happens to be listed first.
//
// The returned FederatedIdentity is an OBSERVATION. TokenEndpointPresent is the
// field that says whether it is bound to anything; detectSigner is what decides
// whether that is enough to support a claim, and callers must not read the
// block's mere presence as one.
func detectWorkloadProvider(env func(string) string) (string, *FederatedIdentity, []string) {
	var (
		ambientName string
		ambient     *providerObservation
	)

	for _, p := range workloadProviders {
		obs := observeProvider(p, env)
		if obs == nil {
			continue
		}
		// A complete binding wins immediately, wherever it sits in the table.
		if obs.fed.TokenEndpointPresent {
			return p.Name, obs.fed, obs.evidence
		}
		// Otherwise keep the FIRST unbound match and carry on looking for a
		// bound one behind it.
		if ambient == nil {
			ambientName, ambient = p.Name, obs
		}
	}

	if ambient == nil {
		return "", nil, nil
	}
	return ambientName, ambient.fed, ambient.evidence
}

// providerObservation is one provider's match against the environment: the
// claims it publishes and the variables those were read from.
type providerObservation struct {
	fed      *FederatedIdentity
	evidence []string
}

// observeProvider evaluates ONE provider against the environment, returning nil
// when its required variables are not all present.
//
// Split out from detectWorkloadProvider so that "what does this provider say?"
// and "which provider do we believe?" are separate questions. They were one
// function, and the selection rule could not be read without also reading the
// variable-gathering.
func observeProvider(p workloadProvider, env func(string) string) *providerObservation {
	evidence := make([]string, 0, len(p.RequiredEnv)+len(p.TokenRequestEnv))
	for _, key := range p.RequiredEnv {
		if env(key) == "" {
			return nil
		}
		evidence = append(evidence, "environment:"+key)
	}

	// Seeded from the LENGTH, not from true. "All of these are present" is
	// vacuously true over an empty set, so a provider declared with no
	// token-request variables would otherwise be treated as fully bound by
	// construction and would mint a workload claim from its two cheap variables
	// alone — reintroducing the exact fail-open this file guards, without
	// touching any of the code that enforces it.
	//
	// TestSweep_EveryWorkloadProviderDeclaresATokenBinding closes the same hole
	// at the table. Both, deliberately: one keeps the table honest, the other
	// keeps a table change from being silently load-bearing here.
	tokenEndpoint := len(p.TokenRequestEnv) > 0
	for _, key := range p.TokenRequestEnv {
		if env(key) == "" {
			tokenEndpoint = false
			continue
		}
		evidence = append(evidence, "environment:"+key)
	}

	fed := &FederatedIdentity{
		Provider:             p.Name,
		Issuer:               p.Issuer,
		TokenEndpointPresent: tokenEndpoint,
	}
	if p.RepositoryEnv != "" {
		fed.Repository = env(p.RepositoryEnv)
	}
	if p.WorkflowRefEnv != "" {
		fed.WorkflowRef = env(p.WorkflowRefEnv)
	}
	if p.RunnerEnvironmentEnv != "" {
		fed.RunnerEnvironment = env(p.RunnerEnvironmentEnv)
	}
	sort.Strings(evidence)

	return &providerObservation{fed: fed, evidence: evidence}
}

// stdinIsTTY reports whether stdin is a TERMINAL.
func stdinIsTTY() bool {
	return fileIsTerminal(os.Stdin)
}

// fileIsTerminal reports whether f is attached to a terminal.
//
// # Why this is an ioctl and not a mode bit
//
// The obvious test — `info.Mode()&os.ModeCharDevice != 0` — asks whether the
// descriptor is a CHARACTER DEVICE, and that is a strictly larger set than
// "terminal". /dev/null, /dev/zero and /dev/urandom are all character devices
// and none of them is a terminal. /dev/null in particular is the single most
// common stdin for a NON-interactive build: every `cmd < /dev/null`, every
// daemon-launched runner, every container started without a TTY. The mode-bit
// test answered "human at a keyboard" for exactly the environments that most
// certainly had none.
//
// term.IsTerminal issues the terminal-attributes ioctl (TCGETS on Linux,
// TIOCGETA on the BSD/macOS lineage) and asks the kernel whether the descriptor
// carries a terminal line discipline. A pipe, a regular file and /dev/null all
// answer no; a pty and a real console answer yes. The per-OS request constant
// is why this goes through x/term rather than being open-coded — getting it
// wrong on one platform reintroduces the same false claim on that platform
// only, which is the hardest shape of this bug to notice.
//
// A nil file answers false so detectSigner falls through to `unknown` rather
// than to a human-session claim it cannot support. That is the same fail-safe
// direction the old read-error branch took.
//
// Scope note, so this is not read as more than it is: getting the probe right
// does not make the resulting `signer.kind` enforceable. It is emitted with
// PolicyUse == SignerPolicyUse ("observational-only") and pinned that way by
// the schema, because this attestor runs at prematerial time and never sees the
// signing certificate. This fixes a field that was saying something false; it
// does not promote it to something a policy may gate on.
func fileIsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// describeSignerKind returns the catalog line for a kind, or an explicit
// marker for one this build does not know.
func describeSignerKind(k SignerKind) string {
	props, ok := signerKindTable[k]
	if !ok {
		return fmt.Sprintf("unrecognized signer kind %q", string(k))
	}
	return props.Doc
}
