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

// Package standards computes the highest SLSA Build and ALPS level a run's
// OBSERVED shape could support (its ceiling) and the ordered next steps that
// would raise it. It never assigns a verified level: a SLSA Build level needs
// an assessment of the producer and build platform, and an ALPS level needs an
// independent verifier. A ceiling says only "a verifier cannot grant more than
// this, given what cilock saw".
//
// The two decision functions, DeriveSLSA and DeriveALPS, are transcriptions of
// `deriveSlsa` and `deriveAlps` in the Lean model
// (formal/ci-provenance/CiProvenance/{Slsa,Alps}.lean) and are
// differential-tested against its `ciprov-eval` evaluator. Keep them
// structurally identical to the model: a change here that the model does not
// share is a change to the claimed semantics.
package standards

// SLSALevel is a SLSA Build track level. The zero value is "none": no
// provenance at all. Ranks and names match `Slsa.rank` / `Slsa.name`.
type SLSALevel int

const (
	SLSANone SLSALevel = iota
	SLSAL1
	SLSAL2
	SLSAL3
)

func (l SLSALevel) String() string {
	switch l {
	case SLSAL1:
		return "L1"
	case SLSAL2:
		return "L2"
	case SLSAL3:
		return "L3"
	default:
		return "none"
	}
}

// ALPSLevel is an ALPS 0.1 level. The zero value is "unknown": not even ALPS 0
// evidence. Ranks and names match `Alps.rank` / `Alps.name`.
type ALPSLevel int

const (
	ALPSUnknown ALPSLevel = iota
	ALPS0
	ALPS1
	ALPS2
	ALPS3
)

func (l ALPSLevel) String() string {
	switch l {
	case ALPS0:
		return "ALPS-0"
	case ALPS1:
		return "ALPS-1"
	case ALPS2:
		return "ALPS-2"
	case ALPS3:
		return "ALPS-3"
	default:
		return "unknown"
	}
}

// SLSAEvidence is the model's `ProvEvidence` minus subjects: what a verifier
// reads from a provenance envelope and its signing leaf.
type SLSAEvidence struct {
	Present              bool `json:"present"`
	HostedWorkflowSigner bool `json:"hostedWorkflowSigner"`
	TrustedBuilderSigner bool `json:"trustedBuilderSigner"`
	Timestamped          bool `json:"timestamped"`
	EphemeralRunner      bool `json:"ephemeralRunner"`
}

// DeriveSLSA is `deriveSlsa`: the highest SLSA Build level whose cumulative
// requirements the evidence meets. L3 needs a signer the build steps cannot
// become; a workflow-bound leaf on an ephemeral runner alone is L2 (the
// model's `naive_l3_accepts_step_forgery`, issue #9822).
func DeriveSLSA(p SLSAEvidence) SLSALevel {
	switch {
	case !p.Present:
		return SLSANone
	case !(p.HostedWorkflowSigner && p.Timestamped):
		return SLSAL1
	case !(p.TrustedBuilderSigner && p.EphemeralRunner):
		return SLSAL2
	default:
		return SLSAL3
	}
}

// ALPSEvidence is the model's `Evidence` minus the content fields, which
// deriveAlps does not read.
type ALPSEvidence struct {
	Signed             bool `json:"signed"`
	Issued             bool `json:"issued"`
	Timestamped        bool `json:"timestamped"`
	BoundaryClaimed    bool `json:"boundaryClaimed"`
	BoundaryByObserver bool `json:"boundaryByObserver"`
	Isolated           bool `json:"isolated"`
}

// DeriveALPS is `deriveAlps`: the strict verifier. It keys ALPS 2 on a
// boundary signed by a non-agent observer, never on a boundary claimed by
// anyone (the model's `alps2_lax_boundary` refutes the lax reading).
func DeriveALPS(e ALPSEvidence) ALPSLevel {
	switch {
	case !e.Signed:
		return ALPSUnknown
	case !(e.Issued && e.Timestamped):
		return ALPS0
	case !e.BoundaryByObserver:
		return ALPS1
	case !e.Isolated:
		return ALPS2
	default:
		return ALPS3
	}
}
