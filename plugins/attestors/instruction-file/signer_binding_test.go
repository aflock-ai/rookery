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
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// A claim requires a bound credential.
// ---------------------------------------------------------------------------
//
// The hazard this file guards is narrow and worth stating exactly. Ambient
// environment variables are writable by ANY ancestor process. `GITHUB_ACTIONS`
// and `GITHUB_REPOSITORY` are two `export` lines in a shell. Nothing about
// their presence connects them to the credential that will actually sign the
// attestation, so on their own they cannot support a claim about the principal
// behind that credential.
//
// The token-request variables are different in kind, not merely in number.
// ACTIONS_ID_TOKEN_REQUEST_TOKEN is itself a bearer credential the runner
// injects, and CI_JOB_JWT_V2 is the assertion itself. Their presence is what
// makes an ambient observation into something bound to a mintable workload
// identity. Their ABSENCE while the cheap variables are set is not a partial
// signal — it is the exact signature of spoofed CI variables, which the
// TokenRequestEnv field's own doc comment already said before any of this was
// enforced.
//
// So the rule these sweeps encode: ambient observations may be RECORDED, but
// they may never be PROMOTED to a claim. Recording without promoting is the
// distinction the previous round's test missed — it asserted
// TokenEndpointPresent was written down as false, and never asserted that the
// kind stopped being workload-identity.

// signerUnknownClaim names every Signer field that constitutes a CLAIM about
// the principal, paired with the value that field MUST hold when nothing binds
// the environment to a signing credential.
//
// signerAmbientObservation names the rest: fields that record what was seen
// without asserting who will sign. They may be populated in the unbound case,
// and should be — dropping them would trade this fail-open for the silent
// omission that is the other half of the same disease.
//
// Between them the two sets must cover EVERY field of Signer. The sweep walks
// the struct with reflect and fails on any field in neither set, so a field
// added later cannot quietly become a fourth unguarded claim. That completeness
// is the whole point of writing it this way: the review found the defect at
// `kind` and `keyMaterial`, and a test naming only those two would have let the
// next one through at `assurance`.
var (
	signerUnknownClaim = map[string]any{
		"Kind":        SignerKindUnknown,
		"KeyMaterial": KeyMaterialUnknown,
		"Assurance":   AssuranceUnknown,
	}

	signerAmbientObservation = map[string]bool{
		"Federated": true,
		"Evidence":  true,
	}

	// signerConstantField names fields that are the SAME on every branch,
	// paired with the value they must always hold. They are neither claims nor
	// observations: they describe the block itself rather than the environment,
	// so "falls back to unknown when nothing is bound" is the wrong question to
	// ask of them — they must be present and correct unconditionally.
	signerConstantField = map[string]any{
		"PolicyUse": SignerPolicyUse,
	}
)

// assertNoSignerClaim asserts that every claim-bearing field of the Signer sits
// at its unknown sentinel, and that every field is classified at all.
func assertNoSignerClaim(t *testing.T, got Signer) {
	t.Helper()

	v := reflect.ValueOf(got)
	ty := v.Type()
	for i := range ty.NumField() {
		name := ty.Field(i).Name
		got := v.Field(i).Interface()

		if want, isClaim := signerUnknownClaim[name]; isClaim {
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Signer.%s = %v, want %v: no variable in this environment binds to the signing credential, so this field must not carry a claim", name, got, want)
			}
			continue
		}
		if want, isConst := signerConstantField[name]; isConst {
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Signer.%s = %v, want the constant %v", name, got, want)
			}
			continue
		}
		if !signerAmbientObservation[name] {
			t.Fatalf("Signer field %q is classified in none of signerUnknownClaim, signerConstantField or signerAmbientObservation. Classify it: if it asserts anything about the principal it must fall back to an unknown sentinel when no credential is bound", name)
		}
	}
}

// TestSweep_EverySignerThisAttestorCanEmitIsObservationalOnly ranges over the
// COMPLETE output space of detectSigner and asserts the two properties that
// hold for all of it.
//
// Why observational rather than bound: binding these fields to the credential
// that signs would mean reading the signing certificate, and this attestor runs
// at PREMATERIAL time (RunType, instruction_file.go) — before any signing has
// happened. There is no certificate in existence yet. Binding is not reachable
// from here, so the honest alternative is to mark the block non-enforcing in a
// way a machine can check.
//
// Two invariants, both universal:
//
//   - policyUse is always the constant. The JSON Schema pins it too, so a
//     predicate claiming otherwise is invalid rather than merely unusual.
//   - keyMaterial is always unknown. Key material is chosen AT SIGNING, after
//     this predicate exists. A runner with a complete OIDC token environment
//     can still sign with a long-lived static key from a secret, so inferring
//     `keyless` from CI variables asserted something the evidence never
//     supported — which is exactly the case the review named.
//
// The output space is enumerated rather than sampled: every provider, every
// subset of its token-request variables INCLUDING the complete one, and both
// TTY states. The complete-binding case matters most here, because it is the
// one branch that previously emitted a positive key-material claim.
func TestSweep_EverySignerThisAttestorCanEmitIsObservationalOnly(t *testing.T) {
	type namedEnv struct {
		name string
		env  map[string]string
	}

	envs := []namedEnv{{name: "empty", env: map[string]string{}}}
	for _, p := range workloadProviders {
		envs = append(envs, namedEnv{name: p.Name + "/complete", env: fullEnvFor(p)})
		for _, b := range incompleteTokenBindings(p) {
			envs = append(envs, namedEnv{name: p.Name + "/" + b.name, env: b.env})
		}
	}

	for _, e := range envs {
		for _, tty := range []bool{false, true} {
			label := e.name
			if tty {
				label += "/tty"
			}
			t.Run(label, func(t *testing.T) {
				got := detectSigner(envFrom(e.env), tty)

				if got.PolicyUse != SignerPolicyUse {
					t.Errorf("PolicyUse = %q, want %q: every signer block this attestor emits must declare itself non-enforcing, because none of it is bound to the signing credential", got.PolicyUse, SignerPolicyUse)
				}
				if got.KeyMaterial != KeyMaterialUnknown {
					t.Errorf("KeyMaterial = %q, want unknown: key material is chosen at signing time, after this predicate is produced. A CI job with a full token environment can still sign with a static key, so no environment observation can establish this field", got.KeyMaterial)
				}
			})
		}
	}
}

// incompleteBinding is one environment in which a provider's cheap identifying
// variables are all present but its token-request set is not complete.
type incompleteBinding struct {
	name string
	env  map[string]string
}

// incompleteTokenBindings enumerates the COMPLETE set of ways a provider's
// token-request binding can be incomplete: every proper subset of its
// TokenRequestEnv variables, with the provider's required and claim-bearing
// variables fully present.
//
// Enumerating the powerset rather than naming a case or two is what makes this
// a sweep. A provider declaring two token variables has three incomplete
// states, and "both absent" is not the only one that matters — an attacker who
// can set one can usually set the cheap ones too.
func incompleteTokenBindings(p workloadProvider) []incompleteBinding {
	n := len(p.TokenRequestEnv)
	if n == 0 || n > 10 {
		// n == 0 is caught as its own defect by
		// TestSweep_EveryWorkloadProviderDeclaresATokenBinding. The upper
		// bound keeps the powerset from exploding if the table ever grows a
		// provider with many token variables.
		return nil
	}

	out := []incompleteBinding{}
	// Every subset EXCEPT the full one (mask == 1<<n - 1) is incomplete.
	for mask := 0; mask < (1<<n)-1; mask++ {
		env := fullEnvFor(p)
		present := []string{}
		for i, key := range p.TokenRequestEnv {
			if mask&(1<<i) != 0 {
				present = append(present, key)
				continue
			}
			delete(env, key)
		}
		out = append(out, incompleteBinding{
			name: fmt.Sprintf("present=%v", present),
			env:  env,
		})
	}
	return out
}

// TestSweep_NoSignerClaimSurvivesAnIncompleteTokenBinding is the primary sweep.
//
// It ranges over the complete workloadProviders table, over the complete
// powerset of incomplete token bindings for each, and — via assertNoSignerClaim
// — over the complete field set of Signer. Three nested universal quantifiers,
// each over a set derived from the code rather than transcribed into the test.
//
// A provider added to the table, a token variable added to a provider, or a
// claim field added to Signer all land inside this quantifier automatically.
func TestSweep_NoSignerClaimSurvivesAnIncompleteTokenBinding(t *testing.T) {
	for _, p := range workloadProviders {
		for _, b := range incompleteTokenBindings(p) {
			t.Run(p.Name+"/"+b.name, func(t *testing.T) {
				// hasTTY is false: this is the case where the ONLY thing
				// arguing for a workload is the ambient environment.
				assertNoSignerClaim(t, detectSigner(envFrom(b.env), false))
			})
		}
	}
}

// TestSweep_AnIncompleteBindingStillRecordsWhatWasObserved is the other half,
// and it is not optional.
//
// A fail-open is fixed by refusing to claim, not by refusing to look. If the
// detector responded to an unbound environment by discarding what it saw, a
// reader debugging why a CI run produced `unknown` would have nothing to read,
// and the predicate would have quietly lost the single most diagnostic fact
// available: that CI variables were present and the token machinery was not.
//
// So the federated observation must survive, and it must say so.
func TestSweep_AnIncompleteBindingStillRecordsWhatWasObserved(t *testing.T) {
	for _, p := range workloadProviders {
		for _, b := range incompleteTokenBindings(p) {
			t.Run(p.Name+"/"+b.name, func(t *testing.T) {
				got := detectSigner(envFrom(b.env), false)
				if got.Federated == nil {
					t.Fatal("the ambient observation was dropped entirely; an unbound environment must still record what it saw, or a reader cannot tell a spoofed runner from a laptop")
				}
				if got.Federated.Provider != p.Name {
					t.Errorf("federated provider = %q, want %q", got.Federated.Provider, p.Name)
				}
				if got.Federated.TokenEndpointPresent {
					t.Error("TokenEndpointPresent is true with an incomplete token-request set; that is what a spoofed CI environment looks like and it must be visible")
				}
				if len(got.Evidence) == 0 {
					t.Error("no evidence recorded; the inference must stay auditable even when it concludes nothing")
				}
			})
		}
	}
}

// TestSweep_EveryWorkloadProviderDeclaresATokenBinding closes the vacuous-truth
// hole in the table itself.
//
// "All of these variables are present" is trivially TRUE over an empty set. A
// provider added with no TokenRequestEnv would therefore be treated as fully
// bound by construction and would mint workload-identity from its two cheap
// identifying variables — reintroducing exactly the defect this file exists to
// prevent, without touching any of the code that enforces it.
//
// Requiring the declaration makes that unrepresentable rather than merely
// unlikely.
func TestSweep_EveryWorkloadProviderDeclaresATokenBinding(t *testing.T) {
	for _, p := range workloadProviders {
		t.Run(p.Name, func(t *testing.T) {
			if len(p.TokenRequestEnv) == 0 {
				t.Fatalf("provider %q declares no TokenRequestEnv. Presence over an empty set is vacuously true, so this provider would claim workload-identity from ambient variables alone. Name the variable that carries or requests its token", p.Name)
			}
		})
	}
}

// TestATTYWithAnUnboundEnvironmentIsAHumanSessionNotAWorkload pins the
// interaction between the two fallbacks.
//
// Both outcomes are fail-closed under an allowlist policy that admits only
// workload-identity, so this is not a security boundary — it is a correctness
// one. A developer who has exported CI variables into an interactive shell is
// observably at a terminal, and the predicate should say the more specific true
// thing rather than the vaguer one.
func TestATTYWithAnUnboundEnvironmentIsAHumanSessionNotAWorkload(t *testing.T) {
	for _, p := range workloadProviders {
		bindings := incompleteTokenBindings(p)
		if len(bindings) == 0 {
			continue
		}
		t.Run(p.Name, func(t *testing.T) {
			got := detectSigner(envFrom(bindings[0].env), true)
			if got.Kind == SignerKindWorkloadIdentity {
				t.Fatalf("kind = workload-identity at a terminal with no bound token; a TTY is evidence AGAINST a non-interactive workload, never for one")
			}
			if got.Kind != SignerKindInteractiveHumanSession {
				t.Errorf("kind = %q, want interactive-human-session: stdin is a terminal", got.Kind)
			}
		})
	}
}
