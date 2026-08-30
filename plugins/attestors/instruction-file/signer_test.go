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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/invopop/jsonschema"
	tekuri "github.com/santhosh-tekuri/jsonschema/v5"
)

// ---------------------------------------------------------------------------
// Sweeps over signerKindTable.
//
// Every test in this section quantifies over AllSignerKinds() — the package's
// own table — rather than a list written out here. A hand-written list goes
// stale the moment a kind is added, and it goes stale SILENTLY: the tests keep
// passing while the new kind sails past unclassified. Deriving the set from the
// table makes "someone added a kind and forgot to classify it" a failure.
// ---------------------------------------------------------------------------

// TestSweep_EverySignerKindIsClassified asserts every declared kind carries a
// complete classification. This is the gate that makes the table authoritative.
func TestSweep_EverySignerKindIsClassified(t *testing.T) {
	kinds := AllSignerKinds()
	if len(kinds) == 0 {
		t.Fatal("AllSignerKinds() is empty — the table this package derives everything from is missing")
	}

	for _, k := range kinds {
		t.Run(string(k), func(t *testing.T) {
			props, ok := signerKindTable[k]
			if !ok {
				t.Fatalf("kind %q is returned by AllSignerKinds() but has no signerKindTable entry", k)
			}
			if strings.TrimSpace(props.Doc) == "" {
				t.Errorf("kind %q has an empty Doc; the catalog renders this verbatim", k)
			}
			if string(k) == "" {
				t.Error("empty-string kind: absence must be an explicit value, never the zero value")
			}
			if props.RequiresFederated && props.HumanSession {
				t.Errorf("kind %q claims both RequiresFederated and HumanSession; a federated workload identity has no human session in its chain", k)
			}
			if props.RequiresFederated && !props.PositivelyEstablished {
				t.Errorf("kind %q requires federated evidence but is not positively established; a kind that is an absence of evidence cannot demand evidence", k)
			}
		})
	}
}

// TestSweep_UnknownKindIsPresentAndNotPositivelyEstablished pins the fail-closed
// invariant: `unknown` must be a real, declared member of the enum (so it is
// schema-valid and a policy can name it) and must never read as a positive
// finding.
func TestSweep_UnknownKindIsPresentAndNotPositivelyEstablished(t *testing.T) {
	props, ok := signerKindTable[SignerKindUnknown]
	if !ok {
		t.Fatal("SignerKindUnknown must be a declared member so absence is representable, not implicit")
	}
	if props.PositivelyEstablished {
		t.Error("SignerKindUnknown must not be positively established — it IS the absence of a finding")
	}
	if props.RequiresFederated {
		t.Error("SignerKindUnknown must not require federated evidence")
	}
}

// TestSweep_ExactlyOneKindIsHumanSession guards the vocabulary from quietly
// growing a second human-ish kind that an existing allowlist policy would not
// cover. If this fails because a kind was legitimately added, the fix is to
// update the catalog doc's rego example in the same change — which is the point.
func TestSweep_ExactlyOneKindIsHumanSession(t *testing.T) {
	var human []SignerKind
	for _, k := range AllSignerKinds() {
		if signerKindTable[k].HumanSession {
			human = append(human, k)
		}
	}
	if len(human) != 1 || human[0] != SignerKindInteractiveHumanSession {
		t.Errorf("expected exactly [interactive-human-session] to be human-session kinds, got %v — update docs/instruction-file.doc.md's policy example in the same change", human)
	}
}

// TestUnrecognizedKindFailsClosed asserts a kind this build does not know is
// treated as the most dangerous thing it could be. A stale verifier reading a
// newer predicate must deny, not admit.
func TestUnrecognizedKindFailsClosed(t *testing.T) {
	if !SignerKind("some-future-kind").IsInteractiveHumanSession() {
		t.Error("an unrecognized signer kind must report as a human session so a stale consumer fails closed")
	}
	if SignerKindWorkloadIdentity.IsInteractiveHumanSession() {
		t.Error("workload-identity must not report as a human session")
	}
	if !SignerKindInteractiveHumanSession.IsInteractiveHumanSession() {
		t.Error("interactive-human-session must report as a human session")
	}
}

// emittableKinds are the kinds detectSigner can actually produce today.
//
// This is deliberately a SHORTER list than AllSignerKinds(), and the gap is the
// point. `long-lived-key` is part of the predicate's vocabulary — the type is a
// shared contract that other producers and later cilock versions (which will
// see the signing configuration this attestor cannot) need to express — but
// nothing at prematerial time can observe that a static key is about to be
// used, so this attestor never claims it. Recording the gap here keeps it
// visible instead of leaving a value that looks live and is not.
var emittableKinds = map[SignerKind]bool{
	SignerKindWorkloadIdentity:        true,
	SignerKindInteractiveHumanSession: true,
	SignerKindUnknown:                 true,
}

// TestSweep_EmittableKindsAreDeclaredAndClassified asserts every kind this
// attestor can emit is a declared, classified member — and reports the
// declared-but-not-emitted remainder so the gap cannot drift unnoticed.
func TestSweep_EmittableKindsAreDeclaredAndClassified(t *testing.T) {
	declared := map[SignerKind]bool{}
	for _, k := range AllSignerKinds() {
		declared[k] = true
	}

	for k := range emittableKinds {
		if !declared[k] {
			t.Errorf("detectSigner can emit %q but it is not a declared kind; the schema would reject the predicate", k)
		}
	}

	var notEmitted []SignerKind
	for _, k := range AllSignerKinds() {
		if !emittableKinds[k] {
			notEmitted = append(notEmitted, k)
		}
	}
	// Pinned so that adding a kind, or teaching the detector to emit an
	// existing one, forces this list to be updated deliberately.
	if len(notEmitted) != 1 || notEmitted[0] != SignerKindLongLivedKey {
		t.Errorf("declared-but-not-emitted kinds = %v, expected exactly [long-lived-key]; update emittableKinds and the catalog doc in the same change", notEmitted)
	}
}

// TestSweep_DetectSignerOnlyEmitsDeclaredKinds drives the detector across a
// derived matrix of environments and asserts it never produces a kind outside
// the declared set — the property that keeps every emitted predicate
// schema-valid.
func TestSweep_DetectSignerOnlyEmitsDeclaredKinds(t *testing.T) {
	declared := map[SignerKind]bool{}
	for _, k := range AllSignerKinds() {
		declared[k] = true
	}

	envs := []map[string]string{{}}
	for _, p := range workloadProviders {
		full := fullEnvFor(p)
		envs = append(envs, full)
		// Each partial environment: one required variable missing.
		for _, key := range p.RequiredEnv {
			partial := fullEnvFor(p)
			delete(partial, key)
			envs = append(envs, partial)
		}
	}

	for _, env := range envs {
		for _, tty := range []bool{true, false} {
			got := detectSigner(envFrom(env), tty)
			if !declared[got.Kind] {
				t.Errorf("detectSigner produced undeclared kind %q for env %v tty=%v", got.Kind, env, tty)
			}
			if !emittableKinds[got.Kind] {
				t.Errorf("detectSigner produced kind %q which emittableKinds says it cannot; update emittableKinds", got.Kind)
			}
			// The schema invariant must hold for every emitted signer.
			if signerKindTable[got.Kind].RequiresFederated && got.Federated == nil {
				t.Errorf("kind %q requires federated evidence but none was attached (env %v tty=%v); the predicate would be schema-invalid", got.Kind, env, tty)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Sweeps over the generated JSON Schema.
//
// These are the tests that make the human-vs-workload distinction a SCHEMA
// property rather than a naming convention.
// ---------------------------------------------------------------------------

// signerSchema compiles the Signer sub-schema out of the attestor's full
// schema, exactly as a verifier would.
func signerSchema(t *testing.T) *tekuri.Schema {
	t.Helper()
	full := jsonschema.Reflect(&Signer{})
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal Signer schema: %v", err)
	}
	c := tekuri.NewCompiler()
	if err := c.AddResource("signer.schema.json", bytes.NewReader(raw)); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile("signer.schema.json")
	if err != nil {
		t.Fatalf("compile Signer schema: %v", err)
	}
	return sch
}

// schemaEnumFor pulls the enum for one property out of the reflected schema.
func schemaEnumFor(t *testing.T, property string) []string {
	t.Helper()
	full := jsonschema.Reflect(&Signer{})
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal Signer schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal Signer schema: %v", err)
	}
	defs, _ := doc["$defs"].(map[string]any)
	signer, _ := defs["Signer"].(map[string]any)
	if signer == nil {
		t.Fatalf("no Signer definition in reflected schema: %s", string(raw))
	}
	props, _ := signer["properties"].(map[string]any)
	prop, _ := props[property].(map[string]any)
	if prop == nil {
		t.Fatalf("property %q not found in Signer schema", property)
	}
	rawEnum, ok := prop["enum"].([]any)
	if !ok {
		t.Fatalf("property %q carries no enum; an open string field lets an unrecognized value flow through to a policy that has no case for it", property)
	}
	out := make([]string, 0, len(rawEnum))
	for _, v := range rawEnum {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// TestSweep_SchemaKindEnumMatchesTable asserts the schema's enum is EXACTLY the
// table's key set — both directions. A kind in the table but not the enum is
// unrepresentable; a value in the enum but not the table is unclassified.
func TestSweep_SchemaKindEnumMatchesTable(t *testing.T) {
	got := map[string]bool{}
	for _, v := range schemaEnumFor(t, "kind") {
		got[v] = true
	}
	want := map[string]bool{}
	for _, k := range AllSignerKinds() {
		want[string(k)] = true
	}

	for k := range want {
		if !got[k] {
			t.Errorf("kind %q is in signerKindTable but missing from the schema enum", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("kind %q is in the schema enum but has no signerKindTable entry", k)
		}
	}
}

// TestSweep_SchemaEnumsAreClosedForEveryEnumField sweeps every enum-bearing
// field on Signer at once, so a field added later without an enum is caught.
func TestSweep_SchemaEnumsAreClosedForEveryEnumField(t *testing.T) {
	cases := map[string][]string{
		"kind":        stringsOf(AllSignerKinds()),
		"keyMaterial": stringsOf(AllKeyMaterials()),
		"assurance":   stringsOf(AllAssurances()),
	}
	for property, want := range cases {
		t.Run(property, func(t *testing.T) {
			got := schemaEnumFor(t, property)
			if len(got) != len(want) {
				t.Fatalf("enum for %q has %d values %v, table declares %d %v", property, len(got), got, len(want), want)
			}
			set := map[string]bool{}
			for _, g := range got {
				set[g] = true
			}
			for _, w := range want {
				if !set[w] {
					t.Errorf("enum for %q is missing declared value %q", property, w)
				}
			}
		})
	}
}

// TestSweep_EveryKindRequiringFederatedIsSchemaEnforced is the central test of
// this design. For EVERY kind whose table entry demands federated evidence, it
// asserts the compiled schema actually REJECTS a predicate claiming that kind
// without the evidence, and accepts it with. Deriving the cases from the table
// means a future kind marked RequiresFederated is covered the day it is added.
func TestSweep_EveryKindRequiringFederatedIsSchemaEnforced(t *testing.T) {
	sch := signerSchema(t)

	var checked int
	for _, k := range AllSignerKinds() {
		if !signerKindTable[k].RequiresFederated {
			continue
		}
		checked++
		t.Run(string(k), func(t *testing.T) {
			without := map[string]any{
				"kind":        string(k),
				"policyUse":   SignerPolicyUse,
				"keyMaterial": string(KeyMaterialKeyless),
				"assurance":   string(AssuranceEnvironmentObserved),
			}
			if err := sch.Validate(without); err == nil {
				t.Errorf("schema ACCEPTED kind %q with no federated block; the strong claim must be inseparable from its evidence", k)
			}

			with := map[string]any{
				"kind":        string(k),
				"policyUse":   SignerPolicyUse,
				"keyMaterial": string(KeyMaterialKeyless),
				"assurance":   string(AssuranceEnvironmentObserved),
				"federated": map[string]any{
					"provider":             "github-actions",
					"issuer":               "https://token.actions.githubusercontent.com",
					"tokenEndpointPresent": true,
				},
			}
			if err := sch.Validate(with); err != nil {
				t.Errorf("schema REJECTED a well-formed %q predicate: %v", k, err)
			}
		})
	}

	if checked == 0 {
		t.Fatal("no kind requires federated evidence — the schema-level property this predicate exists for is not being enforced anywhere")
	}
}

// TestSchemaRejectsUnrecognizedKind asserts the enum is genuinely closed, so a
// novel kind cannot reach a policy that has no case for it.
func TestSchemaRejectsUnrecognizedKind(t *testing.T) {
	sch := signerSchema(t)
	err := sch.Validate(map[string]any{
		"kind":        "definitely-not-a-declared-kind",
		"policyUse":   SignerPolicyUse,
		"keyMaterial": string(KeyMaterialKeyless),
		"assurance":   string(AssuranceEnvironmentObserved),
	})
	if err == nil {
		t.Error("schema accepted an undeclared signer kind; the enum is not closed")
	}
}

// TestSchemaRequiresCoreSignerFields asserts kind, keyMaterial and assurance are
// REQUIRED. An omitted field reads to a policy as an absent constraint, so a
// signer-less predicate would sail past `signer.kind != "interactive-human-session"`.
func TestSchemaRequiresCoreSignerFields(t *testing.T) {
	sch := signerSchema(t)
	for _, missing := range []string{"kind", "keyMaterial", "assurance"} {
		t.Run("missing_"+missing, func(t *testing.T) {
			doc := map[string]any{
				"kind":        string(SignerKindLongLivedKey),
				"keyMaterial": string(KeyMaterialKeyed),
				"assurance":   string(AssuranceEnvironmentObserved),
			}
			delete(doc, missing)
			if err := sch.Validate(doc); err == nil {
				t.Errorf("schema accepted a signer with no %q; absence must be malformed, not permissive", missing)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Sweeps over workloadProviders.
// ---------------------------------------------------------------------------

// TestSweep_EveryWorkloadProviderIsWellFormed asserts each provider declares
// what the detector needs. A provider with no required variables would match an
// empty environment and manufacture a workload claim out of nothing.
func TestSweep_EveryWorkloadProviderIsWellFormed(t *testing.T) {
	if len(workloadProviders) == 0 {
		t.Fatal("workloadProviders is empty — no workload identity could ever be recognized")
	}
	seen := map[string]bool{}
	for _, p := range workloadProviders {
		t.Run(p.Name, func(t *testing.T) {
			if strings.TrimSpace(p.Name) == "" {
				t.Error("provider has an empty Name")
			}
			if seen[p.Name] {
				t.Errorf("duplicate provider name %q; the first entry would always win", p.Name)
			}
			seen[p.Name] = true
			if !strings.HasPrefix(p.Issuer, "https://") {
				t.Errorf("provider %q issuer %q is not an https URL", p.Name, p.Issuer)
			}
			if len(p.RequiredEnv) == 0 {
				t.Errorf("provider %q declares no RequiredEnv; it would match an empty environment", p.Name)
			}
			for _, key := range p.RequiredEnv {
				if strings.TrimSpace(key) == "" {
					t.Errorf("provider %q has an empty RequiredEnv entry", p.Name)
				}
			}
		})
	}
}

// envFrom builds a lookup func over a fixed map, so these tests never touch the
// real process environment and cannot be perturbed by the machine running them.
func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// fullEnvFor returns an environment in which the provider fully matches.
func fullEnvFor(p workloadProvider) map[string]string {
	env := map[string]string{}
	for _, k := range p.RequiredEnv {
		env[k] = "set"
	}
	for _, k := range p.TokenRequestEnv {
		env[k] = "set"
	}
	if p.RepositoryEnv != "" {
		env[p.RepositoryEnv] = "acme/widget"
	}
	if p.WorkflowRefEnv != "" {
		env[p.WorkflowRefEnv] = "acme/widget/.github/workflows/build.yml@refs/heads/main"
	}
	if p.RunnerEnvironmentEnv != "" {
		env[p.RunnerEnvironmentEnv] = "github-hosted"
	}
	return env
}

// TestSweep_EveryWorkloadProviderIsDetected asserts each declared provider is
// actually recognized when its variables are present. Derived from the table, so
// a provider added without working detection fails here.
func TestSweep_EveryWorkloadProviderIsDetected(t *testing.T) {
	for _, p := range workloadProviders {
		t.Run(p.Name, func(t *testing.T) {
			got := detectSigner(envFrom(fullEnvFor(p)), false)
			if got.Kind != SignerKindWorkloadIdentity {
				t.Fatalf("provider %q with all variables set yielded kind %q, want workload-identity", p.Name, got.Kind)
			}
			if got.Federated == nil {
				t.Fatalf("provider %q yielded workload-identity with no federated block; the schema forbids that combination", p.Name)
			}
			if got.Federated.Provider != p.Name {
				t.Errorf("federated provider = %q, want %q", got.Federated.Provider, p.Name)
			}
			if got.Federated.Issuer != p.Issuer {
				t.Errorf("federated issuer = %q, want %q", got.Federated.Issuer, p.Issuer)
			}
			if !got.Federated.TokenEndpointPresent && len(p.TokenRequestEnv) > 0 {
				t.Error("token endpoint variables were set but TokenEndpointPresent is false")
			}
			if got.Assurance != AssuranceEnvironmentObserved {
				t.Errorf("assurance = %q, want environment-observed; this attestor cannot honestly claim more", got.Assurance)
			}
			if len(got.Evidence) == 0 {
				t.Error("no evidence recorded; the inference must be auditable")
			}
		})
	}
}

// TestSweep_EveryRequiredEnvIsLoadBearing asserts that dropping ANY single
// required variable stops the provider matching. This is the derived-set form of
// "the detector really uses what it declares" — a variable listed as required
// but never actually checked is caught here, per provider, per variable.
func TestSweep_EveryRequiredEnvIsLoadBearing(t *testing.T) {
	for _, p := range workloadProviders {
		for _, key := range p.RequiredEnv {
			t.Run(p.Name+"/"+key, func(t *testing.T) {
				env := fullEnvFor(p)
				delete(env, key)
				got := detectSigner(envFrom(env), false)
				if got.Kind == SignerKindWorkloadIdentity && got.Federated != nil && got.Federated.Provider == p.Name {
					t.Errorf("provider %q still matched with required variable %q absent; the variable is declared required but not enforced", p.Name, key)
				}
			})
		}
	}
}

// TestSpoofedCIVariablesAreRecordedNotHidden asserts that CI variables present
// WITHOUT the token-minting machinery — what spoofed CI variables look like —
// still produce a predicate that says so, rather than quietly claiming a full
// workload identity.
func TestSpoofedCIVariablesAreRecordedNotHidden(t *testing.T) {
	var withToken workloadProvider
	for _, p := range workloadProviders {
		if len(p.TokenRequestEnv) > 0 {
			withToken = p
			break
		}
	}
	if withToken.Name == "" {
		t.Skip("no provider declares TokenRequestEnv")
	}

	env := fullEnvFor(withToken)
	for _, k := range withToken.TokenRequestEnv {
		delete(env, k)
	}
	got := detectSigner(envFrom(env), false)
	if got.Federated == nil {
		t.Fatal("expected a federated block")
	}
	if got.Federated.TokenEndpointPresent {
		t.Error("TokenEndpointPresent is true with no token-request variables set; spoofed CI variables would be indistinguishable from a real runner")
	}
}

// ---------------------------------------------------------------------------
// The fail-closed detection contract.
// ---------------------------------------------------------------------------

// TestDetectSignerFailsClosedWithoutEvidence is the ALPS 0.1 case, and the
// single most important behavior in this package. An agent launched from a
// signed-in human's shell has no TTY and no CI variables. It must NOT be
// mistaken for a workload.
func TestDetectSignerFailsClosedWithoutEvidence(t *testing.T) {
	got := detectSigner(envFrom(map[string]string{}), false)
	if got.Kind != SignerKindUnknown {
		t.Fatalf("kind = %q with no TTY and no CI variables, want unknown — an agent inheriting a human session looks exactly like this and must never read as a workload", got.Kind)
	}
	if got.Assurance != AssuranceUnknown {
		t.Errorf("assurance = %q, want unknown", got.Assurance)
	}
	if got.Federated != nil {
		t.Error("unknown kind must carry no federated block")
	}
}

// TestDetectSignerRecognizesInteractiveHuman asserts a controlling terminal
// with no CI variables is reported as a human session.
func TestDetectSignerRecognizesInteractiveHuman(t *testing.T) {
	got := detectSigner(envFrom(map[string]string{}), true)
	if got.Kind != SignerKindInteractiveHumanSession {
		t.Fatalf("kind = %q with a TTY and no CI variables, want interactive-human-session", got.Kind)
	}
	if !got.Kind.IsInteractiveHumanSession() {
		t.Error("the detected kind must classify as a human session")
	}
}

// TestWorkloadDetectionBeatsTTY asserts a CI runner that happens to have a TTY
// is still a workload — the ordering in detectSigner is deliberate.
func TestWorkloadDetectionBeatsTTY(t *testing.T) {
	got := detectSigner(envFrom(fullEnvFor(workloadProviders[0])), true)
	if got.Kind != SignerKindWorkloadIdentity {
		t.Errorf("kind = %q for a CI environment with a TTY, want workload-identity", got.Kind)
	}
}

// TestDetectSignerIsDeterministic asserts repeated detection over the same
// inputs produces byte-identical output. Signed evidence must not vary run to
// run, and the Evidence slice is the field most likely to pick up map-iteration
// nondeterminism.
func TestDetectSignerIsDeterministic(t *testing.T) {
	env := envFrom(fullEnvFor(workloadProviders[0]))
	first, err := json.Marshal(detectSigner(env, false))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		next, err := json.Marshal(detectSigner(env, false))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("detectSigner is nondeterministic:\n first: %s\n  then: %s", first, next)
		}
	}
}

// TestDescribeSignerKindNamesUnknownValues asserts the catalog helper does not
// silently render an empty line for a kind it does not know.
func TestDescribeSignerKindNamesUnknownValues(t *testing.T) {
	got := describeSignerKind(SignerKind("nope"))
	if !strings.Contains(got, "unrecognized") {
		t.Errorf("describeSignerKind(unknown value) = %q, want it to name the value as unrecognized", got)
	}
	for _, k := range AllSignerKinds() {
		if describeSignerKind(k) != signerKindTable[k].Doc {
			t.Errorf("describeSignerKind(%q) does not return the table's Doc", k)
		}
	}
}

// stringsOf converts any declared enum slice to strings for set comparison.
func stringsOf[T ~string](in []T) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	return out
}
