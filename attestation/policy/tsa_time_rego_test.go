// jade:ring local

package policy

// Verified TSA times in the rego input (testifysec/judge#10528).
//
// FedRAMP deadlines are measured between two events, for example "evaluated
// within 7 days of detection" (VER-TFR-EVU). Before this change rego could read
// another step's collections through attestationsFrom but never the RFC 3161
// time that proves when each was signed. The only times it could read were
// ones the signer wrote into its own payload, and a signer-written clock is
// exactly the one a verifier cannot trust.
//
// These tests pin:
//
//  1. input.collection.tsaTime (the collection under evaluation) and
//     input.steps.<dep>.collections[].tsaTime carry the EARLIEST verified TSA
//     time on a signature whose verifier matched a step functionary, as Unix
//     nanoseconds.
//  2. The field is absent when there is no such time, so a rule reading it is
//     refused rather than passed.
//  3. A payload field of the same name never reaches either location.
//  4. A 7-day deadline rule passes and fails through the real Policy.Verify.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tsaScanType = "https://example.com/vuln-scan/v1"
	tsaEvalType = "https://example.com/vuln-evaluation/v1"
	tsaSubject  = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
)

// selfTimedAttestor carries a payload field literally named tsaTime: the
// signer can write anything there, so it must never be mistaken for the
// verified time.
type selfTimedAttestor struct {
	AttType string `json:"type"`
	TSATime int64  `json:"tsaTime"`
}

func (a *selfTimedAttestor) Name() string                                   { return "self-timed" }
func (a *selfTimedAttestor) Type() string                                   { return a.AttType }
func (a *selfTimedAttestor) RunType() attestation.RunType                   { return "test" }
func (a *selfTimedAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *selfTimedAttestor) Schema() *jsonschema.Schema                     { return nil }

func tsaTestVerifier(t *testing.T) (cryptoutil.Verifier, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	kid, err := v.KeyID()
	require.NoError(t, err)
	return v, kid
}

// timedCollection is a signature-verified collection for step whose
// functionary-matched signer carries the given verified TSA times.
func timedCollection(t *testing.T, step, ref, attType string, v cryptoutil.Verifier, kid string, claimed int64, tsa ...time.Time) source.CollectionVerificationResult {
	t.Helper()
	coll := attestation.Collection{
		Name: step,
		Attestations: []attestation.CollectionAttestation{{
			Type:        attType,
			Attestation: &selfTimedAttestor{AttType: attType, TSATime: claimed},
		}},
	}
	pred, err := json.Marshal(coll)
	require.NoError(t, err)
	res := source.CollectionVerificationResult{
		Verifiers:          []cryptoutil.Verifier{v},
		ValidFunctionaries: []cryptoutil.Verifier{v},
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{
				Type:          intoto.StatementType,
				PredicateType: attestation.CollectionType,
				Subject:       []intoto.Subject{{Name: "system", Digest: map[string]string{"sha256": tsaSubject}}},
				Predicate:     pred,
			},
			Collection: coll,
			Reference:  ref,
		},
	}
	if len(tsa) > 0 {
		res.VerifiedTimestampsByKeyID = map[string][]time.Time{kid: tsa}
	}
	return res
}

func collectionEntries(t *testing.T, ctx map[string]interface{}, step string) []map[string]interface{} {
	t.Helper()
	stepData, ok := ctx[step].(map[string]interface{})
	require.True(t, ok, "input.steps.%s must exist", step)
	raw, ok := stepData[stepCollectionsKey].([]interface{})
	require.True(t, ok)
	out := make([]map[string]interface{}, 0, len(raw))
	for _, c := range raw {
		out = append(out, c.(map[string]interface{}))
	}
	return out
}

func TestTSATime_DepCollectionCarriesEarliestFunctionaryTime(t *testing.T) {
	v, kid := tsaTestVerifier(t)
	early := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	c := timedCollection(t, "scan", "gitoid:a", tsaScanType, v, kid, 0, late, early)

	ctx := buildStepContext([]string{"scan"}, map[string]StepResult{"scan": {Step: "scan", Passed: []PassedCollection{{Collection: c}}}})
	entries := collectionEntries(t, ctx, "scan")
	require.Len(t, entries, 1)
	assert.Equal(t, json.Number("1788264000000000000"), entries[0]["tsaTime"], "earliest verified time, Unix ns")
}

// A TSA token on a signature that did NOT match a functionary must not supply
// the time, the same scoping triageTrustedCollection applies to
// timestampConstraint.
func TestTSATime_NonFunctionarySignatureDoesNotSupplyTime(t *testing.T) {
	v, _ := tsaTestVerifier(t)
	_, otherKid := tsaTestVerifier(t)
	c := timedCollection(t, "scan", "gitoid:a", tsaScanType, v, otherKid, 0, time.Now())

	entries := collectionEntries(t, buildStepContext([]string{"scan"}, map[string]StepResult{"scan": {Step: "scan", Passed: []PassedCollection{{Collection: c}}}}), "scan")
	_, present := entries[0]["tsaTime"]
	assert.False(t, present, "no functionary-matched TSA time: the field is absent")
}

// The signer controls every byte of its payload, including a field named
// tsaTime. With no verified TSA time that field must not surface as
// input.steps.<dep>.collections[].tsaTime or as input.collection.tsaTime.
func TestTSATime_PayloadFieldOfTheSameNameNeverReachesIt(t *testing.T) {
	v, kid := tsaTestVerifier(t)
	forged := time.Now().UnixNano()
	scan := timedCollection(t, "scan", "gitoid:a", tsaScanType, v, kid, forged)

	entries := collectionEntries(t, buildStepContext([]string{"scan"}, map[string]StepResult{"scan": {Step: "scan", Passed: []PassedCollection{{Collection: scan}}}}), "scan")
	_, present := entries[0]["tsaTime"]
	assert.False(t, present, "payload tsaTime must not become the verified field")

	eval := timedCollection(t, "evaluate", "gitoid:e", tsaEvalType, v, kid, forged)
	step := evaluateStep(`package probe
deny[msg] {
    input.collection.tsaTime
    msg := "input.collection.tsaTime exists"
}
deny[msg] {
    c := input.steps.scan.collections[_]
    c.tsaTime
    msg := "input.steps.scan.collections[].tsaTime exists"
}`)
	stepCtx := buildStepRegoContext(step, map[string]StepResult{"scan": {Step: "scan", Passed: []PassedCollection{{Collection: scan}}}}, nil)
	outcome, _, rc := step.gateOne(eval, "", stepCtx)
	assert.Equal(t, gatePassed, outcome, "neither verified field may exist: %v", rc.Reason)
}

func evaluateStep(module string) Step {
	return Step{
		Name:             "evaluate",
		AttestationsFrom: []string{"scan"},
		Attestations: []Attestation{{
			Type:         tsaEvalType,
			RegoPolicies: []RegoPolicy{{Name: "deadline", Module: []byte(module)}},
		}},
	}
}

// deadlineModule is the rule the issue asks for, taken from the policy docs so
// the published example is the one under test: every evaluation must be signed
// within 7 days of the scan that detected the finding.
func deadlineModule(t *testing.T) string {
	t.Helper()
	return string(policySchemaDocFence(t, "ver.evaluation_deadline"))
}

type tsaCollectionSource struct {
	byStep map[string][]source.CollectionVerificationResult
}

func (s *tsaCollectionSource) Search(_ context.Context, name string, _, _ []string) ([]source.CollectionVerificationResult, error) {
	return s.byStep[name], nil
}

func (s *tsaCollectionSource) SearchByPredicateType(context.Context, []string, []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

func verifyDeadline(t *testing.T, scanTSA, evalTSA []time.Time) (bool, map[string]StepResult, error) {
	t.Helper()
	v, kid := tsaTestVerifier(t)
	// Each payload claims it was stamped at the scan's time: a forged
	// self-report that would make any delay look like zero.
	claimed := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	src := &tsaCollectionSource{byStep: map[string][]source.CollectionVerificationResult{
		"scan":     {timedCollection(t, "scan", "gitoid:scan", tsaScanType, v, kid, claimed, scanTSA...)},
		"evaluate": {timedCollection(t, "evaluate", "gitoid:eval", tsaEvalType, v, kid, claimed, evalTSA...)},
	}}
	for _, name := range []string{"scan", "evaluate"} {
		for i := range src.byStep[name] {
			src.byStep[name][i].ValidFunctionaries = nil // Verify's triage decides this
		}
	}
	fn := []Functionary{{Type: "publickey", PublicKeyID: kid}}
	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"scan": {Name: "scan", Functionaries: fn, Attestations: []Attestation{{Type: tsaScanType}}},
			"evaluate": func() Step {
				s := evaluateStep(deadlineModule(t))
				s.Functionaries = fn
				return s
			}(),
		},
	}
	return p.Verify(context.Background(), WithVerifiedSource(src), WithSubjectDigests([]string{tsaSubject}))
}

func TestTSATime_SevenDayDeadline_ThroughVerify(t *testing.T) {
	scan := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	pass, results, err := verifyDeadline(t, []time.Time{scan}, []time.Time{scan.Add(6 * 24 * time.Hour)})
	require.NoError(t, err)
	require.True(t, pass, "6 days after detection is inside the deadline: %+v", results)

	pass, results, err = verifyDeadline(t, []time.Time{scan}, []time.Time{scan.Add(7 * 24 * time.Hour)})
	require.NoError(t, err)
	require.True(t, pass, "exactly 7 days is on the bound, not past it: %+v", results)

	pass, results, _ = verifyDeadline(t, []time.Time{scan}, []time.Time{scan.Add(7*24*time.Hour + time.Second)})
	require.False(t, pass, "one second past 7 days must fail")
	require.Contains(t, results["evaluate"].Rejected[0].Reason.Error(), "over the 7-day deadline")
}

// Absent is not zero: a rule that reads a missing tsaTime is refused, on
// either side of the subtraction.
func TestTSATime_SevenDayDeadline_MissingTimeFailsClosed(t *testing.T) {
	scan := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	pass, results, _ := verifyDeadline(t, []time.Time{scan}, nil)
	require.False(t, pass, "evaluation without a verified TSA time must not pass")
	require.Contains(t, results["evaluate"].Rejected[0].Reason.Error(), "tsaTime")

	pass, results, _ = verifyDeadline(t, nil, []time.Time{scan.Add(time.Hour)})
	require.False(t, pass, "scan without a verified TSA time must not satisfy the deadline")
	require.Contains(t, results["evaluate"].Rejected[0].Reason.Error(), "tsaTime")
}

// The gate memo replays a verdict for a collection it cannot tell apart from
// one already gated. The verified TSA time now feeds Rego, so it must feed
// the key too: otherwise a verdict computed under one time replays for the
// same payload signed at another.
func TestTSATime_GateMemoKeyBindsTheTime(t *testing.T) {
	v, kid := tsaTestVerifier(t)
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	a := timedCollection(t, "evaluate", "", tsaEvalType, v, kid, 0, at)
	b := timedCollection(t, "evaluate", "", tsaEvalType, v, kid, 0, at.Add(8*24*time.Hour))
	g := newGateMemo().forStep("evaluate", map[string]interface{}{})
	require.NotNil(t, g)
	assert.NotEqual(t, g.key(a), g.key(b))
	assert.Equal(t, g.key(a), g.key(timedCollection(t, "evaluate", "", tsaEvalType, v, kid, 0, at)))
}
