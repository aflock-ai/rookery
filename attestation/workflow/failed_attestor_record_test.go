// jade:ring local

package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// #10618: a failed attestor is recorded in the signed collection by name and
// fixed class, and the collection is then v0.2. A run with no failure signs
// v0.1 exactly as before.

type failingAttestor struct {
	name string
	fail func() error
}

func (a *failingAttestor) Name() string                 { return a.name }
func (a *failingAttestor) Type() string                 { return "https://example.com/" + a.name + "/v1" }
func (a *failingAttestor) RunType() attestation.RunType { return attestation.PostProductRunType }
func (a *failingAttestor) Schema() *jsonschema.Schema   { return nil }
func (a *failingAttestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{}
}
func (a *failingAttestor) Attest(*attestation.AttestationContext) error {
	if a.fail == nil {
		return nil
	}
	return a.fail()
}

func signedCollection(t *testing.T, atts ...attestation.Attestor) (string, attestation.Collection) {
	t.Helper()
	result, _ := Run("record", RunWithSigners(sizeTestSigner(t)), RunWithAttestors(atts))
	var stmt struct {
		PredicateType string                 `json:"predicateType"`
		Predicate     attestation.Collection `json:"predicate"`
	}
	require.NoError(t, json.Unmarshal(result.SignedEnvelope.Payload, &stmt))
	return stmt.PredicateType, stmt.Predicate
}

func TestRunRecordsFailedAttestorsByNameAndClass(t *testing.T) {
	const secret = "/home/alice/.aws/credentials: open failed with token=hunter2"
	pt, coll := signedCollection(t,
		&failingAttestor{name: "ok"},
		&failingAttestor{name: "soft", fail: func() error { return attestation.SoftError{Reason: secret} }},
		&failingAttestor{name: "slow", fail: func() error { return fmt.Errorf("%s: %w", secret, context.DeadlineExceeded) }},
		&failingAttestor{name: "missing", fail: func() error { return fmt.Errorf("%s: %w", secret, fs.ErrNotExist) }},
		&failingAttestor{name: "denied", fail: func() error { return fmt.Errorf("%s: %w", secret, fs.ErrPermission) }},
		&failingAttestor{name: "boom", fail: func() error { panic(secret) }},
		&failingAttestor{name: "odd", fail: func() error { return errors.New(secret) }},
	)
	require.Equal(t, attestation.CollectionTypeV02, pt)
	require.Equal(t, []attestation.FailedAttestor{
		{Name: "boom", Class: attestation.FailureCrash},
		{Name: "denied", Class: attestation.FailurePermission},
		{Name: "missing", Class: attestation.FailureNotFound},
		{Name: "odd", Class: attestation.FailureOther},
		{Name: "slow", Class: attestation.FailureTimeout},
		{Name: "soft", Class: attestation.FailureNoInput},
	}, coll.FailedAttestors, "sorted by name, one fixed class each")
	require.NoError(t, coll.ValidateFailedAttestors(pt))
	require.Len(t, coll.Attestations, 1, "only the attestor that succeeded is evidence")

	raw, err := json.Marshal(coll)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "hunter2", "no error text reaches the signed collection")
	require.NotContains(t, string(raw), ".aws")
}

func TestRunWithoutFailuresSignsV01(t *testing.T) {
	pt, coll := signedCollection(t, &failingAttestor{name: "ok"})
	require.Equal(t, attestation.CollectionType, pt)
	require.Empty(t, coll.FailedAttestors)
}

func TestRunDetectionIsEvidenceNotAFailureRecord(t *testing.T) {
	pt, coll := signedCollection(t, &failingAttestor{name: "scan", fail: func() error { return attestation.NewDetectionError("found 1") }})
	require.Equal(t, attestation.CollectionType, pt, "a detection kept its evidence; nothing failed")
	require.Empty(t, coll.FailedAttestors)
}
