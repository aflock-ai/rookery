package witness_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// TestVerifyWitnessAttestation verifies a DSSE envelope created by
// go-witness 0.10.2 using rookery's verification code.
// No attestor plugins are imported — RawAttestation handles deserialization.
//
// Set WITNESS_ATTESTATION and WITNESS_PUBKEY env vars to the paths.
func TestVerifyWitnessAttestation(t *testing.T) { //nolint:gocyclo
	attestationPath := os.Getenv("WITNESS_ATTESTATION")
	pubkeyPath := os.Getenv("WITNESS_PUBKEY")
	if attestationPath == "" || pubkeyPath == "" {
		t.Skip("set WITNESS_ATTESTATION and WITNESS_PUBKEY to run this test")
	}

	// Load the public key
	pubKeyFile, err := os.Open(pubkeyPath)
	if err != nil {
		t.Fatalf("failed to open public key: %v", err)
	}
	defer pubKeyFile.Close()

	verifier, err := cryptoutil.NewVerifierFromReader(pubKeyFile)
	if err != nil {
		t.Fatalf("failed to create verifier from public key: %v", err)
	}

	// Load the DSSE envelope
	envData, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Fatalf("failed to read attestation: %v", err)
	}

	var envelope dsse.Envelope
	if err := json.Unmarshal(envData, &envelope); err != nil {
		t.Fatalf("failed to unmarshal DSSE envelope: %v", err)
	}
	t.Logf("DSSE envelope payload type: %s", envelope.PayloadType)
	t.Logf("DSSE envelope signatures: %d", len(envelope.Signatures))

	// Verify the DSSE signature using rookery
	checkedVerifiers, err := envelope.Verify(dsse.VerifyWithVerifiers(verifier))
	if err != nil {
		t.Fatalf("DSSE signature verification FAILED: %v", err)
	}
	t.Logf("DSSE signature verification PASSED (%d verifiers matched)", len(checkedVerifiers))

	// Unmarshal the in-toto statement from the envelope payload
	var statement intoto.Statement
	if err := json.Unmarshal(envelope.Payload, &statement); err != nil {
		t.Fatalf("failed to unmarshal in-toto statement: %v", err)
	}
	t.Logf("In-toto statement type: %s", statement.Type)
	t.Logf("In-toto predicate type: %s", statement.PredicateType)
	t.Logf("In-toto subjects: %d", len(statement.Subject))

	// Unmarshal the Collection using attestation.Collection — no plugin imports needed.
	// RawAttestation fallback preserves raw JSON for each unknown attestor type.
	var collection attestation.Collection
	if err := json.Unmarshal(statement.Predicate, &collection); err != nil {
		t.Fatalf("failed to unmarshal collection predicate: %v", err)
	}
	t.Logf("Collection name: %s", collection.Name)
	t.Logf("Collection attestations: %d", len(collection.Attestations))

	if collection.Name == "" {
		t.Error("collection name is empty")
	}
	if len(collection.Attestations) == 0 {
		t.Error("collection has no attestations")
	}

	for _, att := range collection.Attestations {
		t.Logf("  - type: %s, name: %s", att.Type, att.Attestation.Name())

		// Verify json.Marshal on the attestation produces valid JSON.
		// This proves Rego/AI policy evaluation would get the original data.
		marshaled, err := json.Marshal(att.Attestation)
		if err != nil {
			t.Errorf("failed to marshal attestation %s: %v", att.Type, err)
			continue
		}
		if !json.Valid(marshaled) {
			t.Errorf("marshaled attestation %s is not valid JSON", att.Type)
		}
		t.Logf("    marshaled %d bytes of valid JSON", len(marshaled))
	}

	// Verify the predicate type is a recognized collection type (dual-URI support)
	switch statement.PredicateType {
	case "https://witness.testifysec.com/attestation-collection/v0.1",
		"https://aflock.ai/attestation-collection/v0.1":
		t.Logf("Predicate type recognized: %s", statement.PredicateType)
	default:
		t.Errorf("unrecognized predicate type: %s", statement.PredicateType)
	}
}
