// jade:ring local

package source

// formal:differential dsse-intoto TestFormalConsumeDifferential
//
// Binds the Lean model of reading a verified envelope as an in-toto statement
// (formal/dsse-intoto, DsseIntoto/Statement.lean) to this package:
//
//   - consume:  EnvelopeToCollectionEnvelope must accept exactly the payload
//     types, statement types and payloads the model accepts.
//   - external: VerifiedSource.SearchByPredicateType, over a source that
//     returns a validly signed envelope next to its own decode, must accept
//     exactly when the model does and hand on the statement the model names.
//
// consumeModel names which model the shipped code must match: "asbuilt"
// while the code has the refuted behaviour, "required" once the fix lands.
//
// The test skips when the vectors are not on disk and FAILS instead when
// JADE_FORMAL_DIFFERENTIAL=1.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

const consumeModel = "asbuilt"

type formalDecoded struct {
	Type          string `json:"type"`
	PredicateType string `json:"predicateType"`
	Collection    bool   `json:"collection"`
}

type formalConsumeVectors struct {
	Consume []struct {
		PayloadType string         `json:"payloadType"`
		Payload     *formalDecoded `json:"payload"`
		AsBuilt     bool           `json:"asbuilt"`
		Required    bool           `json:"required"`
	} `json:"consume"`
	External []struct {
		PayloadType string         `json:"payloadType"`
		Payload     *formalDecoded `json:"payload"`
		Source      formalDecoded  `json:"source"`
		Requested   []string       `json:"requested"`
		AsBuilt     *formalDecoded `json:"asbuilt"`
		Required    *formalDecoded `json:"required"`
	} `json:"external"`
}

const formalSubjectDigest = "4f1c6e1b0a7a1f4b6ad0e5d8f1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c4"

// formalPayload is the JSON a Decoded stands for; nil is bytes that are not
// a statement at all.
func formalPayload(d *formalDecoded) []byte {
	if d == nil {
		return []byte("not json")
	}
	pred := `"not-a-collection"`
	if d.Collection {
		pred = `{"name":"step","attestations":[]}`
	}
	return []byte(fmt.Sprintf(`{"_type":%q,"subject":[{"name":"a","digest":{"sha256":%q}}],"predicateType":%q,"predicate":%s}`,
		d.Type, formalSubjectDigest, d.PredicateType, pred))
}

type formalExternalSource struct {
	env  dsse.Envelope
	stmt intoto.Statement
}

func (s formalExternalSource) Search(context.Context, string, []string, []string) ([]CollectionEnvelope, error) {
	return nil, nil
}

func (s formalExternalSource) SearchByPredicateType(context.Context, []string, []string) ([]StatementEnvelope, error) {
	return []StatementEnvelope{{Envelope: s.env, Statement: s.stmt, Reference: "formal"}}, nil
}

func TestFormalConsumeDifferential(t *testing.T) {
	path := filepath.Join("..", "..", "formal", "dsse-intoto", "vectors", "dsse-intoto.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") != "" {
			t.Fatalf("JADE_FORMAL_DIFFERENTIAL is set but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal vectors not on disk (%v); the differential needs the repository checkout", err)
	}
	var v formalConsumeVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(v.Consume) == 0 || len(v.External) == 0 {
		t.Fatalf("vectors are missing a section: consume=%d external=%d", len(v.Consume), len(v.External))
	}

	bad := 0
	for i, c := range v.Consume {
		want := c.AsBuilt
		if consumeModel == "required" {
			want = c.Required
		}
		_, err := EnvelopeToCollectionEnvelope("formal", dsse.Envelope{PayloadType: c.PayloadType, Payload: formalPayload(c.Payload)})
		if got := err == nil; got != want {
			bad++
			if bad <= 20 {
				t.Errorf("consume case %d: code accepts=%v, %s model %v (payloadType %q, payload %+v, err %v)", i, got, consumeModel, want, c.PayloadType, c.Payload, err)
			}
		}
	}
	if bad > 0 {
		t.Errorf("consume: %d of %d cases disagree with the %s model", bad, len(v.Consume), consumeModel)
	} else {
		t.Logf("consume: %d cases agree with the %s model", len(v.Consume), consumeModel)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := cryptoutil.NewECDSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	bad = 0
	for i, c := range v.External {
		want := c.AsBuilt
		if consumeModel == "required" {
			want = c.Required
		}
		env, err := dsse.Sign(c.PayloadType, strings.NewReader(string(formalPayload(c.Payload))), dsse.SignWithSigners(signer))
		if err != nil {
			t.Fatal(err)
		}
		src := formalExternalSource{env: env, stmt: intoto.Statement{Type: c.Source.Type, PredicateType: c.Source.PredicateType}}
		rs, err := NewVerifiedSource(src, dsse.VerifyWithVerifiers(verifier)).
			SearchByPredicateType(context.Background(), c.Requested, []string{formalSubjectDigest})
		if err != nil || len(rs) != 1 {
			t.Fatalf("external case %d: %d results, err %v", i, len(rs), err)
		}
		var got *formalDecoded
		if len(rs[0].Verifiers) > 0 && len(rs[0].Errors) == 0 {
			got = &formalDecoded{Type: rs[0].Statement.Type, PredicateType: rs[0].Statement.PredicateType}
		}
		if want != nil {
			want = &formalDecoded{Type: want.Type, PredicateType: want.PredicateType}
		}
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			bad++
			if bad <= 20 {
				t.Errorf("external case %d: code %+v, %s model %+v (payloadType %q, payload %+v, source %+v, errors %v)",
					i, got, consumeModel, want, c.PayloadType, c.Payload, c.Source, rs[0].Errors)
			}
		}
	}
	if bad > 0 {
		t.Errorf("external: %d of %d cases disagree with the %s model", bad, len(v.External), consumeModel)
	} else {
		t.Logf("external: %d cases agree with the %s model", len(v.External), consumeModel)
	}
}
