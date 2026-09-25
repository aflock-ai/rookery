// jade:ring local

package dsse

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// DSSE protocol v1.0.2: "Either standard or URL-safe base64 encodings are
// allowed. Signers may use either, and verifiers MUST accept either."
// DSSE envelope v1.0.2, parsing rules: "The following fields are REQUIRED and
// MUST be set, even if empty: payload, payloadType, signature, signature.sig."

func TestEnvelopeDecodesURLSafeBase64(t *testing.T) {
	var env Envelope
	doc := `{"payload":"-_8=","payloadType":"t","signatures":[{"keyid":"k","sig":"-_8="}]}`
	if err := json.Unmarshal([]byte(doc), &env); err != nil {
		t.Fatalf("a URL-safe envelope, which a verifier MUST accept, was refused: %v", err)
	}
	if !bytes.Equal(env.Payload, []byte{0xfb, 0xff}) || !bytes.Equal(env.Signatures[0].Signature, []byte{0xfb, 0xff}) {
		t.Fatalf("URL-safe fields decoded wrong: payload %x sig %x", env.Payload, env.Signatures[0].Signature)
	}
}

func TestEnvelopeDecodesStandardBase64(t *testing.T) {
	var env Envelope
	doc := `{"payload":"+/8=","payloadType":"t","signatures":[{"sig":"aGVsbG8="}]}`
	if err := json.Unmarshal([]byte(doc), &env); err != nil {
		t.Fatalf("a standard-alphabet envelope was refused: %v", err)
	}
	if !bytes.Equal(env.Payload, []byte{0xfb, 0xff}) || string(env.Signatures[0].Signature) != "hello" {
		t.Fatalf("standard fields decoded wrong: payload %x sig %q", env.Payload, env.Signatures[0].Signature)
	}
}

func TestEnvelopeRefusesMalformedBase64(t *testing.T) {
	for _, doc := range []string{
		`{"payload":"!!!!","payloadType":"t","signatures":[]}`,
		`{"payload":"+_8=","payloadType":"t","signatures":[]}`, // mixes the two alphabets
		`{"payload":"aGVsbG8=","payloadType":"t","signatures":[{"sig":"!!!!"}]}`,
	} {
		var env Envelope
		if err := json.Unmarshal([]byte(doc), &env); err == nil {
			t.Errorf("malformed base64 decoded: %s", doc)
		}
	}
}

func TestEnvelopeRefusesMissingRequiredFields(t *testing.T) {
	for _, doc := range []string{
		`{"payloadType":"t","signatures":[]}`,
		`{"payload":"aGVsbG8=","signatures":[]}`,
		`{"payload":"aGVsbG8=","payloadType":"t"}`,
		`{"payload":"aGVsbG8=","payloadType":"t","signatures":[{"keyid":"k"}]}`,
		`{}`,
	} {
		var env Envelope
		if err := json.Unmarshal([]byte(doc), &env); err == nil {
			t.Errorf("an envelope missing a REQUIRED field decoded: %s", doc)
		}
	}
}

// Set-but-empty is set: the parsing rules require the key, not a value.
func TestEnvelopeAcceptsSetButEmptyFields(t *testing.T) {
	for _, doc := range []string{
		`{"payload":"","payloadType":"","signatures":[]}`,
		`{"payload":null,"payloadType":"t","signatures":null}`,
		`{"payload":"aGVsbG8=","payloadType":"t","signatures":[{"sig":""}]}`,
	} {
		var env Envelope
		if err := json.Unmarshal([]byte(doc), &env); err != nil {
			t.Errorf("a set-but-empty envelope was refused: %s: %v", doc, err)
		}
	}
}

// The encoder is unchanged (standard alphabet), and every other field
// round-trips.
func TestEnvelopeJSONRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign("application/vnd.in-toto+json", strings.NewReader(`{"a":"ûÿ"}`), SignWithSigners(cryptoutil.NewECDSASigner(priv, crypto.SHA256)))
	if err != nil {
		t.Fatal(err)
	}
	env.Signatures[0].Certificate = []byte("-----BEGIN CERTIFICATE-----\n")
	env.Signatures[0].Intermediates = [][]byte{[]byte("i1"), []byte("i2")}
	env.Signatures[0].Timestamps = []SignatureTimestamp{{Type: TimestampRFC3161, Data: []byte{0xfb, 0xff}}}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), base64.StdEncoding.EncodeToString(env.Payload)) {
		t.Fatalf("the encoder no longer writes the standard alphabet: %s", out)
	}
	var back Envelope
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, again) {
		t.Fatalf("round trip changed the envelope:\n%s\n%s", out, again)
	}
}

// A signed envelope re-encoded in the URL-safe alphabet verifies.
func TestEnvelopeURLSafeVerifies(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign("application/vnd.test+json", strings.NewReader("\xfb\xff\xfe payload"), SignWithSigners(cryptoutil.NewECDSASigner(priv, crypto.SHA256)))
	if err != nil {
		t.Fatal(err)
	}
	doc := `{"payload":"` + base64.URLEncoding.EncodeToString(env.Payload) + `","payloadType":"application/vnd.test+json","signatures":[{"keyid":"","sig":"` +
		base64.URLEncoding.EncodeToString(env.Signatures[0].Signature) + `"}]}`
	var back Envelope
	if err := json.Unmarshal([]byte(doc), &back); err != nil {
		t.Fatalf("URL-safe envelope refused: %v", err)
	}
	if _, err := back.Verify(VerifyWithVerifiers(cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256))); err != nil {
		t.Fatalf("URL-safe envelope did not verify: %v", err)
	}
}
