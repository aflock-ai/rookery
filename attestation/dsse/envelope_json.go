// Copyright 2026 The Aflock Authors
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

package dsse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// UnmarshalJSON applies the DSSE JSON envelope parsing rules (DSSE envelope
// v1.0.2): payload, payloadType and signatures are REQUIRED keys, where
// set-but-empty (including null) counts as set, and payload is base64 in the
// standard or the URL-safe alphabet, both of which a verifier MUST accept
// (DSSE protocol v1.0.2). Unknown fields are ignored. Encoding is unchanged:
// Envelope marshals with the standard alphabet.
func (e *Envelope) UnmarshalJSON(data []byte) error {
	var raw struct {
		Payload     json.RawMessage `json:"payload"`
		PayloadType json.RawMessage `json:"payloadType"`
		Signatures  json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	switch {
	case raw.Payload == nil:
		return errors.New("dsse: envelope is missing the REQUIRED payload field")
	case raw.PayloadType == nil:
		return errors.New("dsse: envelope is missing the REQUIRED payloadType field")
	case raw.Signatures == nil:
		return errors.New("dsse: envelope is missing the REQUIRED signatures field")
	}
	payload, err := decodeBase64Field(raw.Payload)
	if err != nil {
		return fmt.Errorf("dsse: payload: %w", err)
	}
	var payloadType string
	if string(raw.PayloadType) != "null" {
		if err := json.Unmarshal(raw.PayloadType, &payloadType); err != nil {
			return fmt.Errorf("dsse: payloadType: %w", err)
		}
	}
	var sigs []Signature
	if err := json.Unmarshal(raw.Signatures, &sigs); err != nil {
		return fmt.Errorf("dsse: signatures: %w", err)
	}
	*e = Envelope{Payload: payload, PayloadType: payloadType, Signatures: sigs}
	return nil
}

// UnmarshalJSON decodes one signature: sig is a REQUIRED key and, like the
// payload, is base64 in either alphabet. The certificate, intermediates and
// timestamps are rookery's own extensions and keep their standard encoding.
func (s *Signature) UnmarshalJSON(data []byte) error {
	var w struct {
		KeyID         string               `json:"keyid"`
		Sig           json.RawMessage      `json:"sig"`
		Certificate   []byte               `json:"certificate,omitempty"`
		Intermediates [][]byte             `json:"intermediates,omitempty"`
		Timestamps    []SignatureTimestamp `json:"timestamps,omitempty"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	if w.Sig == nil {
		return errors.New("dsse: signature is missing the REQUIRED sig field")
	}
	sig, err := decodeBase64Field(w.Sig)
	if err != nil {
		return fmt.Errorf("dsse: sig: %w", err)
	}
	*s = Signature{KeyID: w.KeyID, Signature: sig, Certificate: w.Certificate, Intermediates: w.Intermediates, Timestamps: w.Timestamps}
	return nil
}

// decodeBase64Field decodes a JSON string holding padded base64 in the
// standard alphabet (RFC 4648 §4) or the URL-safe one (§5). The two differ
// only at indexes 62 and 63, so a string valid in both decodes to the same
// bytes either way. JSON null is the empty value.
func decodeBase64Field(raw json.RawMessage) ([]byte, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not base64 in the standard or the URL-safe alphabet: %w", err)
	}
	return b, nil
}
