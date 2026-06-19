// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import (
	"errors"
	"testing"
)

// TestParseTransmitResponse_SuccessStripsSW confirms a 0x9000 response strips
// the trailing 2 SW bytes and reports no continuation.
func TestParseTransmitResponse_SuccessStripsSW(t *testing.T) {
	resp := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00}
	more, data, err := parseTransmitResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if more {
		t.Fatalf("expected more=false on 0x9000")
	}
	if want := []byte{0xDE, 0xAD, 0xBE, 0xEF}; !bytesEqual(data, want) {
		t.Fatalf("data = %x, want %x", data, want)
	}
}

// TestParseTransmitResponse_GetResponseChaining confirms a 0x61xx response
// reports more=true and still strips the SW bytes — this is the GET RESPONSE
// chaining path used for multi-byte reads (e.g. certificate retrieval).
func TestParseTransmitResponse_GetResponseChaining(t *testing.T) {
	// 0x61 0x10 means "0x10 more bytes available".
	resp := []byte{0x01, 0x02, 0x03, 0x61, 0x10}
	more, data, err := parseTransmitResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !more {
		t.Fatalf("expected more=true on 0x61xx")
	}
	if want := []byte{0x01, 0x02, 0x03}; !bytesEqual(data, want) {
		t.Fatalf("data = %x, want %x", data, want)
	}
}

// TestParseTransmitResponse_EmptyDataSuccess confirms an exactly-2-byte 0x9000
// response yields empty data (not an error).
func TestParseTransmitResponse_EmptyDataSuccess(t *testing.T) {
	more, data, err := parseTransmitResponse([]byte{0x90, 0x00})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if more || len(data) != 0 {
		t.Fatalf("more=%v data=%x, want more=false data=empty", more, data)
	}
}

// TestParseTransmitResponse_ErrorStatus confirms a non-success SW maps to an
// *apduErr carrying the exact SW1/SW2, and that the well-known PIV statuses
// unwrap to the typed errors callers rely on (ErrNotFound, AuthErr{n}).
func TestParseTransmitResponse_ErrorStatus(t *testing.T) {
	tests := []struct {
		name       string
		sw1, sw2   byte
		wantStatus uint16
		wantUnwrap error // matched with errors.Is, nil means "no special unwrap"
		wantAuthN  int   // for AuthErr cases, -1 if N/A
	}{
		{"not found (6a82)", 0x6a, 0x82, 0x6a82, ErrNotFound, -1},
		{"ref data not found (6a88)", 0x6a, 0x88, 0x6a88, ErrNotFound, -1},
		{"verify failed 3 retries (63c3)", 0x63, 0xc3, 0x63c3, nil, 3},
		{"blocked (6983)", 0x69, 0x83, 0x6983, nil, 0},
		{"security status (6982)", 0x69, 0x82, 0x6982, nil, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := []byte{0xFF, tc.sw1, tc.sw2}
			more, data, err := parseTransmitResponse(resp)
			if more || data != nil {
				t.Fatalf("more=%v data=%x, want more=false data=nil", more, data)
			}
			var ae *apduErr
			if !errors.As(err, &ae) {
				t.Fatalf("error %v is not *apduErr", err)
			}
			if ae.Status() != tc.wantStatus {
				t.Fatalf("status = %04x, want %04x", ae.Status(), tc.wantStatus)
			}
			if tc.wantUnwrap != nil && !errors.Is(err, tc.wantUnwrap) {
				t.Fatalf("error %v does not unwrap to %v", err, tc.wantUnwrap)
			}
			if tc.wantAuthN >= 0 {
				var auth AuthErr
				if !errors.As(err, &auth) {
					t.Fatalf("error %v is not AuthErr", err)
				}
				if auth.Retries != tc.wantAuthN {
					t.Fatalf("retries = %d, want %d", auth.Retries, tc.wantAuthN)
				}
			}
		})
	}
}

// TestParseTransmitResponse_TooShort confirms a <2-byte response is an error,
// not a panic (defends against a truncated read).
func TestParseTransmitResponse_TooShort(t *testing.T) {
	for _, resp := range [][]byte{nil, {}, {0x90}} {
		if _, _, err := parseTransmitResponse(resp); err == nil {
			t.Fatalf("expected error for short response %x", resp)
		}
	}
}

func TestScCheck(t *testing.T) {
	if err := scCheck(rcSuccess, nil); err != nil {
		t.Fatalf("success code should be nil error, got %v", err)
	}
	// 0x80100069: card removed.
	err := scCheck(0x80100069, nil)
	if err == nil {
		t.Fatalf("non-success code should be an error")
	}
	var se *scErr
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not *scErr", err)
	}
}

func TestFindReaderName(t *testing.T) {
	tests := []struct {
		name    string
		readers []string
		want    string
		found   bool
	}{
		{"yubikey product string", []string{"Yubico YubiKey OTP+FIDO+CCID"}, "Yubico YubiKey OTP+FIDO+CCID", true},
		{"case insensitive", []string{"ACME Reader", "some yubikey here"}, "some yubikey here", true},
		{"yubico vendor only", []string{"Yubico Authenticator"}, "Yubico Authenticator", true},
		{"no yubikey", []string{"Generic Smart Card Reader"}, "", false},
		{"empty", nil, "", false},
		{"first match wins", []string{"YubiKey A", "YubiKey B"}, "YubiKey A", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, found := FindReaderName(tc.readers)
			if found != tc.found || got != tc.want {
				t.Fatalf("FindReaderName(%v) = (%q,%v), want (%q,%v)", tc.readers, got, found, tc.want, tc.found)
			}
		})
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
