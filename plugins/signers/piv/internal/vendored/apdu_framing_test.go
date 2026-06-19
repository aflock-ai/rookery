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
	"bytes"
	"testing"
)

// fakeTransmit records the requests it received and replays a scripted list of
// responses. It lets us exercise the vendored pcsc.go (*scTx).Transmit framing
// (ISO-7816 command chaining + GET RESPONSE looping) without any hardware.
type fakeTransmit struct {
	t         *testing.T
	requests  [][]byte
	responses []fakeResp
	idx       int
}

type fakeResp struct {
	more bool
	data []byte
}

func (f *fakeTransmit) fn(req []byte) (bool, []byte, error) {
	f.requests = append(f.requests, append([]byte(nil), req...))
	if f.idx >= len(f.responses) {
		f.t.Fatalf("unexpected transmit #%d, req=%x (no scripted response)", f.idx+1, req)
	}
	r := f.responses[f.idx]
	f.idx++
	return r.more, r.data, nil
}

// TestTransmit_SingleAPDU confirms a small command produces exactly one APDU
// with the correct 5-byte header (CLA=0x00, INS, P1, P2, Lc) plus the data.
func TestTransmit_SingleAPDU(t *testing.T) {
	f := &fakeTransmit{t: t, responses: []fakeResp{
		{more: false, data: []byte{0xAA, 0xBB}},
	}}
	tx := &scTx{transmitFn: f.fn}

	resp, err := tx.Transmit(apdu{instruction: 0x87, param1: 0x11, param2: 0x9c, data: []byte{0x01, 0x02, 0x03}})
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !bytes.Equal(resp, []byte{0xAA, 0xBB}) {
		t.Fatalf("resp = %x, want AABB", resp)
	}
	if len(f.requests) != 1 {
		t.Fatalf("expected 1 transmit, got %d", len(f.requests))
	}
	want := []byte{0x00, 0x87, 0x11, 0x9c, 0x03, 0x01, 0x02, 0x03}
	if !bytes.Equal(f.requests[0], want) {
		t.Fatalf("req = %x, want %x", f.requests[0], want)
	}
}

// TestTransmit_GetResponseChaining confirms that when the card returns SW1=0x61
// (more data available) the framing layer issues GET RESPONSE (INS=0xc0) APDUs
// and concatenates the data until the card returns 0x9000.
func TestTransmit_GetResponseChaining(t *testing.T) {
	f := &fakeTransmit{t: t, responses: []fakeResp{
		{more: true, data: []byte{0x01, 0x02}},  // first chunk, "more"
		{more: true, data: []byte{0x03, 0x04}},  // second chunk via GET RESPONSE, still "more"
		{more: false, data: []byte{0x05, 0x06}}, // final chunk, 0x9000
	}}
	tx := &scTx{transmitFn: f.fn}

	resp, err := tx.Transmit(apdu{instruction: 0xcb, param1: 0x3f, param2: 0xff})
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	if !bytes.Equal(resp, want) {
		t.Fatalf("resp = %x, want %x", resp, want)
	}
	if len(f.requests) != 3 {
		t.Fatalf("expected 3 transmits (1 command + 2 GET RESPONSE), got %d", len(f.requests))
	}
	// The two continuation requests must be GET RESPONSE (INS=0xc0), 5-byte headers.
	for _, i := range []int{1, 2} {
		if f.requests[i][1] != insGetResponseAPDU {
			t.Fatalf("continuation req %d INS = %02x, want %02x", i, f.requests[i][1], insGetResponseAPDU)
		}
		if len(f.requests[i]) != 5 {
			t.Fatalf("GET RESPONSE req %d len = %d, want 5", i, len(f.requests[i]))
		}
	}
}

// TestTransmit_CommandChaining confirms that data larger than 255 bytes is
// split into 0x10-CLA continuation APDUs (ISO-7816-4 5.1.1), each carrying at
// most 0xff bytes, with the final APDU using CLA=0x00.
func TestTransmit_CommandChaining(t *testing.T) {
	// 600 bytes of data => two 255-byte chunks (CLA 0x10) + a 90-byte final.
	data := make([]byte, 600)
	for i := range data {
		data[i] = byte(i)
	}
	f := &fakeTransmit{t: t, responses: []fakeResp{
		{more: false, data: nil}, // ack first chained chunk
		{more: false, data: nil}, // ack second chained chunk
		{more: false, data: []byte{0xFE}},
	}}
	tx := &scTx{transmitFn: f.fn}

	resp, err := tx.Transmit(apdu{instruction: 0xdb, param1: 0x3f, param2: 0xff, data: data})
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !bytes.Equal(resp, []byte{0xFE}) {
		t.Fatalf("resp = %x, want FE", resp)
	}
	if len(f.requests) != 3 {
		t.Fatalf("expected 3 transmits (2 chained + 1 final), got %d", len(f.requests))
	}
	// First two are chained: CLA=0x10, Lc=0xff, 255 data bytes.
	for _, i := range []int{0, 1} {
		r := f.requests[i]
		if r[0] != 0x10 {
			t.Fatalf("chained req %d CLA = %02x, want 0x10", i, r[0])
		}
		if r[4] != 0xff {
			t.Fatalf("chained req %d Lc = %02x, want 0xff", i, r[4])
		}
		if len(r) != 5+0xff {
			t.Fatalf("chained req %d len = %d, want %d", i, len(r), 5+0xff)
		}
	}
	// Final APDU: CLA=0x00, Lc=90 (600 - 2*255).
	final := f.requests[2]
	if final[0] != 0x00 {
		t.Fatalf("final req CLA = %02x, want 0x00", final[0])
	}
	if int(final[4]) != 600-2*0xff {
		t.Fatalf("final req Lc = %d, want %d", final[4], 600-2*0xff)
	}
}

// TestTransmit_PropagatesAPDUError confirms a non-success SW on the first
// command surfaces as an *apduErr to the caller.
func TestTransmit_PropagatesAPDUError(t *testing.T) {
	// parseTransmitResponse would turn 0x6982 into an apduErr; emulate that the
	// underlying transmit returns the error directly.
	called := 0
	tx := &scTx{transmitFn: func(req []byte) (bool, []byte, error) {
		called++
		_, _, err := parseTransmitResponse([]byte{0x69, 0x82})
		return false, nil, err
	}}
	_, err := tx.Transmit(apdu{instruction: 0x20})
	if err == nil {
		t.Fatalf("expected error")
	}
	if called != 1 {
		t.Fatalf("expected 1 transmit, got %d", called)
	}
}
