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

// pcsc_goscard.go is the pure-Go (CGO_ENABLED=0) PC/SC transport for the
// vendored go-piv protocol layer. It replaces the upstream cgo files
// (pcsc_unix.go / pcsc_darwin.go / pcsc_windows.go, which were intentionally
// NOT vendored) with an implementation backed by github.com/ElMostafaIdrassi/
// goscard, which drives PC/SC over purego (no `import "C"`).
//
// The struct types (scContext, scHandle, scTx), their method names/signatures,
// the rcSuccess const, and scCheck are kept byte-compatible with the upstream
// cgo transport so that the vendored piv.go / key.go / pcsc.go compile and run
// UNCHANGED. The single load-bearing method is (*scTx).transmit, which
// reproduces upstream's Status-Word parsing exactly.

package piv

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ElMostafaIdrassi/goscard"
)

// rcSuccess mirrors the upstream constant (C.SCARD_S_SUCCESS == 0). The
// vendored scErr type formats any non-success return code via pcscErrMsgs.
const rcSuccess = 0

// scCheck converts a raw PC/SC return code (the SCARD_* code goscard returns as
// the second value of every call) plus the call's Go error into a *scErr,
// matching the upstream cgo scCheck contract. A nil error with a success code
// means the call succeeded.
//
// goscard already surfaces non-success codes as a non-nil err, but we treat the
// raw code as authoritative so the rich pcscErrMsgs table (keyed by the SCARD_*
// code) is preserved exactly as upstream.
func scCheck(ret uint64, err error) error {
	if ret == rcSuccess {
		return nil
	}
	return &scErr{rc: int64(ret)}
}

// pcscInit guards the process-global goscard.Initialize, which loads the PCSC
// shared library and binds every SCard symbol exactly once. goscard.Initialize
// is documented as a no-op if the library is already loaded, but we additionally
// guard it so concurrent Open() calls can't race the package-global proc
// pointers it mutates.
var (
	pcscInitOnce sync.Once
	pcscInitErr  error
)

func pcscInitialize() error {
	pcscInitOnce.Do(func() {
		// No explicit lib paths => goscard uses the built-in per-OS default
		// (on darwin: the PCSC.framework shipped with macOS).
		//
		// Logging: goscard's default (passing nil) is a stdout logger at INFO
		// level, which prints a "[INFO] Transmit IN/OUT" line for EVERY APDU
		// plus a benign "[ERRO] Failed to find SCardFreeMemory" probe at load
		// time. That noise pollutes a normal signing session, so we install a
		// quiet logger that drops everything (LogLevelNone) by default. Set
		// CILOCK_PIV_DEBUG=1 to restore goscard's verbose per-APDU tracing on
		// stderr for hardware debugging.
		pcscInitErr = goscard.Initialize(pcscLogger())
	})
	return pcscInitErr
}

// pcscLogger returns the goscard logger to install. Quiet (LogLevelNone) by
// default so a normal sign emits no PC/SC chatter; CILOCK_PIV_DEBUG enables
// full debug-level tracing to stderr.
//
// Reading the debug toggle from the environment is the cilock/rookery
// convention (cf. CILOCK_FANOTIFY, CILOCK_FSVERITY, CILOCK_EBPF_DEBUG): cilock
// is a standalone cobra CLI with no Viper layer, and the rookery subtree does
// not enforce the judge-api Viper-only rule (no forbidigo in rookery's
// .golangci.yml). goscard's logger is a process-global set once inside
// Initialize, so resolving the toggle once under pcscInitOnce is correct — the
// logger cannot be reconfigured per call regardless.
func pcscLogger() goscard.Logger {
	if v := os.Getenv("CILOCK_PIV_DEBUG"); v != "" && v != "0" && v != "false" {
		return goscard.NewDefaultFileLogger(goscard.LogLevelDebug, os.Stderr)
	}
	return goscard.NewDefaultFileLogger(goscard.LogLevelNone, os.Stderr)
}

// scContext wraps a goscard.Context (SCardEstablishContext).
type scContext struct {
	ctx goscard.Context
}

func newSCContext() (*scContext, error) {
	if err := pcscInitialize(); err != nil {
		return nil, fmt.Errorf("initializing pcsc: %w", err)
	}
	ctx, ret, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if cerr := scCheck(ret, err); cerr != nil {
		return nil, cerr
	}
	return &scContext{ctx: ctx}, nil
}

func (c *scContext) Close() error {
	ret, err := c.ctx.Release()
	return scCheck(ret, err)
}

func (c *scContext) ListReaders() ([]string, error) {
	readers, ret, err := c.ctx.ListReaders(nil)
	// When no reader/card is present some PC/SC stacks return a "no readers
	// available" code rather than an empty list. Treat that as "no readers"
	// (nil, nil), matching the upstream Linux behavior, instead of an error.
	if ret == scardENoReadersAvailable || ret == scardEReaderUnavailable {
		return nil, nil
	}
	if cerr := scCheck(ret, err); cerr != nil {
		return nil, cerr
	}
	return readers, nil
}

// scContext-level SCARD_* codes we special-case in ListReaders.
const (
	scardENoReadersAvailable uint64 = 0x8010002E
	scardEReaderUnavailable  uint64 = 0x80100017
)

// scHandle wraps a connected goscard.Card (SCardConnect).
type scHandle struct {
	card goscard.Card
}

func (c *scContext) Connect(reader string) (*scHandle, error) {
	card, ret, err := c.ctx.Connect(reader, goscard.SCardShareExclusive, goscard.SCardProtocolT1)
	if cerr := scCheck(ret, err); cerr != nil {
		return nil, cerr
	}
	return &scHandle{card: card}, nil
}

func (h *scHandle) Close() error {
	ret, err := h.card.Disconnect(goscard.SCardLeaveCard)
	return scCheck(ret, err)
}

// scTx wraps an open PC/SC transaction. It holds the same goscard.Card the
// handle holds; BeginTransaction/EndTransaction bracket the exclusive access.
//
// transmitFn is a test-only seam: when non-nil it replaces the goscard-backed
// raw transmit, letting tests drive the full APDU framing (command chaining +
// GET RESPONSE looping in the vendored pcsc.go Transmit) against canned card
// responses with no hardware. Production code never sets it.
type scTx struct {
	card       goscard.Card
	transmitFn func(req []byte) (more bool, b []byte, err error)
}

func (h *scHandle) Begin() (*scTx, error) {
	ret, err := h.card.BeginTransaction()
	if cerr := scCheck(ret, err); cerr != nil {
		return nil, cerr
	}
	return &scTx{card: h.card}, nil
}

func (t *scTx) Close() error {
	ret, err := t.card.EndTransaction(goscard.SCardLeaveCard)
	return scCheck(ret, err)
}

// transmit is THE seam. It sends one raw APDU and parses the trailing Status
// Word, reproducing upstream pcsc_unix.go's (*scTx).transmit exactly:
//
//	SW1==0x90 && SW2==0x00 -> (more=false, data, nil)
//	SW1==0x61              -> (more=true,  data, nil)   (GET RESPONSE follows)
//	otherwise              -> (false, nil, &apduErr{sw1,sw2})
//
// goscard returns the FULL response INCLUDING the 2 SW bytes (it does NOT strip
// them) and auto-retries internally on SCARD_E_INSUFFICIENT_BUFFER, so we just
// peel the last two bytes here. ioSendPci must be the T1 PCI request goscard
// populated from the library's g_rgSCardT1Pci during Initialize.
func (t *scTx) transmit(req []byte) (more bool, b []byte, err error) {
	if t.transmitFn != nil {
		return t.transmitFn(req)
	}
	pci := goscard.SCardIoRequestT1
	resp, ret, terr := t.card.Transmit(&pci, req, nil)
	if cerr := scCheck(ret, terr); cerr != nil {
		return false, nil, fmt.Errorf("transmitting request: %w", cerr)
	}
	return parseTransmitResponse(resp)
}

// parseTransmitResponse splits a raw PC/SC response (which goscard returns WITH
// the trailing 2 Status-Word bytes) into (more, data, err), reproducing the
// upstream go-piv Status-Word contract byte for byte. It is factored out so it
// can be unit-tested without hardware — this is the logic most likely to be
// wrong about goscard's "response includes SW bytes" behavior.
func parseTransmitResponse(resp []byte) (more bool, b []byte, err error) {
	if len(resp) < 2 {
		return false, nil, fmt.Errorf("scard response too short: %d", len(resp))
	}
	sw1 := resp[len(resp)-2]
	sw2 := resp[len(resp)-1]
	if sw1 == 0x90 && sw2 == 0x00 {
		return false, resp[:len(resp)-2], nil
	}
	if sw1 == 0x61 {
		return true, resp[:len(resp)-2], nil
	}
	return false, nil, &apduErr{sw1, sw2}
}

// FindReaderName returns the first reader name that looks like a YubiKey. The
// PC/SC reader string is environment-dependent (e.g. "Yubico YubiKey
// OTP+FIDO+CCID"), so we match case-insensitively on the known vendor/product
// substrings.
func FindReaderName(readers []string) (string, bool) {
	for _, r := range readers {
		l := strings.ToLower(r)
		if strings.Contains(l, "yubikey") || strings.Contains(l, "yubico") {
			return r, true
		}
	}
	return "", false
}
