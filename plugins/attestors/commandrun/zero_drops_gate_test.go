// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package commandrun

import (
	"errors"
	"strings"
	"testing"
)

func TestZeroDropsGate_NilSummary(t *testing.T) {
	r := &CommandRun{}
	if err := r.zeroDropsGate(); err != nil {
		t.Fatalf("nil summary should pass gate, got %v", err)
	}
}

func TestZeroDropsGate_AllZero(t *testing.T) {
	r := &CommandRun{
		Summary: &TraceSummary{},
	}
	if err := r.zeroDropsGate(); err != nil {
		t.Fatalf("all-zero diagnostics should pass gate, got %v", err)
	}
}

func TestZeroDropsGate_PartialReadFallbacksDontFail(t *testing.T) {
	// PartialReadFallbacks are CORRECT behavior (digest comes from
	// path-hash at openat time). They shouldn't fail the gate.
	r := &CommandRun{
		Summary: &TraceSummary{
			Diagnostics: TraceDiagnostics{
				PartialReadFallbacks: 50,
			},
		},
	}
	if err := r.zeroDropsGate(); err != nil {
		t.Errorf("partial-read-fallbacks should NOT fail gate, got %v", err)
	}
}

func TestZeroDropsGate_RingbufDropFails(t *testing.T) {
	r := &CommandRun{
		Summary: &TraceSummary{
			Diagnostics: TraceDiagnostics{
				RingbufReadTapDrops: 7,
			},
		},
	}
	err := r.zeroDropsGate()
	if err == nil {
		t.Fatalf("ringbuf drops should fail gate")
	}
	var zde *ZeroDropsError
	if !errors.As(err, &zde) {
		t.Fatalf("expected ZeroDropsError, got %T: %v", err, err)
	}
	if zde.RingbufReadTapDrops != 7 {
		t.Errorf("expected 7 readtap drops, got %d", zde.RingbufReadTapDrops)
	}
	msg := err.Error()
	if !strings.Contains(msg, "bpf-readtap-drops=7") {
		t.Errorf("error message should mention drop count; got %q", msg)
	}
}

func TestZeroDropsGate_FanotifyTimeoutFails(t *testing.T) {
	r := &CommandRun{
		Summary: &TraceSummary{
			Diagnostics: TraceDiagnostics{
				FanotifyTimeouts: 1,
			},
		},
	}
	err := r.zeroDropsGate()
	if err == nil {
		t.Fatalf("fanotify timeout should fail gate")
	}
	var zde *ZeroDropsError
	if !errors.As(err, &zde) {
		t.Fatalf("expected ZeroDropsError, got %T", err)
	}
	if zde.FanotifyTimeouts != 1 {
		t.Errorf("expected 1 fanotify timeout, got %d", zde.FanotifyTimeouts)
	}
}

func TestZeroDropsGate_AllCountersAggregated(t *testing.T) {
	r := &CommandRun{
		Summary: &TraceSummary{
			Diagnostics: TraceDiagnostics{
				RingbufOpenatDrops:   1,
				RingbufReadTapDrops:  2,
				FanotifyTimeouts:     3,
				UnhashedOpensTotal:   4,
				FallbackHashFailures: 5,
				FsVeritySealFailures: 6,
			},
		},
	}
	err := r.zeroDropsGate()
	if err == nil {
		t.Fatalf("any non-zero counter should fail gate")
	}
	msg := err.Error()
	for _, want := range []string{
		"bpf-openat-drops=1", "bpf-readtap-drops=2", "fanotify-timeouts=3",
		"unhashed-opens=4", "fallback-hash-failures=5", "fsverity-failures=6",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q; full=%q", want, msg)
		}
	}
}
