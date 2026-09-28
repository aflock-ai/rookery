// jade:ring local
// Copyright 2026 TestifySec, Inc.
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

package archivista

import (
	"net/http"
	"testing"
	"time"
)

// The per-attempt deadline was a package constant with no way to override it.
// A 5.27 MiB envelope that cannot transfer inside it failed SEVEN consecutive
// attempts at 120.001s–120.003s each — 2ms of variance across 14m24s — and
// every knob that looked like it should help (more retries, a bigger retry
// budget) bounds a different quantity. These tests pin the override and, just
// as importantly, the case where it must refuse to act.

func TestWithTimeout_OverridesThePerAttemptDeadline(t *testing.T) {
	c := New("https://archivista.example", WithTimeout(9*time.Minute))
	if got := c.client.Timeout; got != 9*time.Minute {
		t.Fatalf("per-attempt deadline = %v, want 9m", got)
	}
}

func TestWithTimeout_DefaultIsUnchanged(t *testing.T) {
	c := New("https://archivista.example")
	if got := c.client.Timeout; got != defaultHTTPTimeout {
		t.Fatalf("default deadline = %v, want %v — raising it for everyone is a separate decision", got, defaultHTTPTimeout)
	}
}

// A non-positive duration must NOT install an unbounded client. Zero is how the
// cilock flag spells "leave the default alone", and a negative value is an
// operator slip; either one silently removing the deadline would reintroduce
// the hang defaultHTTPTimeout exists to prevent — in CI, a 20-minute job
// timeout with no error at all.
func TestWithTimeout_NonPositiveKeepsTheDefault(t *testing.T) {
	for _, d := range []time.Duration{0, -1 * time.Second} {
		c := New("https://archivista.example", WithTimeout(d))
		if got := c.client.Timeout; got != defaultHTTPTimeout {
			t.Fatalf("WithTimeout(%v) left deadline %v, want the default %v", d, got, defaultHTTPTimeout)
		}
	}
}

// Option order is caller-visible: WithTimeout mutates whatever client is
// installed when it runs, and WithHTTPClient replaces that pointer. Pinning
// both directions documents which spelling an integrator must use — and the
// cilock run path appends WithTimeout last for exactly this reason.
func TestWithTimeout_OrderRelativeToWithHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 30 * time.Second}

	after := New("https://archivista.example", WithHTTPClient(custom), WithTimeout(7*time.Minute))
	if got := after.client.Timeout; got != 7*time.Minute {
		t.Fatalf("timeout applied after the custom client = %v, want 7m", got)
	}

	// The reverse order sets the deadline on a client that is then discarded.
	replaced := &http.Client{Timeout: 30 * time.Second}
	before := New("https://archivista.example", WithTimeout(7*time.Minute), WithHTTPClient(replaced))
	if got := before.client.Timeout; got != 30*time.Second {
		t.Fatalf("custom client applied last = %v, want its own 30s — if this changed, the ordering note in run.go is wrong", got)
	}
}
