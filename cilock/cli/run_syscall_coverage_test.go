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

package cli

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// accept4 is the same channel as accept, and matching only one spelling is a
// spelling bug with the consequence of a security hole: the other falls
// through as "not connect" and an inbound input channel produces a no-egress
// summary. The kernel has more than one accept entry point and backends
// differ about which name they report.
func TestAcceptSpellingsAreTheSameChannel(t *testing.T) {
	t.Parallel()
	mk := func(call string) commandrun.NetworkConnection {
		return commandrun.NetworkConnection{
			Syscall: call, Family: commandrun.FamilyInetUnspecified,
			Address: commandrun.HostNotObservable, Port: 8080,
		}
	}
	a, okA := egressEndpoint(mk("accept"))
	b, okB := egressEndpoint(mk("accept4"))
	if !okA || !okB {
		t.Fatalf("an accepted inbound connection did not count: accept=%v accept4=%v", okA, okB)
	}
	if a != b {
		t.Errorf("accept and accept4 produced different labels (%q vs %q) — the same channel must waive identically", a, b)
	}
	if !strings.HasPrefix(a, "inbound:") {
		t.Errorf("label = %q, want an inbound: label", a)
	}
}

// AN OPERATION THIS CONSUMER DOES NOT KNOW MUST NOT VANISH. Dropping
// everything that is merely not "connect" is the same fail-open this file
// already rejects for socket families: the linux backend's opName returns
// "unknown" for an op it cannot name, and a vanished operation reads
// downstream as "there was nothing there".
func TestUnrecognisedSyscallIsCountedNotDropped(t *testing.T) {
	t.Parallel()
	for _, call := range []string{"unknown", "recvfrom", "sendmsg", ""} {
		ep, counts := egressEndpoint(commandrun.NetworkConnection{
			Syscall: call, Family: commandrun.FamilyIPv4, Address: "203.0.113.7", Port: 443,
		})
		if !counts {
			t.Errorf("syscall %q was DROPPED; an operation nobody classified must be counted, not silently absent", call)
			continue
		}
		if !strings.Contains(ep, "unclassified-syscall") {
			t.Errorf("syscall %q gave label %q, want it to say plainly that it was not understood", call, ep)
		}
	}
}

// Serving is still not fetching, and these are the ONLY operations dropped by
// name — so the drop list stays a short, deliberate allowlist rather than
// "everything we failed to think about".
func TestServingSyscallsAreStillNotEgress(t *testing.T) {
	t.Parallel()
	for _, call := range []string{"bind", "listen"} {
		if ep, counts := egressEndpoint(commandrun.NetworkConnection{
			Syscall: call, Family: commandrun.FamilyIPv4, Address: "0.0.0.0", Port: 8080,
		}); counts {
			t.Errorf("%s counted as egress (%q); serving is not fetching", call, ep)
		}
	}
}
