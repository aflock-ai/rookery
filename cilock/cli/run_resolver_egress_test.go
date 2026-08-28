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
	"testing"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// Name resolution is a remote channel, not noise: the names a build queries
// leave the machine, and the answers come back as inputs the build acts on —
// a build can consume attacker-controlled DNS data through getaddrinfo alone,
// with no other socket. On macOS that channel surfaces as an AF_UNIX connect
// to the system resolver daemon (mDNSResponder), so skipping every
// non-container UNIX socket signed such builds hermetic. The resolver socket
// must count as egress, labelled so the reader sees what the channel was.
func TestSystemResolverSocketCountsAsEgress(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/private/var/run/mDNSResponder", // as the darwin sandbox report names it
		"/var/run/mDNSResponder",         // the unresolved-symlink spelling
	} {
		c := commandrun.NetworkConnection{
			Syscall: "connect",
			Family:  commandrun.FamilyUnix,
			Address: path,
			FD:      commandrun.FDNotObservable,
		}
		endpoint, counts := egressEndpoint(c)
		if !counts {
			t.Errorf("a connect to the system resolver socket %q was not counted as egress; "+
				"name resolution moves data both ways, so a resolving build must not be signed hermetic", path)
			continue
		}
		if endpoint != "unix:"+path {
			t.Errorf("egressEndpoint(%q) = %q, want %q so the signed summary names the channel", path, endpoint, "unix:"+path)
		}
	}
}

// Ordinary AF_UNIX IPC stays uncounted — the resolver rule must not widen
// into counting every local socket, which would make hermeticity unreachable
// without improving honesty.
func TestOrdinaryUnixSocketStillDoesNotCount(t *testing.T) {
	t.Parallel()
	c := commandrun.NetworkConnection{
		Syscall: "connect",
		Family:  commandrun.FamilyUnix,
		Address: "/var/run/syslog",
		FD:      commandrun.FDNotObservable,
	}
	// No path is exempt any more — the OS's own logging socket counts too,
	// because the channel names a path and cannot identify the peer.
	if endpoint, counts := egressEndpoint(c); !counts || endpoint != "unix:/var/run/syslog" {
		t.Errorf("egressEndpoint(%q) = %q counts=%v, want unix:%s", c.Address, endpoint, counts, c.Address)
	}
}
