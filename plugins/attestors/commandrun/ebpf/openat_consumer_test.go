// Copyright 2026 The Rookery Contributors
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

//go:build linux

package ebpf

import (
	"testing"
)

func TestUnameKernelVersionCode_LiveSystem(t *testing.T) {
	// Sanity: on a real Linux host the call should succeed and
	// produce a sensible value (> 0, with major version between 4 and 10).
	v, err := unameKernelVersionCode()
	if err != nil {
		t.Fatalf("unameKernelVersionCode on live system: %v", err)
	}
	major := (v >> 16) & 0xFFFF
	if major < 4 || major > 10 {
		t.Errorf("unexpected major version %d from encoded %#x", major, v)
	}
	// And it must NOT be the cilium/ebpf magic value, otherwise the
	// /proc/self/mem fallback would still trigger.
	const magic = 0xFFFFFFFE
	if v == magic {
		t.Errorf("uname-derived version equals MagicKernelVersion (%#x) — would trigger /proc/self/mem fallback", magic)
	}
	if v == 0 {
		t.Errorf("uname-derived version is 0 — would trigger /proc/self/mem fallback")
	}
}
