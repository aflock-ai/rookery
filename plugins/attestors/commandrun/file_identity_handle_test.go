// jade:ring local
// Copyright 2021 The Witness Contributors
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

package commandrun

import (
	"testing"
	"time"
)

// 2026-10-02T00:00:00Z as a Windows FILETIME (100ns ticks since 1601).
var testChangeTime = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).UnixNano()/100 + windowsEpochToUnix

func idBytes(lo, hi byte) (b [16]byte) {
	b[0], b[8] = lo, hi
	return b
}

// The identity is the volume, the whole 128-bit file id and the ChangeTime.
// Every one of them must move the comparison: a field that is read but never
// compared is a hole (issue #10571).
func TestWindowsIdentityIsFileIdNotPath(t *testing.T) {
	base, ok := windowsFileIdentity(7, idBytes(1, 0), testChangeTime, 100)
	if !ok {
		t.Fatal("a complete handle identity must be comparable")
	}
	same, _ := windowsFileIdentity(7, idBytes(1, 0), testChangeTime, 100)
	if same != base {
		t.Fatal("identical handle facts must compare equal")
	}
	for name, mutate := range map[string]func() (fileIdentity, bool){
		"volume":       func() (fileIdentity, bool) { return windowsFileIdentity(8, idBytes(1, 0), testChangeTime, 100) },
		"file id low":  func() (fileIdentity, bool) { return windowsFileIdentity(7, idBytes(2, 0), testChangeTime, 100) },
		"file id high": func() (fileIdentity, bool) { return windowsFileIdentity(7, idBytes(1, 1), testChangeTime, 100) },
		"change time":  func() (fileIdentity, bool) { return windowsFileIdentity(7, idBytes(1, 0), testChangeTime+1, 100) },
		"size":         func() (fileIdentity, bool) { return windowsFileIdentity(7, idBytes(1, 0), testChangeTime, 101) },
	} {
		got, ok := mutate()
		if !ok {
			t.Fatalf("%s: a complete identity became incomparable", name)
		}
		if got == base {
			t.Errorf("%s moved but the identities compare equal", name)
		}
	}
}

// An absent ChangeTime or an all-zero file id is "not reported", never
// "reported and unchanged": the bracket must refuse, not compare zeros.
func TestWindowsIdentityRefusesWhatTheHandleDidNotReport(t *testing.T) {
	for name, c := range map[string]struct {
		id     [16]byte
		change int64
	}{
		"no change time": {idBytes(1, 0), 0},
		"negative":       {idBytes(1, 0), -5},
		"zero file id":   {idBytes(0, 0), testChangeTime},
	} {
		if _, ok := windowsFileIdentity(7, c.id, c.change, 1); ok {
			t.Errorf("%s: yielded an identity", name)
		}
	}
}

// ChangeTime keeps its 100ns resolution, which is what lets the bracket see a
// change a coarser clock would round away.
func TestWindowsIdentityKeepsSubSecondResolution(t *testing.T) {
	a, _ := windowsFileIdentity(1, idBytes(1, 0), testChangeTime, 1)
	if a.ctimeSec != time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC).Unix() || a.ctimeNsec != 0 {
		t.Fatalf("epoch conversion wrong: %d.%09d", a.ctimeSec, a.ctimeNsec)
	}
	b, _ := windowsFileIdentity(1, idBytes(1, 0), testChangeTime+3, 1)
	if b.ctimeNsec != 300 {
		t.Fatalf("three ticks must be 300ns, got %d", b.ctimeNsec)
	}
}
