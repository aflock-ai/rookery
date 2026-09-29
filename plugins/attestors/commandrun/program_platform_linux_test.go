// jade:ring local
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

package commandrun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// capV2NetRaw is a security.capability value (VFS_CAP_REVISION_2, effective)
// granting CAP_NET_RAW: what `setcap cap_net_raw+ep` writes.
var capV2NetRaw = []byte{
	0x01, 0x00, 0x00, 0x02, // magic_etc: revision 2 | VFS_CAP_FLAGS_EFFECTIVE
	0x00, 0x20, 0x00, 0x00, // permitted[0]: bit 13, CAP_NET_RAW
	0x00, 0x00, 0x00, 0x00, // inheritable[0]
	0x00, 0x00, 0x00, 0x00, // permitted[1]
	0x00, 0x00, 0x00, 0x00, // inheritable[1]
}

// TestCapabilityReadWithoutProcIsNotReportedAbsent: a program that carries a
// file capability and no setuid or setgid bit, measured where /proc is not
// available. The bytes are still hashed through the open descriptor, so the
// capability must be read through that same descriptor; a lookup through
// /proc/self/fd fails with ENOENT there, and an ignored ENOENT would sign
// "setId": false for a program that gains privilege when it runs.
func TestCapabilityReadWithoutProcIsNotReportedAbsent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("precondition: root, to write security.capability and to hide /proc in a private mount namespace")
	}
	prog := filepath.Join(t.TempDir(), "capped")
	writeProgramScript(t, prog, programTestScript)
	if err := unix.Setxattr(prog, "security.capability", capV2NetRaw, 0); err != nil {
		t.Skipf("precondition: this file system cannot carry a file capability: %v", err)
	}

	type result struct {
		file    []byte
		skip    string
		failure string
	}
	done := make(chan result, 1)
	go func() {
		// The goroutine keeps its thread locked and never unlocks it, so the
		// private mount namespace dies with the thread instead of leaking
		// into the rest of the test binary.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			done <- result{skip: "cannot unshare the mount namespace: " + err.Error()}
			return
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			done <- result{skip: "cannot make the mounts private: " + err.Error()}
			return
		}
		if err := unix.Mount("tmpfs", "/proc", "tmpfs", 0, ""); err != nil {
			done <- result{skip: "cannot hide /proc: " + err.Error()}
			return
		}
		if _, err := os.Readlink("/proc/self/fd/0"); err == nil {
			done <- result{failure: "precondition: /proc/self/fd still answers after /proc was hidden"}
			return
		}
		m := measureProgramFile(prog, programHashes(nil))
		if m.digest == nil {
			done <- result{failure: "precondition: the program was not hashed (" + m.unresolved + ")"}
			return
		}
		raw, err := json.Marshal(m.file)
		if err != nil {
			done <- result{failure: err.Error()}
			return
		}
		done <- result{file: raw}
	}()
	r := <-done
	if r.skip != "" {
		t.Skip("precondition: " + r.skip)
	}
	if r.failure != "" {
		t.Fatal(r.failure)
	}
	if !strings.Contains(string(r.file), `"setId":true`) {
		t.Fatalf("file = %s: a program carrying a file capability, hashed through an open descriptor, must record setId true", r.file)
	}
}

// TestCapabilityLookupErrorIsUnknown: only an answer that establishes absence
// may record setId false. ENODATA (no such attribute) and EOPNOTSUPP (a file
// system that cannot carry one, which is also what the kernel's own exec-time
// lookup sees) establish it; every other error means the attribute could not
// be read, and setId is then null with the reason.
func TestCapabilityLookupErrorIsUnknown(t *testing.T) {
	prog := filepath.Join(t.TempDir(), "tool")
	writeProgramScript(t, prog, programTestScript)
	f, err := os.Open(prog) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fgetxattr = unix.Fgetxattr; getxattr = unix.Getxattr })

	cases := []struct {
		name     string
		fdErr    error
		procErr  error
		want     string
		noReason bool
	}{
		{name: "the attribute exists", fdErr: nil, want: "true", noReason: true},
		{name: "ENODATA: no attribute", fdErr: unix.ENODATA, want: "false", noReason: true},
		{name: "EOPNOTSUPP: the file system carries none", fdErr: unix.EOPNOTSUPP, want: "false", noReason: true},
		{name: "ENOENT", fdErr: unix.ENOENT, want: "null"},
		{name: "EIO", fdErr: unix.EIO, want: "null"},
		{name: "EACCES from a security module", fdErr: unix.EACCES, want: "null"},
		{name: "EOVERFLOW: a capability owned outside this user namespace", fdErr: unix.EOVERFLOW, want: "null"},
		{name: "ERANGE", fdErr: unix.ERANGE, want: "null"},
		{name: "EBADF (O_PATH), then /proc answers ENODATA", fdErr: unix.EBADF, procErr: unix.ENODATA, want: "false", noReason: true},
		{name: "EBADF (O_PATH), then no /proc", fdErr: unix.EBADF, procErr: unix.ENOENT, want: "null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fgetxattr = func(int, string, []byte) (int, error) {
				if tc.fdErr != nil {
					return 0, tc.fdErr
				}
				return len(capV2NetRaw), nil
			}
			getxattr = func(string, string, []byte) (int, error) {
				if tc.procErr != nil {
					return 0, tc.procErr
				}
				return len(capV2NetRaw), nil
			}
			pf := programFileFacts(f, fi)
			raw, err := json.Marshal(pf)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), `"setId":`+tc.want) {
				t.Fatalf("file = %s, want setId %s", raw, tc.want)
			}
			if tc.noReason && pf.SetIDReason != "" {
				t.Fatalf("setIdReason = %q on an established answer", pf.SetIDReason)
			}
			if !tc.noReason && pf.SetIDReason == "" {
				t.Fatal("setId is unknown with no reason")
			}
		})
	}

	t.Run("a setuid bit is established whatever the attribute lookup says", func(t *testing.T) {
		if err := os.Chmod(prog, os.ModeSetuid|0o755); err != nil { //nolint:gosec // the point is a setuid fixture
			t.Fatal(err)
		}
		sfi, err := os.Stat(prog)
		if err != nil {
			t.Fatal(err)
		}
		if sfi.Mode()&os.ModeSetuid == 0 {
			t.Fatal("precondition: the fixture has no setuid bit")
		}
		fgetxattr = func(int, string, []byte) (int, error) { return 0, unix.EIO }
		if pf := programFileFacts(f, sfi); pf.SetID == nil || !*pf.SetID {
			t.Fatalf("setId = %v, want true from the mode bits", pf.SetID)
		}
	})

	t.Run("no descriptor: the capability cannot be read, so setId is unknown", func(t *testing.T) {
		fgetxattr = func(int, string, []byte) (int, error) { return 0, unix.ENODATA }
		pf := programFileFacts(nil, fi)
		if pf.SetID != nil || pf.SetIDReason == "" {
			t.Fatalf("setId = %v, setIdReason = %q: with no descriptor absence is not established", pf.SetID, pf.SetIDReason)
		}
	})
}
