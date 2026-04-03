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

//go:build linux

package commandrun

import "testing"

const (
	status = `
Name:   blkcg_punt_bio
Umask:  0000
State:  I (idle)
Tgid:   214
Ngid:   0
Pid:    214
PPid:   2
TracerPid:      0
Uid:    0       0       0       0
Gid:    0       0       0       0
FDSize: 64
Groups:
NStgid: 214
NSpid:  214
NSpgid: 0
NSsid:  0
Threads:        1
SigQ:   0/514646
SigPnd: 0000000000000000
ShdPnd: 0000000000000000
SigBlk: 0000000000000000
SigIgn: ffffffffffffffff
SigCgt: 0000000000000000
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Seccomp:        0
Speculation_Store_Bypass:       thread vulnerable
Cpus_allowed:   ffffffff
Cpus_allowed_list:      0-31
Mems_allowed:   00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
Mems_allowed_list:      0
voluntary_ctxt_switches:        2
nonvoluntary_ctxt_switches:     0
	`
)

func Test_getPPIDFromStatus(t *testing.T) {
	byteStatus := []byte(status)

	ppid, err := getPPIDFromStatus(byteStatus)
	if err != nil {
		t.Errorf("getPPIDFromStatus() error = %v", err)
		return
	}

	if ppid != 2 {
		t.Errorf("getPPIDFromStatus() = %v, want %v", ppid, 2)
	}

}

func Test_getSpecBypassIsVulnFromStatus(t *testing.T) {
	byteStatus := []byte(status)

	isVuln := getSpecBypassIsVulnFromStatus(byteStatus)

	if isVuln != true {
		t.Errorf("getSpecBypassIsVulnFromStatus() = %v, want %v", isVuln, true)
	}

}

func Test_socketFamilyName(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{2, "AF_INET"},   // unix.AF_INET
		{10, "AF_INET6"}, // unix.AF_INET6
		{1, "AF_UNIX"},   // unix.AF_UNIX
		{16, "AF_NETLINK"},
		{99, "AF_99"},
	}
	for _, tt := range tests {
		got := socketFamilyName(tt.input)
		if got != tt.want {
			t.Errorf("socketFamilyName(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func Test_socketTypeName(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{1, "SOCK_STREAM"},
		{2, "SOCK_DGRAM"},
		{3, "SOCK_RAW"},
		// SOCK_STREAM | SOCK_NONBLOCK (0x800)
		{1 | 0x800, "SOCK_STREAM"},
		// SOCK_DGRAM | SOCK_CLOEXEC (0x80000)
		{2 | 0x80000, "SOCK_DGRAM"},
		{99, "SOCK_3"}, // 99 & 0xf = 3 = SOCK_RAW
	}
	for _, tt := range tests {
		got := socketTypeName(tt.input)
		if got != tt.want {
			t.Errorf("socketTypeName(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func Test_ensureNetwork(t *testing.T) {
	pctx := &ptraceContext{
		processes: make(map[int]*ProcessInfo),
	}
	procInfo := pctx.getProcInfo(1)

	if procInfo.Network != nil {
		t.Error("Network should be nil initially")
	}

	pctx.ensureNetwork(procInfo)
	if procInfo.Network == nil {
		t.Error("Network should not be nil after ensureNetwork")
	}

	// Calling again should not replace the existing struct
	procInfo.Network.Sockets = append(procInfo.Network.Sockets, SocketInfo{Family: "AF_INET"})
	pctx.ensureNetwork(procInfo)
	if len(procInfo.Network.Sockets) != 1 {
		t.Error("ensureNetwork should not reset existing NetworkActivity")
	}
}
