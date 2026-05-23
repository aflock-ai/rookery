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

// Package ebpf is cilock's eBPF-based tracing capture path (#167).
//
// V1: kprobe on openat-family syscalls + ring buffer of (pid, path,
// stat_at_open) events. Userspace re-stats the path on consumption
// and classifies the hash as TOCTOU-stable or TOCTOU-suspect based
// on whether stat changed between BPF-capture and userspace-stat.
//
// Requires: CAP_BPF + CAP_PERFMON (Linux 5.8+). The selector in
// trace_mode_linux.go gates entry to this path on availability.

package ebpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	// Must match the C struct openat_event layout exactly. Sizes:
	//   u64 timestamp_ns       (8 bytes, offset 0)
	//   u32 pid                (4, 8)
	//   u32 tgid               (4, 12)
	//   u32 ppid               (4, 16)
	//   s32 dirfd              (4, 20)
	//   u32 path_len           (4, 24)
	//   u32 _pad               (4, 28 — alignment)
	//   u64 size_at_open       (8, 32)
	//   u64 mtime_ns           (8, 40)
	//   char comm[16]          (16, 48)
	//   char path[4096]        (4096, 64)
	// Total: 4160 bytes
	openatEventSize = 4160
	maxPath         = 4096
	taskCommLen     = 16
)

// OpenatEvent is the Go-side decoding of the BPF openat event.
type OpenatEvent struct {
	TimestampNs uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
	Dirfd       int32
	PathLen     uint32
	SizeAtOpen  uint64
	MtimeNs     uint64
	Comm        string
	Path        string
}

//go:embed bpf/openat_kprobe.bpf.o
var bpfObjBytes []byte

// Consumer owns a loaded BPF program + attached kprobe + ringbuf reader.
type Consumer struct {
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
}

// Open loads the embedded BPF object, attaches kprobes for the
// current architecture's openat-family syscalls, and prepares a
// ringbuf reader. Caller must call Close() when done.
func Open() (*Consumer, error) {
	// Without this the BPF program loader fails with "Operation not
	// permitted" even when CAP_BPF is granted — the memlock rlimit
	// defaults to a tiny value on most distros.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObjBytes))
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("instantiate BPF: %w", err)
	}

	c := &Consumer{coll: coll}

	// Pick the right kprobe symbols for this arch.
	progNames, kprobeSyms := archKprobeNames()
	for i, progName := range progNames {
		prog, ok := coll.Programs[progName]
		if !ok {
			// Program not in this build (e.g., compiled for different arch).
			continue
		}
		l, err := link.Kprobe(kprobeSyms[i], prog, nil)
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("attach %s -> %s: %w", kprobeSyms[i], progName, err)
		}
		c.links = append(c.links, l)
	}
	if len(c.links) == 0 {
		_ = c.Close()
		return nil, fmt.Errorf("no kprobes attached for arch=%s", runtime.GOARCH)
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("events map not found in BPF object")
	}
	r, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	c.reader = r
	return c, nil
}

// archKprobeNames returns (BPF program names, kernel symbols) to
// attach on the current architecture. Program names match the SEC()
// labels in openat_kprobe.bpf.c.
func archKprobeNames() ([]string, []string) {
	switch runtime.GOARCH {
	case "amd64":
		return []string{"kprobe_openat_x64", "kprobe_openat2_x64"},
			[]string{"__x64_sys_openat", "__x64_sys_openat2"}
	case "arm64":
		return []string{"kprobe_openat_arm64", "kprobe_openat2_arm64"},
			[]string{"__arm64_sys_openat", "__arm64_sys_openat2"}
	default:
		return nil, nil
	}
}

// Read blocks until the next event is available, then decodes and
// returns it. Returns io.EOF-equivalent when the consumer is closed.
func (c *Consumer) Read() (*OpenatEvent, error) {
	rec, err := c.reader.Read()
	if err != nil {
		return nil, err
	}
	return decodeOpenatEvent(rec.RawSample)
}

// Close detaches kprobes and frees BPF resources. Safe to call
// multiple times.
func (c *Consumer) Close() error {
	if c == nil {
		return nil
	}
	for _, l := range c.links {
		_ = l.Close()
	}
	c.links = nil
	if c.reader != nil {
		_ = c.reader.Close()
		c.reader = nil
	}
	if c.coll != nil {
		c.coll.Close()
		c.coll = nil
	}
	return nil
}

// decodeOpenatEvent parses the raw ring-buffer bytes per the layout
// documented in openat_kprobe.bpf.c.
func decodeOpenatEvent(raw []byte) (*OpenatEvent, error) {
	if len(raw) < openatEventSize {
		return nil, fmt.Errorf("event too short: %d < %d", len(raw), openatEventSize)
	}
	ev := &OpenatEvent{
		TimestampNs: binary.LittleEndian.Uint64(raw[0:]),
		PID:         binary.LittleEndian.Uint32(raw[8:]),
		TGID:        binary.LittleEndian.Uint32(raw[12:]),
		PPID:        binary.LittleEndian.Uint32(raw[16:]),
		Dirfd:       int32(binary.LittleEndian.Uint32(raw[20:])),
		PathLen:     binary.LittleEndian.Uint32(raw[24:]),
		// 28: 4 bytes alignment padding
		SizeAtOpen: binary.LittleEndian.Uint64(raw[32:]),
		MtimeNs:    binary.LittleEndian.Uint64(raw[40:]),
		Comm:       cstring(raw[48 : 48+taskCommLen]),
		Path:       cstring(raw[64 : 64+maxPath]),
	}
	return ev, nil
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
