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

// probe-ebpf: standalone tool that attaches the openat-kprobe BPF
// program and prints the first N captured events. Used during
// development to verify the BPF program loads + attaches + emits
// events as expected. Run with sudo (needs CAP_BPF + CAP_PERFMON).
//
//   sudo probe-ebpf [-n 10]
//
// Expected: opens any file from another shell, see the path appear
// in the output.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/ebpf"
)

func main() {
	n := flag.Int("n", 0, "exit after N events (0 = run until SIGINT)")
	flag.Parse()

	c, err := ebpf.Open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	fmt.Fprintln(os.Stderr, "probe-ebpf: attached. Tracing openat-class syscalls. ^C to exit.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = c.Close()
		os.Exit(0)
	}()

	count := 0
	for {
		ev, err := c.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[%d] pid=%d tgid=%d ppid=%d comm=%-16s dirfd=%-5d size=%-8d mtime_ns=%-20d path=%s\n",
			ev.TimestampNs, ev.PID, ev.TGID, ev.PPID, ev.Comm, ev.Dirfd, ev.SizeAtOpen, ev.MtimeNs, ev.Path)
		count++
		if *n > 0 && count >= *n {
			return
		}
	}
}
