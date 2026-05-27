// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package ebpf

// EXPERIMENT — easily deletable. Delete this whole file and the two
// resizeRingbufFromEnv() calls in openat_consumer.go to revert to the
// compiled-in ringbuf sizes.
//
// The BPF object hardcodes oversized ringbufs (events = 256 MiB,
// read_tap_events = 1 GiB). Those fail to allocate on memory-constrained
// hosts (small CI runners, the local colima VM) and — per the ringbuf
// research — only paper over an event-VOLUME problem rather than fixing
// it. These knobs let an ablation sweep buffer sizes at LOAD time via the
// CollectionSpec, with NO BPF recompile, so we can measure drops vs size
// empirically and pick a sane default before committing one in the .bpf.c.

import (
	"fmt"
	"math/bits"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
)

// resizeRingbufFromEnv overrides a ringbuf map's byte size from env when
// set. No-op when the var is unset (keeps the compiled-in size). The
// kernel requires a ringbuf's size to be a power of two AND a multiple of
// the page size; we round the requested value DOWN to the nearest power of
// two (>= 4 KiB) and warn if we had to adjust. Unparseable/zero values are
// ignored with a warning — the fail-safe is the compiled-in size.
func resizeRingbufFromEnv(spec *ebpf.CollectionSpec, mapName, envVar string) {
	v := os.Getenv(envVar)
	if v == "" {
		return
	}
	m, ok := spec.Maps[mapName]
	if !ok {
		fmt.Fprintf(os.Stderr, "cilock-ebpf: %s set but map %q not in spec; ignoring\n", envVar, mapName)
		return
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n < 4096 {
		fmt.Fprintf(os.Stderr,
			"cilock-ebpf: ignoring invalid %s=%q (want bytes >= 4096); keeping %d\n",
			envVar, v, m.MaxEntries)
		return
	}
	size := uint32(n)
	if bits.OnesCount64(n) != 1 {
		// Round down to nearest power of two.
		size = uint32(1) << (bits.Len64(n) - 1)
		fmt.Fprintf(os.Stderr,
			"cilock-ebpf: %s=%d not a power of two; rounding down to %d bytes for %q\n",
			envVar, n, size, mapName)
	}
	m.MaxEntries = size
	fmt.Fprintf(os.Stderr, "cilock-ebpf: ringbuf %q resized to %d bytes via %s\n", mapName, size, envVar)
}
