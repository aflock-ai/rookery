// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package commandrun

import (
	"context"
	"crypto"
	"encoding/hex"
	"os"
	"sync"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun/fanotify"
)

// EnvVarFanotify selects the fanotify integrity gate. Values:
//   - "" (unset): DEFAULT — same as "auto" (enable if available).
//     fanotify is the authoritative, synchronous content-hash source
//     that closes the eBPF write-tap gap on kernels where the CO-RE
//     object (or its host-rebuilt variant) mis-hashes writes — e.g.
//     GitHub's Azure 6.17 runner, where the eBPF tap silently dropped
//     every product digest and shipped an empty product tree. Defaulting
//     it ON means correct product capture out of the box.
//   - "auto": enable if Probe succeeds; otherwise fall back silently
//   - "1" / "on": REQUIRE fanotify; error if Probe fails
//   - "0" / "off" / "off-explicit": explicitly disable (BPF-only)
const EnvVarFanotify = "CILOCK_FANOTIFY"

// fanotifySession bundles the running Handler and its goroutine so
// the trace path can stop + harvest digests cleanly at end-of-trace.
type fanotifySession struct {
	h      *fanotify.Handler
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// maybeStartFanotify decides whether to enable the fanotify integrity
// gate, probes capability, and starts the handler goroutine. Returns
// (session, nil) on success, (nil, nil) when disabled or unavailable
// in auto mode, or (nil, error) when explicitly required but
// unavailable.
//
// The probe + activate sequence costs a few syscalls and is safe to
// call regardless of trace mode; we just gate on the env var.
func maybeStartFanotify(workingDir string) (*fanotifySession, error) {
	mode := os.Getenv(EnvVarFanotify)
	switch mode {
	case "0", "off", "off-explicit":
		// Explicit opt-out — operator chose BPF-only.
		return nil, nil
	case "", "auto", "1", "on":
		// Unset now defaults to auto (enable-if-available). "1"/"on"
		// additionally REQUIRE it (see `required` below).
		// continue
	default:
		// Unknown value — treat as disabled but log so operators can
		// notice typos.
		log.Debugf("(fanotify) unknown %s=%q; disabled", EnvVarFanotify, mode)
		return nil, nil
	}

	if workingDir == "" {
		workingDir = "."
	}
	required := mode == "1" || mode == "on"

	if err := fanotify.Probe(workingDir); err != nil {
		if required {
			return nil, &fanotifyUnavailableError{cause: err}
		}
		log.Debugf("(fanotify) probe failed (auto-mode, falling back to BPF): %v", err)
		return nil, nil
	}

	h, err := fanotify.New(workingDir)
	if err != nil {
		if required {
			return nil, &fanotifyUnavailableError{cause: err}
		}
		log.Debugf("(fanotify) New failed (auto-mode, falling back): %v", err)
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &fanotifySession{h: h, cancel: cancel}
	s.wg.Add(1)
	ready := make(chan struct{})
	go func() {
		defer s.wg.Done()
		close(ready) // signal we entered the goroutine
		if err := h.Run(ctx); err != nil {
			log.Debugf("(fanotify) Run returned: %v", err)
		}
	}()
	// Wait for the handler goroutine to actually start polling.
	// Without this, the kernel mark IS armed (set in fanotify.New)
	// but events queue in the kernel buffer until userspace polls.
	// Under cold-start burst workloads we'd see the queue overflow
	// before the goroutine drained the first event. A short settling
	// period gives the goroutine its first poll cycle before c.Start()
	// races to fork the tracee.
	<-ready
	time.Sleep(50 * time.Millisecond)
	log.Debugf("(fanotify) integrity gate active on %s", workingDir)
	return s, nil
}

// stop drains the handler and harvests its digests. Safe to call on
// nil session (the typical disabled case).
func (s *fanotifySession) stop() (map[string][32]byte, fanotify.Stats) {
	if s == nil {
		return nil, fanotify.Stats{}
	}
	s.cancel()
	digests := s.h.Digests()
	stats := s.h.GetStats()
	_ = s.h.Close()
	s.wg.Wait()
	return digests, stats
}

// mergeFanotifyDigests folds fanotify-captured (path → SHA-256) into
// every process's OpenedFiles map. Fanotify digests are authoritative
// (kernel-synchronous, race-free) so they OVERWRITE any prior digest
// for the same path. Returns:
//   - touched: count of OpenedFiles entries upgraded
//   - fanotifyOnly: paths fanotify hashed that NO process recorded
//     an open for. These represent BPF-missed opens (dropped event,
//     fast-exiting process, watched-set miss) but the kernel-rooted
//     digest is still authoritative. The caller surfaces these as
//     Summary.FanotifyOnlyDigests so no observed open is silently lost.
//
// The model: fanotify digests are GLOBAL (whole-mount), not per-pid;
// but ProcessInfo.OpenedFiles is per-pid. We fold the same fanotify
// digest into every process that recorded an open for the path,
// providing per-pid attribution alongside the kernel-rooted digest.
// writeOpenClaimed (3rd return) is the set of paths whose OpenedFiles entry
// was a WRITE-open (recorded nil-digest to mark "opened to write, not read")
// that fanotify then upgraded with an open-time hash. fanotify hashes every
// open indiscriminately, so this digest is NOT read-evidence — and for an
// O_CREAT output it's the empty pre-write content. TraceOutputs must exclude
// these from readPaths, otherwise a written product fanotify happened to hash
// gets counted as a read and dropped as an "intermediate" (empty product tree
// on GitHub's Azure runner when fanotify is on and the write-tap fails).
func mergeFanotifyDigests(processes []ProcessInfo, fanDigests map[string][32]byte) (touched int, fanotifyOnly map[string]string, writeOpenClaimed map[string]bool) {
	if len(fanDigests) == 0 {
		return 0, nil, nil
	}
	// Pre-convert to cryptoutil.DigestSet once per path.
	dsCache := make(map[string]cryptoutil.DigestSet, len(fanDigests))
	hexCache := make(map[string]string, len(fanDigests))
	for path, raw := range fanDigests {
		h := hex.EncodeToString(raw[:])
		ds := cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA256}: h,
		}
		dsCache[path] = ds
		hexCache[path] = h
	}
	// Track which paths were claimed by at least one process.
	claimed := make(map[string]bool, len(fanDigests))
	for i := range processes {
		// (1) Upgrade existing OpenedFiles entries to the fanotify
		//     digest — fanotify is kernel-synchronous, race-free, so
		//     it overwrites any BPF-time digest for the same path.
		if processes[i].OpenedFiles != nil {
			for path, existing := range processes[i].OpenedFiles {
				if ds, ok := dsCache[path]; ok {
					// A nil existing entry means this was a write-open
					// (recorded for inventory, not a read). fanotify's
					// open-time hash here isn't read-evidence — flag it so
					// TraceOutputs doesn't demote the written product to an
					// intermediate.
					if existing == nil {
						if writeOpenClaimed == nil {
							writeOpenClaimed = make(map[string]bool)
						}
						writeOpenClaimed[path] = true
					}
					processes[i].OpenedFiles[path] = ds
					claimed[path] = true
					touched++
				}
			}
		}
		// (2) Reconcile UnhashedOpens against fanotify. Any entry
		//     whose path fanotify successfully hashed is no longer
		//     "unhashed" — promote it back to OpenedFiles with the
		//     fanotify digest and drop the UnhashedOpens entry.
		//     Without this, --require-zero-drops fails on files
		//     that fanotify already rescued (smoke run 26421280285).
		if len(processes[i].UnhashedOpens) > 0 {
			kept := processes[i].UnhashedOpens[:0]
			for _, u := range processes[i].UnhashedOpens {
				if ds, ok := dsCache[u.Path]; ok {
					if processes[i].OpenedFiles == nil {
						processes[i].OpenedFiles = make(map[string]cryptoutil.DigestSet)
					}
					processes[i].OpenedFiles[u.Path] = ds
					claimed[u.Path] = true
					touched++
					continue
				}
				kept = append(kept, u)
			}
			processes[i].UnhashedOpens = kept
		}
	}
	// Anything fanotify saw that no process claimed → fanotify-only.
	for path, h := range hexCache {
		if !claimed[path] {
			if fanotifyOnly == nil {
				fanotifyOnly = make(map[string]string)
			}
			fanotifyOnly[path] = h
		}
	}
	return touched, fanotifyOnly, writeOpenClaimed
}

type fanotifyUnavailableError struct {
	cause error
}

func (e *fanotifyUnavailableError) Error() string {
	return "fanotify required but unavailable: " + e.cause.Error()
}

func (e *fanotifyUnavailableError) Unwrap() error { return e.cause }
