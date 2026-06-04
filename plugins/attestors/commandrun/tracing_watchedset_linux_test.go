//go:build linux

// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package commandrun

import "testing"

// TestWatchedSet_RootParentNestedNamespace pins the namespace-agnostic fix: in
// a nested PID namespace the BPF events carry KERNEL-GLOBAL pids that never
// equal the tracer's namespace-local seed, so matching must hinge on rootParent
// (cilock's global tgid, recorded by the BPF sentinel). The tracee
// (ppid == rootParent) is tracked and its descendants follow; cilock itself
// (pid == rootParent) is excluded so its own syscalls aren't counted as the
// build's traced activity.
func TestWatchedSet_RootParentNestedNamespace(t *testing.T) {
	const (
		localTracee = 8     // tracer's namespace-local view of the tracee (never matches global events)
		cilockGtgid = 14689 // cilock's kernel-global tgid == rootParent
		traceeGpid  = 14690 // tracee's kernel-global pid
		childGpid   = 14750 // a build worker forked by the tracee
		grandchild  = 14800 // forked by the worker
		unrelated   = 22222 // a global pid outside cilock's subtree
	)
	w := newWatchedSet(localTracee, cilockGtgid)

	// The tracee (direct child of cilock) is recognised by ppid == rootParent.
	if !w.matchAndAdd(traceeGpid, traceeGpid, cilockGtgid) {
		t.Fatal("tracee (ppid==rootParent) must match")
	}
	// A descendant follows via the now-tracked tracee pid.
	if !w.matchAndAdd(childGpid, childGpid, traceeGpid) {
		t.Fatal("descendant of the tracee must match")
	}
	// And a grandchild via the worker.
	if !w.matchAndAdd(grandchild, grandchild, childGpid) {
		t.Fatal("grandchild must match via descent")
	}
	// cilock itself (pid == rootParent, but ppid is its own shell/launcher) is
	// NOT part of the build's traced activity and must NOT match.
	if w.match(cilockGtgid, cilockGtgid, 1) {
		t.Error("cilock (pid==rootParent) must NOT match — its own syscalls are excluded")
	}
	// An unrelated global process (not under cilock) must not match.
	if w.match(unrelated, unrelated, 1) {
		t.Error("unrelated process must not match")
	}
	// addAndReturnNew (fork-event path) honours rootParent too.
	w2 := newWatchedSet(localTracee, cilockGtgid)
	if !w2.addAndReturnNew(traceeGpid, cilockGtgid) {
		t.Error("addAndReturnNew must add the tracee via rootParent")
	}
	if w2.addAndReturnNew(unrelated, 1) {
		t.Error("addAndReturnNew must not add an unrelated process")
	}
}

// TestWatchedSet_HostNamespaceLocalSeed pins the host-namespace path: there the
// tracer's pid seed equals the global event pid, so the tracee matches via the
// seed even though rootParent is also set (both paths agree).
func TestWatchedSet_HostNamespaceLocalSeed(t *testing.T) {
	const tracee = 14690
	w := newWatchedSet(tracee, 14689) // host-ns: local == global
	if !w.match(tracee, tracee, 14689) {
		t.Fatal("host-ns tracee (seeded pid) must match")
	}
}

// TestWatchedSet_ZeroRootParent pins that a zero rootParent never spuriously
// matches by ppid == 0 (the host fallback path where no global root was
// recorded must rely solely on the pid seed).
func TestWatchedSet_ZeroRootParent(t *testing.T) {
	w := newWatchedSet(100, 0)
	if w.match(200, 200, 0) {
		t.Error("zero rootParent must not match ppid==0")
	}
	if w.matchAndAdd(200, 200, 0) {
		t.Error("zero rootParent must not matchAndAdd ppid==0")
	}
}
