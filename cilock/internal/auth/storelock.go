// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// withStoreLock runs fn while holding an exclusive inter-process lock on
// storePath, so a read-modify-write of a credential store cannot interleave
// with another cilock process doing the same.
//
// WHY A LOCK AND NOT JUST A COMPARISON. Comparing a stored value against a new
// one closes the case where the write has ALREADY landed. It cannot close the
// case where two processes both READ before either WRITES — and for the trust
// domain that is the difference between "the second run is refused" and "two
// runs pin different authorities and both sign". The same read-modify-write
// window lets a concurrent logout be undone by an in-flight save, resurrecting
// a credential the operator just removed.
//
// AN OS-RELEASED ADVISORY LOCK, AND THE FIRST VERSION OF THIS FILE GOT IT
// WRONG IN A WAY WORTH RECORDING. It used O_CREATE|O_EXCL and, because the OS
// does not clean that up when a process dies, broke any lock whose file was
// older than 30 seconds. AGE DOES NOT DISTINGUISH A DEAD HOLDER FROM A SLOW
// ONE: a holder that is descheduled, swapping, stopped under a debugger, or
// waiting on a slow disk is still holding, and evicting it puts two writers in
// the critical section — the exact failure this lock exists to prevent,
// reintroduced by the code meant to keep it live.
//
// flock(2), and LockFileEx on Windows, have no such tradeoff to make: the
// kernel releases the lock when the process dies and holds it while the process
// merely stalls. So there is no staleness policy here at all, because there is
// no longer a question for one to answer.
//
// The lockfile is deliberately NEVER unlinked. Removing it is its own race —
// one process can delete the file another has already opened and locked, after
// which the two hold locks on different inodes and both proceed. A zero-byte
// file left in the config dir is the cheaper end of that trade.
//
// THE LOCK IS HELD FOR MICROSECONDS — a small JSON read, a map edit, a write —
// so contention is rare and the wait is short. It is NOT a general-purpose
// mutex and must not wrap anything that blocks, least of all an HTTP exchange:
// a lock held across a network call is how a transient platform outage becomes
// every subsequent run hanging on a lockfile.
func withStoreLock(storePath string, fn func() error) error {
	lockPath := storePath + ".lock"

	// The lock is taken BEFORE the store is written, so on a machine that has
	// never stored a credential the config directory does not exist yet and the
	// lockfile has nowhere to live. saveAgents creates it, but that runs inside
	// the critical section this is trying to enter. Same 0700 as the store's own
	// directory: it holds secrets.
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return fmt.Errorf("create credential store dir for %s: %w", lockPath, err)
	}

	const (
		// A contended lock resolves in microseconds; anything past this is a
		// stuck peer, and blocking a signing run indefinitely on a lockfile is
		// worse than failing it with a message naming the file. Bounded rather
		// than a blocking flock for exactly that reason.
		waitBudget = 5 * time.Second
		pollEvery  = 5 * time.Millisecond
	)

	//nolint:gosec // G304: lockPath is derived from AgentStorePath/StorePath, i.e.
	// the user's own config dir, never from caller input — same provenance as the
	// store file this guards, which carries the identical annotation.
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open credential store lock %s: %w", lockPath, err)
	}
	defer f.Close() //nolint:errcheck // the unlock below is what matters; close is cleanup

	deadline := time.Now().Add(waitBudget)
	for {
		locked, lerr := tryLockStoreFile(f)
		if lerr != nil {
			return fmt.Errorf("acquire credential store lock %s: %w", lockPath, lerr)
		}
		if locked {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"credential store %s is locked by another cilock process and did not free within %s",
				storePath, waitBudget)
		}
		time.Sleep(pollEvery)
	}
	defer unlockStoreFile(f)

	return fn()
}
