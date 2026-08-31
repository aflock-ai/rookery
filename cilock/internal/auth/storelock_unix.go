// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build unix

package auth

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryLockStoreFile takes an exclusive flock(2) without blocking, reporting
// whether it got it.
//
// LOCK_NB rather than a blocking LOCK_EX so the caller keeps its own wait
// budget: a blocking acquire against a wedged peer hangs a signing run with no
// message, where the bounded poll fails with one that names the lockfile.
//
// The kernel owns the lifetime. It drops the lock when the process exits,
// however it exits, and it keeps the lock while the holder is merely slow —
// which is the whole reason this replaced an O_EXCL file with a staleness
// timeout. There is no dead-holder case left for this code to guess at.
func tryLockStoreFile(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK):
		// Held by someone else, right now. Not an error — the caller retries.
		return false, nil
	default:
		return false, err
	}
}

// unlockStoreFile releases the flock. Closing the file would release it too,
// but doing it explicitly keeps the release adjacent to the acquire rather than
// implied by a deferred Close somewhere else.
func unlockStoreFile(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:errcheck // best effort; the close that follows releases it regardless
}
