// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build windows

package auth

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLockStoreFile takes an exclusive LockFileEx without blocking, reporting
// whether it got it.
//
// THIS FILE EXISTS RATHER THAN A NO-OP FALLBACK, and the distinction is a
// security one. jade's generate lock degrades to uncoordinated off unix because
// being uncoordinated was the pre-existing behaviour there and the cost is a
// slow rebuild. Here an unlocked path silently reinstates the vulnerability
// this lock was added to close — two runs pinning different trust domains and
// both signing — so a `!unix` no-op would ship a platform on which the
// compare-and-set is not a compare-and-set.
//
// LOCKFILE_FAIL_IMMEDIATELY is the LOCK_NB equivalent, so the caller keeps its
// own wait budget. Windows releases the lock when the handle closes, including
// on abnormal termination, giving the same "no staleness policy needed"
// property flock provides.
func tryLockStoreFile(f *os.File) (bool, error) {
	// Lock one byte at offset 0. The region is arbitrary — the file is a
	// rendezvous point, never read — but it must be the SAME region in every
	// process, which is why it is fixed here rather than sized from the file.
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped),
	)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		// Held by someone else, right now. Not an error — the caller retries.
		return false, nil
	default:
		return false, err
	}
}

// unlockStoreFile releases the LockFileEx region.
func unlockStoreFile(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped)) //nolint:errcheck // best effort; closing the handle releases it regardless
}
