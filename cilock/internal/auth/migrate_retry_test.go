// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withMigrationStub swaps doMigrateLegacy for a controllable stub and re-arms the
// migration guard, restoring both on cleanup. The returned counter records how
// many times the migration body actually ran.
func withMigrationStub(t *testing.T, body func() error) *int {
	t.Helper()
	orig := doMigrateLegacy
	calls := 0
	doMigrateLegacy = func() error {
		calls++
		return body()
	}
	resetMigrateOnceForTest()
	t.Cleanup(func() {
		doMigrateLegacy = orig
		resetMigrateOnceForTest()
	})
	return &calls
}

// TestMigrateLegacyOnce_RetriesAfterFailure is the retry-semantics gate for
// FINDING 1: a migration that FAILS must NOT consume the one-shot guard. The
// process must retry on the next read path instead of being stuck on fallbacks
// for its whole lifetime. Here the stub fails the first two attempts and succeeds
// the third; each migrateLegacyOnce call must re-run the body until one succeeds.
func TestMigrateLegacyOnce_RetriesAfterFailure(t *testing.T) {
	const failUntil = 2 // fail attempts 1 and 2, succeed on 3
	attempt := 0
	calls := withMigrationStub(t, func() error {
		attempt++
		if attempt <= failUntil {
			return errors.New("injected keyring write failure")
		}
		return nil
	})

	migrateLegacyOnce() // attempt 1 — fails, guard stays unset
	assert.Equal(t, 1, *calls, "first attempt ran")

	migrateLegacyOnce() // attempt 2 — fails, guard still unset (RETRY happened)
	assert.Equal(t, 2, *calls, "a failed migration must be retried, not skipped by a consumed guard")

	migrateLegacyOnce() // attempt 3 — succeeds, guard set
	assert.Equal(t, 3, *calls, "retry continues until success")

	migrateLegacyOnce() // guard is now set — must NOT re-run
	assert.Equal(t, 3, *calls, "a successful migration is do-once: no further attempts")
}

// TestMigrateLegacyOnce_SuccessIsDoOnce confirms the success path preserves the
// exact prior behavior: a migration that succeeds on the first try runs exactly
// once across many reads.
func TestMigrateLegacyOnce_SuccessIsDoOnce(t *testing.T) {
	calls := withMigrationStub(t, func() error { return nil })

	for range 5 {
		migrateLegacyOnce()
	}
	assert.Equal(t, 1, *calls, "a successful migration runs exactly once for the process lifetime")
}

// TestMigrateLegacyOnce_ConcurrentRetriesSerialize is the thundering-herd gate:
// concurrent reads that all trigger a still-failing migration must serialize on
// the mutex (one body at a time) rather than racing, and must keep retrying. We
// assert no data race (run with -race) and that at least one attempt occurred.
func TestMigrateLegacyOnce_ConcurrentRetriesSerialize(t *testing.T) {
	var mu sync.Mutex
	concurrent := 0
	maxConcurrent := 0
	calls := withMigrationStub(t, func() error {
		mu.Lock()
		concurrent++
		if concurrent > maxConcurrent {
			maxConcurrent = concurrent
		}
		mu.Unlock()
		mu.Lock()
		concurrent--
		mu.Unlock()
		return errors.New("still failing")
	})

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			migrateLegacyOnce()
		}()
	}
	wg.Wait()

	require.GreaterOrEqual(t, *calls, 1, "at least one migration attempt ran")
	assert.LessOrEqual(t, maxConcurrent, 1, "migration body must not run concurrently (mutex serializes retries)")
}
