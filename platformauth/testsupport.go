// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

// This file exports test-support hooks that let a CONSUMING package's tests
// (e.g. jctl's config bridge in another module) drive the same keyring-mode
// reset the in-package tests use. The store's backend selection is a
// process-global once-guard probed lazily; a consumer test that flips
// JUDGE_DISABLE_KEYRING or calls keyring.MockInit between cases must re-arm that
// probe, which the unexported resetStoreForTest does for the in-package tests.
// These are the public seam for the cross-module case. They have no effect on
// production behavior (they only reset lazily-cached probe state).

// ResetStoreForTest re-arms the once-guarded keyring backend probe so a test in
// a consuming package can switch the backend (e.g. keyring.MockInit, then set or
// clear JUDGE_DISABLE_KEYRING, then re-probe). Test-only.
func ResetStoreForTest() { resetStoreForTest() }
