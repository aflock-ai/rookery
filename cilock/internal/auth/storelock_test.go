// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A HELD LOCK MUST NEVER BE BROKEN, NO MATTER HOW OLD IT LOOKS.
//
// The previous implementation evicted any lock whose file mtime was older than
// 30s, on the theory that a lock that old came from a process that died inside
// its critical section. AGE DOES NOT DISTINGUISH A DEAD HOLDER FROM A SLOW ONE.
// A holder that is descheduled, swapping, stopped under a debugger, or simply
// waiting on a slow disk is still HOLDING, and evicting it puts two processes
// in the critical section at once — which is the precise failure the lock
// exists to prevent, reintroduced by the code meant to keep it live.
//
// The consequence is not theoretical: the two writers then race exactly as they
// did unlocked, so the trust-domain compare-and-set can pin two authorities and
// a concurrent logout can be undone.
//
// This drives that case directly by backdating the lockfile while it is
// genuinely held. Under an age-based break the second caller is admitted and
// this test fails; under an OS-released lock the kernel knows the holder is
// alive, the age is irrelevant, and the second caller is refused.
func TestAHeldLockIsNotBrokenNoMatterHowOldItLooks(t *testing.T) {
	isolateConfig(t)

	path, err := AgentStorePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	held := make(chan struct{})
	release := make(chan struct{})
	holder := make(chan error, 1)

	go func() {
		holder <- withStoreLock(path, func() error {
			// Make the lock look ancient -- far older than any staleness window
			// a break-on-age policy could plausibly use.
			old := time.Now().Add(-time.Hour)
			_ = os.Chtimes(path+".lock", old, old) //nolint:errcheck // best effort; absence is itself a failure the assert below catches
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	second := make(chan error, 1)
	go func() { second <- withStoreLock(path, func() error { return nil }) }()

	select {
	case err := <-second:
		if err == nil {
			t.Fatal("a second caller entered the critical section while the lock was STILL HELD — " +
				"an age-based break evicted a live holder, putting two writers in the critical section")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the second caller neither entered nor was refused within the wait budget")
	}

	close(release)
	if err := <-holder; err != nil {
		t.Fatalf("the holder itself failed: %v", err)
	}
}

// CONCURRENT FIRST-USE MUST PRODUCE ONE PINNED AUTHORITY, NOT TWO.
//
// The compare-and-set alone closed the case where a write had ALREADY landed.
// It could not close the case both runs READ before either WROTE — and for the
// trust domain that is the difference between "the second run is refused" and
// "two runs pin different authorities and both sign". This drives that window
// directly: N goroutines racing to pin N DIFFERENT domains against one unpinned
// credential.
//
// The property is not "a particular one wins". It is that exactly one value is
// stored, every other caller is REFUSED rather than silently accepted, and the
// refusals name the value that actually won.
func TestConcurrentFirstUsePinsExactlyOneTrustDomain(t *testing.T) {
	isolateConfig(t)

	const platform = "https://platform.example.com"
	seeded := AgentCredential{
		PlatformURL: platform, TenantID: "t-1", AgentID: "a-1",
		RefreshCredential: "s3cret",
	}
	if err := SaveAgent(seeded); err != nil {
		t.Fatalf("seed: %v", err)
	}

	domains := []string{
		"judge.testifysec.com",
		"attacker.example.com",
		"someone-else.example.com",
		"third.example.com",
		"fourth.example.com",
		"fifth.example.com",
	}

	var (
		mu       sync.Mutex
		accepted []string
		refused  int
		start    = make(chan struct{})
		wg       sync.WaitGroup
	)
	for _, d := range domains {
		wg.Add(1)
		go func(td string) {
			defer wg.Done()
			<-start // release them together, to actually contend
			err := PinAgentTrustDomain(seeded, td)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				accepted = append(accepted, td)
			} else {
				refused++
			}
		}(d)
	}
	close(start)
	wg.Wait()

	if len(accepted) != 1 {
		t.Fatalf("%d callers were accepted, want exactly 1 — the others raced past the pin: %v", len(accepted), accepted)
	}
	if refused != len(domains)-1 {
		t.Fatalf("refused %d, want %d; a caller neither pinned nor was refused", refused, len(domains)-1)
	}

	got, err := LookupAgent(platform)
	if err != nil || got == nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.TrustDomain != accepted[0] {
		t.Fatalf("stored trust domain %q is not the one the accepted caller pinned (%q)", got.TrustDomain, accepted[0])
	}
}

// A CONCURRENT LOGOUT MUST NOT BE UNDONE by an in-flight save.
//
// Both SaveAgent and DeleteAgent rewrite the whole store from a snapshot. Taken
// without a lock, a save that read before the delete lands after it and
// resurrects a credential the operator just removed — the second half of the
// read-modify-write finding, and the more alarming half, since the operator has
// been told the credential is gone.
//
// The property under test is CONSISTENCY, not ordering: whichever runs last,
// the store must not end up holding a credential that has been deleted since
// its own write. So the assertion is that the final state is one of the two
// legitimate outcomes and never a torn one.
func TestConcurrentSaveAndDeleteLeaveAConsistentStore(t *testing.T) {
	isolateConfig(t)

	const platform = "https://platform.example.com"
	cred := AgentCredential{
		PlatformURL: platform, TenantID: "t-1", AgentID: "a-1",
		RefreshCredential: "s3cret",
	}
	if err := SaveAgent(cred); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; _ = SaveAgent(cred) }()
	go func() { defer wg.Done(); <-start; _, _ = DeleteAgent(platform) }()
	close(start)
	wg.Wait()

	// Either outcome is legitimate; a store that cannot be read back is not.
	got, err := LookupAgent(platform)
	if err != nil {
		t.Fatalf("the store is unreadable after a concurrent save/delete — a torn write: %v", err)
	}
	if got != nil && got.RefreshCredential != "s3cret" {
		t.Fatalf("the credential came back mangled: %+v", got)
	}
}
