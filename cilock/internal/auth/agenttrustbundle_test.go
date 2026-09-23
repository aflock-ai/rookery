// jade:ring local
// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"errors"
	"strings"
	"testing"
)

// TestPinAgentTrustBundleIsCompareAndSet walks the Git verifier's trust pin
// through every state the store can be in when verification reaches it.
// The case that matters most is "absent": a credential logged out or
// re-enrolled between lookup and pin must report persisted=false, because a
// nil there would let the verifier adopt the network bundle with no pin on
// disk. That is the silent first-use adoption the human path refuses.
func TestPinAgentTrustBundleIsCompareAndSet(t *testing.T) {
	isolateConfig(t)
	const platform = "https://platform.example.com"
	cred := AgentCredential{PlatformURL: platform, TenantID: "t-1", AgentID: "a-1", RefreshCredential: "s3cret"}
	if err := SaveAgent(cred); err != nil {
		t.Fatalf("seed: %v", err)
	}

	persisted, err := PinAgentTrustBundle(cred, "aaaa")
	if err != nil || !persisted {
		t.Fatalf("first pin: persisted=%v err=%v, want true, nil", persisted, err)
	}
	if got, _ := LookupAgent(platform); got == nil || got.TrustBundleSPKI != "aaaa" {
		t.Fatalf("first pin not on disk: %+v", got)
	}

	persisted, err = PinAgentTrustBundle(cred, "aaaa")
	if err != nil || !persisted {
		t.Fatalf("equal pin: persisted=%v err=%v, want true, nil", persisted, err)
	}

	persisted, err = PinAgentTrustBundle(cred, "bbbb")
	if err == nil || persisted {
		t.Fatalf("a different bundle was accepted: persisted=%v err=%v", persisted, err)
	}
	for _, want := range []string{"aaaa", "bbbb", "cilock enroll agent"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q must name %q", err, want)
		}
	}
	if got, _ := LookupAgent(platform); got == nil || got.TrustBundleSPKI != "aaaa" {
		t.Fatalf("the refused pin overwrote the stored one: %+v", got)
	}

	// Another command replaced the credential: never pin onto someone else's.
	other := cred
	other.RefreshCredential = "rotated"
	if err := SaveAgent(other); err != nil {
		t.Fatalf("replace: %v", err)
	}
	persisted, err = PinAgentTrustBundle(cred, "cccc")
	if !errors.Is(err, ErrAgentCredentialReplaced) || persisted {
		t.Fatalf("replaced credential: persisted=%v err=%v, want ErrAgentCredentialReplaced", persisted, err)
	}
	if got, _ := LookupAgent(platform); got == nil || got.TrustBundleSPKI != "" {
		t.Fatalf("pin landed on the replacing credential: %+v", got)
	}

	// Logged out in between: absent is NOT persisted, and not an error either.
	if _, err := DeleteAgentIf(other); err != nil {
		t.Fatalf("logout: %v", err)
	}
	persisted, err = PinAgentTrustBundle(other, "dddd")
	if err != nil || persisted {
		t.Fatalf("absent credential: persisted=%v err=%v, want false, nil", persisted, err)
	}
	if got, _ := LookupAgent(platform); got != nil {
		t.Fatalf("pinning an absent credential created one: %+v", got)
	}
}
