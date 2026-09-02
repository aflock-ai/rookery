package auth

import (
	"strings"
	"testing"
)

// A PIN THAT ALREADY DISAGREES IS A REFUSAL, not a silent success.
//
// The earlier implementation returned nil whenever ANY pin existed, without
// comparing it. That protected the stored value and not the decision — which is
// the half that matters — and it had a race behind it: two first-use exchanges
// running concurrently both start unpinned, the first records domain X, and the
// second, answered with domain Y, saw a non-empty pin, called it success, and
// went on to sign under Y.
//
// This is that second exchange, with the interleaving already resolved: the
// store holds X and the platform has just answered Y.
func TestPinRefusesWhenAnExistingPinDisagrees(t *testing.T) {
	isolateConfig(t)

	const platform = "https://platform.example.com"
	if err := SaveAgent(AgentCredential{
		PlatformURL:       platform,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: "s3cret",
		TrustDomain:       "judge.testifysec.com",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := PinAgentTrustDomain(AgentCredential{PlatformURL: platform, TenantID: "t-1", AgentID: "a-1", RefreshCredential: "s3cret"}, "attacker.example.com")
	if err == nil {
		t.Fatal("a pin that disagrees with the stored one was accepted; that is the concurrent first-use hole")
	}
	if !strings.Contains(err.Error(), "judge.testifysec.com") || !strings.Contains(err.Error(), "attacker.example.com") {
		t.Fatalf("the refusal must name BOTH domains so an operator can tell which is which, got %v", err)
	}

	// And it must not have overwritten the pin on its way out.
	got, err := LookupAgent(platform)
	if err != nil || got == nil {
		t.Fatalf("lookup after refusal: %v", err)
	}
	if got.TrustDomain != "judge.testifysec.com" {
		t.Fatalf("the refused pin overwrote the stored one: %q", got.TrustDomain)
	}
}

// Re-pinning the SAME domain is idempotent and must not be an error — the
// control against a version that refuses everything, which would fail every
// run after the first.
func TestPinIsIdempotentForTheSameDomain(t *testing.T) {
	isolateConfig(t)

	const platform = "https://platform.example.com"
	if err := SaveAgent(AgentCredential{
		PlatformURL: platform, TenantID: "t-1", AgentID: "a-1",
		RefreshCredential: "s3cret", TrustDomain: "judge.testifysec.com",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := PinAgentTrustDomain(AgentCredential{PlatformURL: platform, TenantID: "t-1", AgentID: "a-1", RefreshCredential: "s3cret"}, "judge.testifysec.com"); err != nil {
		t.Fatalf("re-pinning the same domain must be a no-op, got %v", err)
	}
}

// First use records the answer — without this the refusals above could be
// satisfied by a function that never pins anything.
func TestPinRecordsTheFirstAnswer(t *testing.T) {
	isolateConfig(t)

	const platform = "https://platform.example.com"
	if err := SaveAgent(AgentCredential{
		PlatformURL: platform, TenantID: "t-1", AgentID: "a-1",
		RefreshCredential: "s3cret",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := PinAgentTrustDomain(AgentCredential{PlatformURL: platform, TenantID: "t-1", AgentID: "a-1", RefreshCredential: "s3cret"}, "judge.testifysec.com"); err != nil {
		t.Fatalf("first pin must succeed, got %v", err)
	}
	got, err := LookupAgent(platform)
	if err != nil || got == nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.TrustDomain != "judge.testifysec.com" {
		t.Fatalf("TrustDomain = %q, want the pinned value", got.TrustDomain)
	}
}

// A credential removed between the exchange and the pin is NOT an error: there
// is nothing left to protect, and failing here would abort a run that was
// already authorised for a logout that already happened.
func TestPinIsANoOpWhenTheCredentialIsGone(t *testing.T) {
	isolateConfig(t)
	if err := PinAgentTrustDomain(AgentCredential{PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-1", RefreshCredential: "s3cret"}, "judge.testifysec.com"); err != nil {
		t.Fatalf("pinning a platform with no stored credential must be a no-op, got %v", err)
	}
}
