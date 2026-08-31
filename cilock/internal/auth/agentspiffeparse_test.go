// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"strings"
	"testing"
)

// canonicalID is the one shape the platform mints and the only one cilock signs
// under. Built from the same fixture the refusal cases mutate, so a case differs
// from the accepted form in exactly the property it is testing.
func canonicalID() string {
	c := bindingCred("")
	return "spiffe://judge.testifysec.com/tenant/" + c.TenantID + "/agent/" + c.AgentID
}

// TestCanonicalIDIsAccepted is the control, and it is load-bearing rather than
// ceremonial: every other test here asserts a REFUSAL, so an implementation that
// refused everything — `return errors.New("no")` — would pass all of them. This
// is what makes the refusals mean "too strict is caught too".
func TestCanonicalIDIsAccepted(t *testing.T) {
	if err := checkSPIFFEIDNamesCredential(canonicalID(), bindingCred("")); err != nil {
		t.Fatalf("the canonical principal must be accepted, got %v", err)
	}
}

// TestPrefixSuffixEvasionsAreRefused covers the class the round-4 review named:
// a `HasPrefix`/`HasSuffix` pair anchors both ENDS of the string and leaves the
// middle — where the principal actually lives — unconstrained.
//
// Each of these begins with "spiffe://" and ends with
// "/tenant/<enrolled>/agent/<enrolled>", so each one PASSED the previous
// implementation while naming something the credential does not enroll. They are
// the regression cases proper: revert the parse to prefix+suffix and every
// subtest here fails.
func TestPrefixSuffixEvasionsAreRefused(t *testing.T) {
	cred := bindingCred("")
	suffix := "/tenant/" + cred.TenantID + "/agent/" + cred.AgentID

	cases := map[string]string{
		// A DIFFERENT SPIFFE path. SPIFFE identity is the whole path, so extra
		// leading segments name another principal in another namespace — one an
		// operator never enrolled and a policy author never wrote a rule for.
		"extra leading segment": "spiffe://judge.testifysec.com/extra" + suffix,
		"two extra segments":    "spiffe://judge.testifysec.com/a/b" + suffix,

		// No trust domain at all. The trust domain is the authority that vouches
		// for the name; without it the id asserts a principal with nothing
		// standing behind it.
		"empty trust domain": "spiffe://" + suffix,

		// SPIFFE forbids userinfo and a port. Both make the effective host
		// ambiguous to a reader scanning evidence later, which is exactly when
		// nobody is in a position to double-check.
		"userinfo": "spiffe://user:pw@judge.testifysec.com" + suffix,
		"port":     "spiffe://judge.testifysec.com:8443" + suffix,

		// An EMPTY port and a bare trailing "?" are the same class arriving
		// through lossy accessors: url.URL.Hostname() strips a trailing colon, so
		// Port() reports "" for "td:", and a lone "?" leaves RawQuery empty while
		// setting ForceQuery. Both would otherwise be accepted and then compared
		// as if they were the canonical id. Found by review on the sibling parse
		// in jade's certverify and fixed here in the same round.
		"empty port":  "spiffe://judge.testifysec.com:" + suffix,
		"force query": "spiffe://judge.testifysec.com" + suffix + "?",

		// Not the spiffe scheme. A https:// URI that happens to end in the right
		// path is not a SPIFFE ID, and Fulcio's SPIFFE issuer type would not
		// produce one.
		"https scheme":  "https://judge.testifysec.com" + suffix,
		"spiffe opaque": "spiffe:tenant/" + cred.TenantID + "/agent/" + cred.AgentID,
	}

	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkSPIFFEIDNamesCredential(id, cred)
			if err == nil {
				t.Fatalf("%q must be refused: it is anchored at both ends but does not name the enrolled principal", id)
			}
			// The refusal must name the offending id so an operator debugging a
			// broken platform can see WHAT came back, not just that something did.
			if !strings.Contains(err.Error(), id) {
				t.Fatalf("the refusal must quote the id it rejected, got %v", err)
			}
		})
	}
}

// THE TRUST DOMAIN IS PART OF THE IDENTITY, and it is the third this operator
// never supplied — so before it was pinned, it was entirely the server's choice.
//
// Each of these carries the CORRECT tenant and agent and a DIFFERENT authority.
// They passed a tenant-and-agent comparison while naming a principal in a
// namespace nobody enrolled in, and the run summary would have reported the
// enrolled agent. Two thirds of a SPIFFE ID is not the identity.
func TestADifferentTrustDomainIsRefusedOncePinned(t *testing.T) {
	cred := bindingCred("")
	cred.TrustDomain = "judge.testifysec.com"
	suffix := "/tenant/" + cred.TenantID + "/agent/" + cred.AgentID

	for name, id := range map[string]string{
		"another factory":    "spiffe://someone-else.example.com" + suffix,
		"lookalike domain":   "spiffe://judge.testifysec.com.evil.example" + suffix,
		"subdomain":          "spiffe://sub.judge.testifysec.com" + suffix,
		"parent domain":      "spiffe://testifysec.com" + suffix,
		"trailing dot forms": "spiffe://judge.testifysec.com." + suffix,
	} {
		t.Run(name, func(t *testing.T) {
			err := checkSPIFFEIDNamesCredential(id, cred)
			if err == nil {
				t.Fatalf("%q names a different trust domain and must be refused", id)
			}
			if !strings.Contains(err.Error(), "trust domain") {
				t.Errorf("the refusal should name the trust domain mismatch, got %v", err)
			}
		})
	}
}

// The control: the pinned trust domain is still accepted, so the check above
// cannot pass by refusing everything.
func TestThePinnedTrustDomainIsAccepted(t *testing.T) {
	cred := bindingCred("")
	cred.TrustDomain = "judge.testifysec.com"
	id := "spiffe://judge.testifysec.com/tenant/" + cred.TenantID + "/agent/" + cred.AgentID
	if err := checkSPIFFEIDNamesCredential(id, cred); err != nil {
		t.Fatalf("the enrolled principal under the pinned trust domain must be accepted, got %v", err)
	}
}

// An UNPINNED credential still accepts the answer — that is trust-on-first-use,
// and the pin is recorded afterwards. Pinned here so the TOFU window is a
// deliberate, tested property rather than an accident of ordering.
func TestAnUnpinnedCredentialAcceptsAnyWellFormedTrustDomain(t *testing.T) {
	cred := bindingCred("") // TrustDomain empty
	id := "spiffe://first-seen.example.com/tenant/" + cred.TenantID + "/agent/" + cred.AgentID
	if err := checkSPIFFEIDNamesCredential(id, cred); err != nil {
		t.Fatalf("an unpinned credential must accept the first answer (TOFU), got %v", err)
	}
}

// PERCENT-ENCODING IS REFUSED, not decoded and compared.
//
// `%31` decodes to "1", so a decode-then-compare accepts an id that is a
// DIFFERENT STRING from the canonical one — and SPIFFE IDs compare as strings,
// so a policy pinned to the canonical spelling would not match the certificate
// actually minted, while the summary claims the enrolled agent.
func TestPercentEncodedSegmentsAreRefused(t *testing.T) {
	cred := bindingCred("")
	// The first character of the fixture tenant id is "1"; %31 is "1".
	encodedTenant := "%31" + cred.TenantID[1:]

	for name, id := range map[string]string{
		"encoded tenant": "spiffe://judge.testifysec.com/tenant/" + encodedTenant + "/agent/" + cred.AgentID,
		"encoded agent":  "spiffe://judge.testifysec.com/tenant/" + cred.TenantID + "/agent/%32" + cred.AgentID[1:],
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkSPIFFEIDNamesCredential(id, cred); err == nil {
				t.Fatalf("%q is a different string from the canonical id and must be refused", id)
			}
		})
	}
}

// The SPIFFE 2048-byte ceiling, tested on BOTH sides of the boundary — a cap
// asserted only above its limit cannot tell you it sits in the right place.
//
// Enforced in this client as well as in jade's certverify because they are two
// parses of ONE grammar: a limit in only one of them means cilock signs under
// an id the verifier will refuse.
func TestOverlongPrincipalIsRefusedAtTheSpiffeLimit(t *testing.T) {
	cred := bindingCred("")
	head := "spiffe://judge.testifysec.com/tenant/" + cred.TenantID + "/agent/"

	// At the limit the id is well-formed but names a different agent, so the
	// expected refusal is the TENANT/AGENT mismatch — not the length. That is
	// what shows the length check did not fire early.
	atLimit := head + strings.Repeat("a", maxSPIFFEIDBytes-len(head))
	if got := len(atLimit); got != maxSPIFFEIDBytes {
		t.Fatalf("fixture is %d bytes, wanted %d", got, maxSPIFFEIDBytes)
	}
	err := checkSPIFFEIDNamesCredential(atLimit, cred)
	if err == nil {
		t.Fatal("the at-limit fixture names a different agent and must still be refused")
	}
	if strings.Contains(err.Error(), "2048") {
		t.Fatalf("an id AT the limit must not be refused FOR its length: %v", err)
	}

	overLimit := head + strings.Repeat("a", maxSPIFFEIDBytes+1-len(head))
	err = checkSPIFFEIDNamesCredential(overLimit, cred)
	if err == nil {
		t.Fatalf("an id of %d bytes exceeds the SPIFFE limit and must be refused", len(overLimit))
	}
	if !strings.Contains(err.Error(), "2048") {
		t.Fatalf("the refusal should name the length limit, got %v", err)
	}
}

// TestEscapedSeparatorCannotForgeAPath pins the reason the check splits the
// ESCAPED path and unescapes each segment on its own.
//
// url.Parse decodes %2F to "/" in u.Path. So an id whose tenant segment is
// "<tenant>%2Fagent%2F<agent>" has a DECODED path that reads character for
// character like the canonical form, while being a different name — one
// principal's id wearing another's namespace. Comparing the decoded path as a
// single string would accept it.
func TestEscapedSeparatorCannotForgeAPath(t *testing.T) {
	cred := bindingCred("")

	forged := "spiffe://judge.testifysec.com/tenant/" +
		cred.TenantID + "%2Fagent%2F" + cred.AgentID + "/agent/attacker"

	if err := checkSPIFFEIDNamesCredential(forged, cred); err == nil {
		t.Fatalf("an escaped separator must not be able to forge the canonical path: %q", forged)
	}
}

// TestADifferentPrincipalIsRefused is the ordinary case the parse must not lose
// while getting stricter: correct shape, wrong ids.
func TestADifferentPrincipalIsRefused(t *testing.T) {
	cred := bindingCred("")

	for name, id := range map[string]string{
		"other tenant": "spiffe://judge.testifysec.com/tenant/99999999-9999-9999-9999-999999999999/agent/" + cred.AgentID,
		"other agent":  "spiffe://judge.testifysec.com/tenant/" + cred.TenantID + "/agent/99999999-9999-9999-9999-999999999999",
		// Textual containment of an opaque UUID means nothing — pinned because a
		// `strings.Contains` implementation would accept this one.
		"tenant embeds ours": "spiffe://judge.testifysec.com/tenant/x" + cred.TenantID + "/agent/" + cred.AgentID,
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkSPIFFEIDNamesCredential(id, cred); err == nil {
				t.Fatalf("%q names a principal this credential does not enroll and must be refused", id)
			}
		})
	}
}

// TestMalformedIDsAreRefused covers inputs that are not principals at all. An
// empty string matters most: it is what a platform that omits `spiffe_id`
// produces, and an agent run whose principal cannot be named is the ambiguity
// this path exists to remove.
func TestMalformedIDsAreRefused(t *testing.T) {
	cred := bindingCred("")

	for name, id := range map[string]string{
		"empty":          "",
		"plain text":     "not-a-uri",
		"query appended": canonicalID() + "?role=admin",
		"fragment":       canonicalID() + "#x",
		// A BARE "#" IS NOT THE SAME CASE AS "#x", and it is the one a parsed
		// field cannot see. Measured against net/url: "…/agent/a#" yields
		// Fragment=="" AND RawFragment=="" AND ForceQuery==false — byte-identical
		// to an id with no fragment at all — while String() silently DROPS the
		// "#". So `u.Fragment != ""` passes it, and the id this function hands
		// back is not the id it was given. That is the whole hazard: a SPIFFE ID
		// is compared as a string, so a value the platform spelled one way and we
		// report another way is two principals wearing one name.
		//
		// Contrast the "?" sibling, which Go DOES record (ForceQuery), and which
		// is why that one was already caught. The lesson is that enumerating
		// decorations only closes the ones the parser bothered to remember.
		"bare fragment delimiter": canonicalID() + "#",
		"trailing slash":          canonicalID() + "/",
		"missing agent":           "spiffe://judge.testifysec.com/tenant/" + cred.TenantID,
		"wrong key order":         "spiffe://judge.testifysec.com/agent/" + cred.AgentID + "/tenant/" + cred.TenantID,
		"control in tenant":       "spiffe://judge.testifysec.com/tenant/" + cred.TenantID + "%00/agent/" + cred.AgentID,
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkSPIFFEIDNamesCredential(id, cred); err == nil {
				t.Fatalf("%q is not a well-formed enrolled principal and must be refused", id)
			}
		})
	}
}
