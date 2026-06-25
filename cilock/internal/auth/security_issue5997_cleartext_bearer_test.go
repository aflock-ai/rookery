// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"strings"
	"testing"
)

// TestSecurity_Issue5997_SignTokenRefusesCleartextBearer is the regression test
// for GHSA / issue #5997: the https-or-loopback guard lived only in discovery,
// so the token-bearing sign-token exchange would attach a session bearer (which
// can mint Fulcio signing tokens) and POST it over cleartext http:// to an
// attacker-chosen host. ExchangeSignTokenResult must refuse a non-loopback
// http:// platform URL BEFORE the bearer is attached or any request is sent,
// returning an error that names the https/cleartext requirement.
//
// The reserved .invalid TLD guarantees the host never resolves, so a regression
// (no guard) is still observable: without the guard the call falls through to a
// DNS/transport failure that does NOT mention the https/cleartext requirement.
func TestSecurity_Issue5997_SignTokenRefusesCleartextBearer(t *testing.T) {
	const attackerURL = "http://platform.attacker.example.invalid"
	const bearer = "session-bearer-that-must-not-leak"

	_, err := ExchangeSignTokenResult(attackerURL, bearer)
	if err == nil {
		t.Fatalf("expected ExchangeSignTokenResult to refuse cleartext http:// platform URL %q, got nil error (bearer would have been sent over cleartext)", attackerURL)
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "https") {
		t.Fatalf("expected refusal naming the https/cleartext requirement, got: %v", err)
	}
}
