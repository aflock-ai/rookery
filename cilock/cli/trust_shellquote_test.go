// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
)

// The remedy this CLI prints is meant to be COPIED INTO A SHELL, and the issuer
// inside it is attacker-influenced. A URL path may legally contain shell
// syntax, so an unquoted "curl https://host/$(id)" executes id when pasted.
//
// The operator would nominally be attacking themselves, which is why this reads
// as harmless until you look at what the message actually says: your setup
// instructions are out of date. Those instructions came from somewhere else,
// and whoever wrote them picks the issuer string. The hostile-instructions case
// is the EXPECTED one for this message, not an exotic one.

// hostileIssuers are shapes that execute, expand, or split into extra arguments
// if they reach a shell unquoted. None uses a constant from the code under
// test, so these stay meaningful if the implementation is rewritten.
var hostileIssuers = []string{
	`https://evil.test/$(id)`,
	"https://evil.test/`id`",
	`https://evil.test/${HOME}`,
	`https://evil.test/;id`,
	`https://evil.test/&&id`,
	`https://evil.test/|id`,
	`https://evil.test/ extra-arg`,
	`https://evil.test/'; id; echo '`,
	`https://evil.test/"quoted"`,
	`https://evil.test/*`,
	"https://evil.test/\nid",
}

// TestShellQuote_ProducesExactlyOneWord is the property, checked by a REAL
// SHELL rather than by pattern-matching the output.
//
// A hand-rolled assertion about quoting is a restatement of the implementation
// and would pass for any consistent-looking scheme. Asking /bin/sh to expand
// the quoted string and print its argument count is the reviewer's actual
// claim — "causing command execution if copied" — evaluated by the thing that
// would do the executing.
func TestShellQuote_ProducesExactlyOneWord(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no POSIX shell available: %v", err)
	}

	for _, raw := range hostileIssuers {
		t.Run(strings.ReplaceAll(raw, "\n", "\\n"), func(t *testing.T) {
			quoted := shellQuote(raw)

			// printf %s\n on each positional parameter: one line per WORD the
			// shell produced. Anything that expanded, split or executed shows
			// up as a differing count or differing bytes.
			out, runErr := exec.Command(sh, "-c", `set -- `+quoted+`; printf '%s\n' "$#"; printf '%s' "$1"`).Output() //nolint:gosec // the whole point is to feed the shell this exact string
			if runErr != nil {
				t.Fatalf("shell rejected the quoted value (%s): %v", quoted, runErr)
			}

			count, rest, ok := strings.Cut(string(out), "\n")
			if !ok {
				t.Fatalf("unexpected shell output %q", out)
			}
			if count != "1" {
				t.Errorf("%s expanded to %s shell words, want exactly 1", quoted, count)
			}
			if rest != raw {
				t.Errorf("shell saw %q, want the literal %q — the value was altered in transit", rest, raw)
			}
		})
	}
}

// TestPreflightMessage_QuotesTheSuggestedCommand pins the property at the place
// it actually matters: the message a human is handed.
//
// It drives the real preflight through a stubbed resolver so the NXDOMAIN
// branch — the only branch that prints a command — is genuinely taken, then
// checks the shell cannot reach the payload. Testing shellQuote alone would
// leave the caller free to stop calling it.
func TestPreflightMessage_QuotesTheSuggestedCommand(t *testing.T) {
	const payload = `https://stale.invalid/$(id)`

	restore := lookupIssuerHost
	lookupIssuerHost = func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "stale.invalid", IsNotFound: true}
	}
	t.Cleanup(func() { lookupIssuerHost = restore })

	err := preflightIssuerResolvable(context.Background(), payload)
	if err == nil {
		t.Fatal("an unresolvable issuer must be refused")
	}
	msg := err.Error()

	// The command line the operator is invited to paste.
	line := ""
	for _, l := range strings.Split(msg, "\n") {
		if strings.Contains(l, "curl") {
			line = strings.TrimSpace(l)
			break
		}
	}
	if line == "" {
		t.Fatalf("the refusal no longer suggests a command; if that is deliberate delete this test, otherwise: %s", msg)
	}

	if strings.Contains(line, `$(`) && !strings.Contains(line, `'`) {
		t.Errorf("the suggested command carries unquoted shell syntax: %s", line)
	}

	// The decisive check: hand the whole line to a shell in a mode that
	// PARSES but does not execute. A command substitution that survived
	// quoting is syntax the shell would run.
	sh, lookErr := exec.LookPath("sh")
	if lookErr != nil {
		t.Skipf("no POSIX shell available: %v", lookErr)
	}
	out, runErr := exec.Command(sh, "-c", `set -- `+strings.TrimPrefix(line, "curl -- ")+`; printf '%s' "$1"`).Output() //nolint:gosec // deliberately feeding the shell the suggested line
	if runErr != nil {
		t.Fatalf("shell rejected the suggested command %q: %v", line, runErr)
	}
	if !strings.Contains(string(out), `$(id)`) {
		t.Errorf("the shell did not see the literal payload — it expanded it. got %q from %q", out, line)
	}
	if errors.Is(runErr, exec.ErrNotFound) {
		t.Fatal("unreachable")
	}
}
