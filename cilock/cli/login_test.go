// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newQuietCmd returns a command whose stderr is discarded so the --token
// shell-history warning doesn't pollute test output.
func newQuietCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetErr(io.Discard)
	return cmd
}

func TestResolveLoginCredentialFromToken(t *testing.T) {
	cred, err := resolveLoginCredential(newQuietCmd(), "https://platform.example.com", "tok-123", "", "", false, false, false)
	if err != nil {
		t.Fatalf("resolveLoginCredential: %v", err)
	}
	if cred.Token != "tok-123" {
		t.Errorf("Token = %q, want tok-123", cred.Token)
	}
	if cred.PlatformURL != "https://platform.example.com" {
		t.Errorf("PlatformURL = %q, want the supplied url", cred.PlatformURL)
	}
}

func TestResolveLoginCredentialFromStdin(t *testing.T) {
	cmd := newQuietCmd()
	cmd.SetIn(strings.NewReader("  stdin-token\n"))
	cred, err := resolveLoginCredential(cmd, "https://platform.example.com", "-", "", "", false, false, false)
	if err != nil {
		t.Fatalf("resolveLoginCredential: %v", err)
	}
	if cred.Token != "stdin-token" {
		t.Errorf("Token = %q, want stdin-token (whitespace trimmed)", cred.Token)
	}
}

func TestResolveLoginCredentialEmptyTokenErrors(t *testing.T) {
	if _, err := resolveLoginCredential(newQuietCmd(), "https://platform.example.com", "   ", "", "", false, false, false); err == nil {
		t.Fatal("expected an error for an all-whitespace token, got nil")
	}
}
