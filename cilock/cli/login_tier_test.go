// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import "testing"

// TestDecideLoginTier exhaustively pins the login precedence and its security
// gates: --token > ambient workflow OIDC (default-platform-only unless opted in)
// > interactive browser, with hard errors instead of unsafe fallbacks.
func TestDecideLoginTier(t *testing.T) {
	const def = "https://platform.testifysec.com"
	const other = "https://evil.example.com"

	cases := []struct {
		name                                   string
		token                                  string
		interactive, workflowIdentity, ambient bool
		url                                    string
		want                                   loginTier
		wantErr                                bool
	}{
		{"explicit token wins over everything", "jwt", false, false, true, other, tierToken, false},
		{"--interactive forces browser even in CI", "", true, false, true, def, tierBrowser, false},
		{"ambient on the default platform auto-fires", "", false, false, true, def, tierWorkflow, false},
		{"ambient on a non-default platform without opt-in is a hard error", "", false, false, true, other, tierBrowser, true},
		{"ambient on a non-default platform WITH --workflow-identity opts in", "", false, true, true, other, tierWorkflow, false},
		{"--workflow-identity with no ambient identity is a hard error", "", false, true, false, def, tierBrowser, true},
		{"no token, no ambient -> interactive browser", "", false, false, false, def, tierBrowser, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decideLoginTier(c.token, c.interactive, c.workflowIdentity, c.ambient, c.url, def)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error (unsafe/unsatisfiable case must not silently fall back)")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("tier = %v, want %v", got, c.want)
			}
		})
	}
}
