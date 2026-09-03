// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package policy

import (
	"strings"
	"testing"
)

func TestValidateRootFunctionaryConstraints(t *testing.T) {
	tests := []struct {
		name        string
		constraint  string
		wantValid   bool
		wantError   string
		wantWarning string
	}{
		{
			name:       "missing common name is an error",
			constraint: `"roots":["rootA"],"dnsnames":["*"],"emails":["*"],"organizations":["*"],"uris":["spiffe://example.test/tenant/t/agent/*"]`,
			wantError:  "commonname",
		},
		{
			name:       "empty common name is an error",
			constraint: `"roots":["rootA"],"commonname":"","dnsnames":["*"],"emails":["*"],"organizations":["*"],"uris":["spiffe://example.test/tenant/t/agent/*"]`,
			wantError:  "commonname",
		},
		{
			name:        "empty dns names warns",
			constraint:  `"roots":["rootA"],"commonname":"*","dnsnames":[],"emails":["*"],"organizations":["*"],"uris":["spiffe://example.test/tenant/t/agent/*"]`,
			wantValid:   true,
			wantWarning: "dnsnames",
		},
		{
			name:        "missing emails warns",
			constraint:  `"roots":["rootA"],"commonname":"*","dnsnames":["*"],"organizations":["*"],"uris":["spiffe://example.test/tenant/t/agent/*"]`,
			wantValid:   true,
			wantWarning: "emails",
		},
		{
			name:        "empty organizations warns",
			constraint:  `"roots":["rootA"],"commonname":"*","dnsnames":["*"],"emails":["*"],"organizations":[],"uris":["spiffe://example.test/tenant/t/agent/*"]`,
			wantValid:   true,
			wantWarning: "organizations",
		},
		{
			name:        "star URI warns about every tenant",
			constraint:  `"roots":["rootA"],"commonname":"*","dnsnames":["*"],"emails":["*"],"organizations":["*"],"uris":["*"]`,
			wantValid:   true,
			wantWarning: "every tenant",
		},
		{
			name:        "unscoped SPIFFE wildcard warns about every tenant",
			constraint:  `"roots":["rootA"],"commonname":"*","dnsnames":["*"],"emails":["*"],"organizations":["*"],"uris":["spiffe://example.test/*"]`,
			wantValid:   true,
			wantWarning: "every tenant",
		},
		{
			name:        "a glob in the tenant segment warns about every tenant",
			constraint:  `"roots":["rootA"],"commonname":"*","dnsnames":["*"],"emails":["*"],"organizations":["*"],"uris":["spiffe://example.test/tenant/*/agent/*"]`,
			wantValid:   true,
			wantWarning: "every tenant",
		},
		{
			name:        "an empty tenant segment warns about every tenant",
			constraint:  `"roots":["rootA"],"commonname":"*","dnsnames":["*"],"emails":["*"],"organizations":["*"],"uris":["spiffe://example.test/tenant//agent/*"]`,
			wantValid:   true,
			wantWarning: "every tenant",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := `{
				"expires":"2030-01-01T00:00:00Z",
				"roots":{"rootA":{"certificate":"Zm9v"}},
				"steps":{"build":{"name":"build",
					"functionaries":[{"type":"root","certConstraint":{` + tc.constraint + `}}],
					"attestations":[{"type":"test"}]}}
			}`

			result := validateRaw(t, fixture)
			if result.Valid != tc.wantValid {
				t.Fatalf("Valid = %v, want %v; errors=%v warnings=%v", result.Valid, tc.wantValid, result.Errors, result.Warnings)
			}
			if tc.wantError != "" && !strings.Contains(strings.Join(result.Errors, " | "), tc.wantError) {
				t.Fatalf("errors %v do not name %q", result.Errors, tc.wantError)
			}
			if tc.wantWarning != "" {
				warnings := strings.Join(result.Warnings, " | ")
				if !strings.Contains(warnings, tc.wantWarning) || !strings.Contains(warnings, "--policy-hardening enforce") {
					t.Fatalf("warnings must name %q and --policy-hardening enforce; got %v", tc.wantWarning, result.Warnings)
				}
			}
		})
	}
}
