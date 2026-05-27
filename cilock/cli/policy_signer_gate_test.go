// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/assert"
)

// Embedded policy-signer identity must be applied ONLY when the operator
// supplied no signer-identity constraint of any kind. Gating on --policy-uris
// alone would silently overwrite an operator who pinned the signer via another
// field (regression flagged by Codex review on PR #5112).
func TestPolicySignerIdentityUnset(t *testing.T) {
	tests := []struct {
		name string
		vo   options.VerifyOptions
		want bool
	}{
		{"nothing set", options.VerifyOptions{}, true},
		// Issuer has a non-empty default and is NOT an explicit pin.
		{"only default issuer", options.VerifyOptions{PolicyFulcioCertExtensions: certificate.Extensions{Issuer: "https://token.actions.githubusercontent.com"}}, true},
		{"emails set (no uris)", options.VerifyOptions{PolicyEmails: []string{"alice@example.com"}}, false},
		{"commonname set", options.VerifyOptions{PolicyCommonName: "release-signer"}, false},
		{"uris set", options.VerifyOptions{PolicyURIs: []string{"*"}}, false},
		{"dns set", options.VerifyOptions{PolicyDNSNames: []string{"a.example.com"}}, false},
		{"orgs set", options.VerifyOptions{PolicyOrganizations: []string{"Acme"}}, false},
		{"fulcio source-repo set", options.VerifyOptions{PolicyFulcioCertExtensions: certificate.Extensions{SourceRepositoryURI: "https://github.com/acme/repo"}}, false},
		{"fulcio build-config set", options.VerifyOptions{PolicyFulcioCertExtensions: certificate.Extensions{BuildConfigURI: "https://github.com/acme/repo/.github/workflows/x.yml@*"}}, false},
		{"fulcio runner-env set", options.VerifyOptions{PolicyFulcioCertExtensions: certificate.Extensions{RunnerEnvironment: "github-hosted"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, policySignerIdentityUnset(tc.vo))
		})
	}
}
