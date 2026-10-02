// jade:ring local

// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"testing"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/require"
)

// Gobwas/glob matches "" for patterns that reduce to one-rune matchers.
// Each of these patterns was observed matching the empty string in gobwas
// v0.2.3. A cert field that is absent must not satisfy any of them.
var emptyMatchingGobwasPatterns = []string{"?", "[!a]", "{a,?}", "{?}", "{,a}"}

func TestCertGlob_NonAllowAllPatternRefusesEmptyCommonName(t *testing.T) {
	for _, pattern := range emptyMatchingGobwasPatterns {
		err := checkCertConstraintGlob("common name", pattern, "")
		require.Error(t, err, "CN constraint %q must not match an empty CN", pattern)
	}
	// The one-character reading still works for a present value.
	require.NoError(t, checkCertConstraintGlob("common name", "?", "a"))
}

func TestCertGlob_NonAllowAllPatternRefusesAbsentExtension(t *testing.T) {
	// The leaf carries an Issuer but no SourceRepositoryRef.
	ext, err := certificate.Extensions{Issuer: "https://token.actions.githubusercontent.com"}.Render()
	require.NoError(t, err)

	for _, pattern := range emptyMatchingGobwasPatterns {
		cc := CertConstraint{Extensions: certificate.Extensions{SourceRepositoryRef: pattern}}
		require.Error(t, cc.checkExtensions(ext), "extension constraint %q must not match an absent extension", pattern)
	}

	// "*" is the explicit allow-all and keeps admitting an absent extension.
	cc := CertConstraint{Extensions: certificate.Extensions{SourceRepositoryRef: AllowAllConstraint}}
	require.NoError(t, cc.checkExtensions(ext))

	// A present value still matches "?".
	withRef, err := certificate.Extensions{Issuer: "i", SourceRepositoryRef: "x"}.Render()
	require.NoError(t, err)
	cc = CertConstraint{Extensions: certificate.Extensions{SourceRepositoryRef: "?"}}
	require.NoError(t, cc.checkExtensions(withRef))
}

func TestCertGlob_CompiledMatcherRefusesEmpty(t *testing.T) {
	for _, pattern := range emptyMatchingGobwasPatterns {
		g, err := compileCertGlob(pattern)
		require.NoError(t, err)
		require.False(t, g.Match(""), "pattern %q", pattern)
	}
	g, err := compileCertGlob(AllowAllConstraint)
	require.NoError(t, err)
	require.True(t, g.Match(""), "\"*\" is the explicit allow-all")
}
