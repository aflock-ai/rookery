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

package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// Onboarding simulator run mx-commander-l5-mugug6lr (L5: SBOM plus
// provenance) failed because the agent never produced provenance. It ran
// `cilock run --step provenance -a provenance ...` and was told only
// "attestor not found: provenance": the product, the brief and `policy guide`
// all call the goal "provenance", and the attestor that records it is slsa.

// The alias table is derived from the goal catalog, never hand-listed: every
// goal id, and every detector category a goal joins on, maps to the attestors
// the goal needs beyond the always-recorded ones.
func TestAttestorAliasesComeFromTheGoalCatalog(t *testing.T) {
	aliases := attestorAliases()
	for id, want := range map[string][]string{
		"provenance":         {"slsa"},
		"tests":              {"test-results"},
		"secrets":            {"secretscan"},
		"vulns":              {"govulncheck"},
		"quality":            {"sarif"},
		"lint":               {"sarif"},
		"unit-test":          {"test-results"},
		"secret-scan":        {"secretscan"},
		"image-vulns":        {"trivy"},
		"vulnerability-scan": {"govulncheck"},
		"app-build":          {},
	} {
		got, ok := aliases[id]
		require.Truef(t, ok, "alias %q missing", id)
		require.Equalf(t, want, got.Attestors, "alias %q", id)
	}
	for _, g := range catalogGoals {
		if _, real := attestation.FactoryByName(g.ID); real {
			continue // "sbom" is both a goal and the attestor that records it
		}
		a, ok := aliases[g.ID]
		require.Truef(t, ok, "goal %q has no alias", g.ID)
		require.Equal(t, g.ID, a.Goal)
		for _, name := range a.Attestors {
			// The catalog's name, not the registry's: this test binary links
			// fewer attestors than the shipped cilock (sbom is not in it).
			_, isAttestor := attestorByName(name)
			require.Truef(t, isAttestor, "goal %q maps to %q, which the catalog does not describe", g.ID, name)
		}
	}
	// A real attestor name is never shadowed by an alias.
	for _, e := range attestation.RegistrationEntries() {
		_, shadowed := aliases[e.Name]
		require.Falsef(t, shadowed, "alias shadows real attestor %q", e.Name)
	}
}

func TestUnknownAttestorGoalIDNamesTheAttestorAndTheFlagToPass(t *testing.T) {
	err := attestorNotFoundError(attestation.ErrAttestorNotFound("provenance"), []string{"provenance"})
	msg := err.Error()
	require.True(t, strings.HasPrefix(msg, "failed to create attestor: attestor not found: provenance"), msg)
	var nf attestation.ErrAttestorNotFound
	require.True(t, errors.As(err, &nf), "the typed error must stay in the chain")
	require.Contains(t, msg, `"provenance": the provenance goal is recorded by the slsa attestor`)
	require.Contains(t, msg, "Next: rerun with -a slsa instead of -a provenance")
}

func TestUnknownAttestorExplainsEveryName(t *testing.T) {
	cases := []struct {
		name      string
		requested []string
		explains  []string
		next      string
	}{
		{
			name:      "alias and a typo of a real attestor",
			requested: []string{"git", "tests", "slas"},
			explains:  []string{`"tests": the tests goal is recorded by the test-results attestor`, `"slas": did you mean slsa?`},
			next:      "Next: rerun with -a test-results instead of -a tests and -a slsa instead of -a slas",
		},
		{
			name:      "singular spelling of a goal id",
			requested: []string{"test"},
			explains:  []string{`"test": did you mean the tests goal? It is recorded by the test-results attestor`},
			next:      "Next: rerun with -a test-results instead of -a test",
		},
		{
			name:      "a goal with nothing to add is dropped",
			requested: []string{"git", "app-build"},
			explains:  []string{`"app-build": the app-build goal needs no -a: its evidence (command-run, product) is recorded on every run, so drop it`},
			next:      "Next: rerun with no -a app-build",
		},
		{
			name:      "case does not matter",
			requested: []string{"SLSA"},
			next:      "Next: rerun with -a slsa instead of -a SLSA",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := ""
			for _, r := range tc.requested {
				if _, ok := attestation.FactoryByName(r); !ok {
					first = r
					break
				}
			}
			msg := attestorNotFoundError(attestation.ErrAttestorNotFound(first), tc.requested).Error()
			require.Contains(t, msg, tc.next, msg)
			for _, e := range tc.explains {
				require.Contains(t, msg, e)
			}
		})
	}
}

func TestUnknownAttestorWithNothingCloseNamesTheList(t *testing.T) {
	err := attestorNotFoundError(attestation.ErrAttestorNotFound("zzzzqqq"), []string{"zzzzqqq"})
	msg := err.Error()
	require.Contains(t, msg, "failed to create attestor: attestor not found: zzzzqqq")
	require.Contains(t, msg, "`cilock attestors list`")
	require.Contains(t, msg, "`cilock policy guide`")
	require.NotContains(t, msg, "Next: cilock run")
}

// One name corrected and one not: the command would still fail, so it is not
// offered as the fix; what is known is still said.
func TestUnknownAttestorPartialCorrectionOffersNoCommand(t *testing.T) {
	err := attestorNotFoundError(attestation.ErrAttestorNotFound("provenance"), []string{"provenance", "zzzzqqq"})
	msg := err.Error()
	require.Contains(t, msg, "the provenance goal is recorded by the slsa attestor")
	require.Contains(t, msg, `"zzzzqqq": no attestor or goal has a name close to it`)
	require.NotContains(t, msg, "Next: cilock run")
	require.Contains(t, msg, "`cilock attestors list`")
}

func TestTemplateUnknownAttestorNamesTheFlagToPass(t *testing.T) {
	err := templateUnknownAttestorError("provenance")
	msg := err.Error()
	require.Contains(t, msg, `unknown attestor "provenance"`)
	require.Contains(t, msg, "the provenance goal is recorded by the slsa attestor")
	require.Contains(t, msg, "Next: --attestor slsa")
	require.Contains(t, msg, "--goal provenance")

	err = templateUnknownAttestorError("zzzzqqq")
	require.Contains(t, err.Error(), "`cilock attestors list`")
	require.NotContains(t, err.Error(), "Next: cilock policy template")
}

// Through the real command: --add-step --attestor provenance refuses exactly
// as before, now with the correction.
func TestTemplateAddStepUnknownAttestorThroughTheCommand(t *testing.T) {
	sandboxCredentials(t, true)
	dir := t.TempDir()
	draft := filepath.Join(dir, "p.json")
	require.NoError(t, runPolicyTemplate(new(strings.Builder), templateOptions{goals: []string{"tests"}, output: draft, platformURL: authoringPlatform}))
	err := runPolicyTemplate(new(strings.Builder), templateOptions{policyPath: draft, addStep: "prov", attestors: []string{"provenance"}, platformURL: authoringPlatform})
	require.Error(t, err)
	require.Contains(t, err.Error(), "--attestor slsa")
}

// Codex round 1 on #10201: the refusal was built with fmt.Errorf over a
// string that held the user's text, so a name with a percent sign
// corrupted it.
func TestUnknownAttestorKeepsPercentSignsInTheCommandAndTheName(t *testing.T) {
	err := attestorNotFoundError(attestation.ErrAttestorNotFound("provenance"), []string{"provenance"})
	msg := err.Error()
	require.Contains(t, msg, "Next: rerun with -a slsa instead of -a provenance")
	require.NotContains(t, msg, "%!")

	err = attestorNotFoundError(attestation.ErrAttestorNotFound("100%"), []string{"100%"})
	msg = err.Error()
	require.Contains(t, msg, `"100%": `)
	require.NotContains(t, msg, "%!")
}

// Codex round 2 on #10201: best started one past the limit and the equality
// branch admitted a candidate at that distance, so a name two edits from a
// four-letter one, or three from a longer one, still got a replacement
// command instead of the unresolved-name fallback. Both limits, both sides.
func TestClosestNamesStopsAtTheEditLimit(t *testing.T) {
	require.Empty(t, closestNames("ab", []string{"cd"}), "two edits on a short name is past the one-edit limit")
	require.Equal(t, []string{"ac"}, closestNames("ab", []string{"ac", "cd"}), "one edit on a short name")
	require.Empty(t, closestNames("secrets", []string{"secxxxs"}), "three edits on a long name is past the two-edit limit")
	require.Equal(t, []string{"secrxts"}, closestNames("secrets", []string{"secrxts", "secxxxs"}), "two edits on a long name")
}
