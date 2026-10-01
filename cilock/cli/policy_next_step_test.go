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

// jade:ring local

package cli

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Where an agent starts the local loop by hand, the output points it at the
// commands that run the loop for it.
func TestFromBundlesPrintsTheNextStep(t *testing.T) {
	dir := t.TempDir()
	bundle := writeOmittedInventoryBundle(t, dir, "tests")
	var stderr bytes.Buffer
	require.NoError(t, runPolicyFromBundles(&bytes.Buffer{}, &stderr, []string{bundle}, nil, filepath.Join(dir, "policy.json"), 24*time.Hour, ""))
	require.Contains(t, stderr.String(), "next: ")
	require.Contains(t, stderr.String(), "cilock policy validate -p")
	require.Contains(t, stderr.String(), "cilock policy template")
	require.Contains(t, stderr.String(), "cilock policy guide")
}

// The govulncheck skip names what the wrapped command must write, and the
// guide that explains it.
func TestGovulncheckSkipNamesTheNextStep(t *testing.T) {
	got := enrichSkippedDetail("govulncheck", "no products to attest")
	require.Contains(t, got, "govulncheck -json ./... > govulncheck.json")
	require.Contains(t, got, "cilock policy guide --goal vulns")
}

// The authoring commands print instructions an agent runs verbatim. Every
// `cilock <group> <sub>` they name must be a command in this binary: an
// instruction that ends at a command the binary lacks strands the agent. A
// first word that is no command at all is prose ("cilock supplies ...").
func TestAuthoringOutputNamesOnlyCommandsThisBinaryHas(t *testing.T) {
	var texts []string
	add := func(args ...string) {
		t.Helper()
		stdout, _, err := executeCmdOutput(args...)
		require.NoError(t, err, args)
		texts = append(texts, stdout)
	}
	add("policy", "guide")
	for _, g := range goalIDs() {
		add("policy", "guide", "--goal", g)
	}
	for _, topic := range guideTopicNames() {
		add("policy", "guide", "--topic", topic)
	}
	add("policy", "template", "--help")
	add("policy", "guide", "--help")
	sandboxCredentials(t, true)
	dir := t.TempDir()
	out, err := templateCmd(t, "--goal", "tests", "-o", filepath.Join(dir, "policy.json"))
	require.NoError(t, err)
	texts = append(texts, out)
	var stderr bytes.Buffer
	printFromBundlesNextStep(&stderr, "policy.json")
	texts = append(texts, stderr.String())

	root := New()
	mention := regexp.MustCompile(`cilock ([a-z][a-z-]*) ([a-z][a-z-]*)`)
	checked := 0
	for _, text := range texts {
		for _, m := range mention.FindAllStringSubmatch(text, -1) {
			group, _ := resolveSubcommand(root, []string{m[1]})
			if group == root || !group.HasSubCommands() || group.Runnable() {
				continue // prose, or a leaf command whose next word is an argument
			}
			checked++
			if cmd, _ := resolveSubcommand(root, []string{m[1], m[2]}); cmd == group {
				t.Errorf("the authoring output names `cilock %s %s`, which this binary does not have:\n%s",
					m[1], m[2], strings.TrimSpace(firstLineWith(text, m[0])))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no `cilock <group> <sub>` mention found; the extractor is broken")
	}
}

func firstLineWith(text, needle string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}
