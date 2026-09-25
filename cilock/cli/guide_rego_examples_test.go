// jade:ring local
// Copyright 2026 The Rookery Contributors
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
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// The high-assurance guide's rego snippets are what customers copy into step
// policies, so they are executed here by the verifier's own evaluator, against
// real command-run attestations. A snippet that stops denying the case it
// exists to refuse (an absent field, an optional field in the message, the
// wrong input root, a module with no deny rule) fails this test.

const highAssuranceGuide = "../../site/docs/guides/high-assurance-attestation.md"

var (
	regoFence   = regexp.MustCompile("(?s)```rego\n(.*?)```")
	regoPackage = regexp.MustCompile(`(?m)^package (\S+)`)
)

func guideRegoModules(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(highAssuranceGuide)
	if err != nil {
		t.Fatalf("read guide: %v", err)
	}
	doc := string(b)
	start := strings.Index(doc, "## Recommended policy.rego snippet")
	end := strings.Index(doc, "## Known gaps")
	if start < 0 || end < start {
		t.Fatal("guide lost its 'Recommended policy.rego snippet' section")
	}
	mods := map[string]string{}
	for _, m := range regoFence.FindAllStringSubmatch(doc[start:end], -1) {
		pkg := regoPackage.FindStringSubmatch(m[1])
		if pkg == nil {
			t.Fatalf("guide rego block has no package:\n%s", m[1])
		}
		mods[pkg[1]] = m[1]
	}
	for _, want := range []string{"cilock.fanotify", "cilock.trace_complete", "cilock.trace_gaps"} {
		if _, ok := mods[want]; !ok {
			t.Fatalf("guide has no rego block for package %s (found %d blocks)", want, len(mods))
		}
	}
	return mods
}

func guideCoverageFixture(cov *commandrun.TraceCoverage) *commandrun.CommandRun {
	return &commandrun.CommandRun{Summary: &commandrun.TraceSummary{
		Coverage:    cov,
		Diagnostics: commandrun.TraceDiagnostics{FanotifyAvailable: true},
	}}
}

func TestGuideRegoSnippetsDecideAsDocumented(t *testing.T) {
	mods := guideRegoModules(t)

	complete := guideCoverageFixture(&commandrun.TraceCoverage{Tracer: commandrun.TraceBackendEBPF, Complete: true})
	accepted := guideCoverageFixture(&commandrun.TraceCoverage{Tracer: commandrun.TraceBackendPtrace, Gaps: []commandrun.TraceGap{
		{Kind: commandrun.GapSyscallsUntraced, Detail: "d"}, {Kind: commandrun.GapFanotifyUnavailable, Detail: "d"},
	}})
	unknownNoDetail := guideCoverageFixture(&commandrun.TraceCoverage{Tracer: commandrun.TraceBackendPtrace, Gaps: []commandrun.TraceGap{
		{Kind: commandrun.GapSyscallsUntraced}, {Kind: commandrun.GapEventsDropped},
	}})
	kindless := guideCoverageFixture(&commandrun.TraceCoverage{Tracer: commandrun.TraceBackendPtrace, Gaps: []commandrun.TraceGap{{Detail: "no kind"}}})
	incompleteNoGaps := guideCoverageFixture(&commandrun.TraceCoverage{Tracer: commandrun.TraceBackendPtrace})
	noCoverage := guideCoverageFixture(nil)
	noSummary := &commandrun.CommandRun{}
	fanotifyOff := &commandrun.CommandRun{Summary: &commandrun.TraceSummary{Coverage: complete.Summary.Coverage}}
	timeouts := guideCoverageFixture(&commandrun.TraceCoverage{Tracer: commandrun.TraceBackendEBPF, Complete: true})
	timeouts.Summary.Diagnostics.FanotifyTimeouts = 3

	cases := []struct {
		pkg, name string
		rc        *commandrun.CommandRun
		deny      bool
	}{
		{"cilock.trace_complete", "complete", complete, false},
		{"cilock.trace_complete", "partial", accepted, true},
		{"cilock.trace_complete", "no coverage", noCoverage, true},
		{"cilock.trace_complete", "no summary", noSummary, true},

		{"cilock.trace_gaps", "complete", complete, false},
		{"cilock.trace_gaps", "only accepted gaps", accepted, false},
		{"cilock.trace_gaps", "unknown gap without detail", unknownNoDetail, true},
		{"cilock.trace_gaps", "gap without kind", kindless, true},
		{"cilock.trace_gaps", "incomplete, no gaps named", incompleteNoGaps, true},
		{"cilock.trace_gaps", "no coverage", noCoverage, true},
		{"cilock.trace_gaps", "no summary", noSummary, true},

		{"cilock.fanotify", "fanotify active, clean", complete, false},
		{"cilock.fanotify", "fanotify not active", fanotifyOff, true},
		{"cilock.fanotify", "fanotify timeouts", timeouts, true},
		{"cilock.fanotify", "no summary", noSummary, true},
	}
	for _, c := range cases {
		t.Run(c.pkg+"/"+c.name, func(t *testing.T) {
			err := policy.EvaluateRegoPolicy(c.rc, []policy.RegoPolicy{{Name: c.pkg, Module: []byte(mods[c.pkg])}})
			if c.deny && err == nil {
				t.Fatalf("%s admitted %q; the guide says it refuses it", c.pkg, c.name)
			}
			if !c.deny && err != nil {
				t.Fatalf("%s refused %q: %v", c.pkg, c.name, err)
			}
		})
	}
}
