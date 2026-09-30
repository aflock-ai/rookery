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

package standards

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Representative run shapes. Each is what cilock can observe for that shape
// today; nothing here observes a boundary or cilockd, because nothing can.
var shapes = map[string]Observations{
	"local-key": {
		Signed: true, Provenance: true, Timestamped: true, Principal: PrincipalKey,
	},
	"local-key-no-provenance": {
		Signed: true, Timestamped: false, Principal: PrincipalKey,
	},
	"local-enrolled-agent": {
		Signed: true, Provenance: true, Timestamped: true, Principal: PrincipalAgent,
	},
	"inline-gha-keyless": {
		Signed: true, Provenance: true, Timestamped: true, HostedRunner: true,
		Principal: PrincipalWorkflow, CI: true, CIPlatform: CIGitHub,
	},
	"self-hosted-keyless": {
		Signed: true, Provenance: true, Timestamped: true,
		Principal: PrincipalWorkflow, CI: true, CIPlatform: CIGitHub,
	},
	"provenance-workflow": {
		Signed: true, Provenance: true, Timestamped: true, HostedRunner: true,
		TrustedBuilder: true, Principal: PrincipalWorkflow, CI: true, CIPlatform: CIGitHub,
	},
	"run-failed": {
		Provenance: true, Timestamped: true, HostedRunner: true, Principal: PrincipalWorkflow, CI: true, CIPlatform: CIGitHub,
	},
	// formal/slsa-tracks: gitlab.com inline reaches L2 today; L3 is refuted there.
	// Signed through public Sigstore (CI/lock 4.5.0 cannot fetch the job token
	// for the platform CA), so the workflow identity is not platform issued.
	"gitlab-saas-keyless": {
		Signed: true, Provenance: true, Timestamped: true, HostedRunner: true,
		Principal: PrincipalWorkflow, CI: true, CIPlatform: CIGitLab,
	},
	// A self-managed GitLab job signing with a job key (GitLab CE 19.4.1,
	// pipeline 9 job 31): the next steps are GitLab's (id_tokens, no GitHub
	// `id-token: write` or cilock-action snippet).
	"gitlab-self-managed-key": {
		Signed: true, Timestamped: true, Principal: PrincipalKey, CI: true, CIPlatform: CIGitLab,
	},
	// CircleCI reports no hosted runner, so L2 depends on interpretation I2.
	"circleci-keyless": {
		Signed: true, Provenance: true, Timestamped: true,
		Principal: PrincipalWorkflow, CI: true, CIPlatform: CICircleCI,
	},
}

func TestGuidanceGolden(t *testing.T) {
	for name, o := range shapes {
		for _, audience := range []string{AudienceHuman, AudienceAgent} {
			for _, scope := range []string{ScopeRun, ScopeVerify} {
				// Keep the golden set readable: verify-scope goldens only for
				// the shapes the verify output is documented with.
				if scope == ScopeVerify && name != "inline-gha-keyless" && name != "provenance-workflow" && name != "gitlab-saas-keyless" {
					continue
				}
				t.Run(name+"/"+scope+"/"+audience, func(t *testing.T) {
					g := Compute(o, scope, audience)
					if g == nil {
						t.Fatal("Compute returned nil: the embedded catalog failed to load")
					}
					var human bytes.Buffer
					g.WriteHuman(&human, "  ")
					js, err := json.MarshalIndent(g, "", "  ")
					if err != nil {
						t.Fatal(err)
					}
					base := filepath.Join("testdata", "golden", name+"."+scope+"."+audience)
					golden(t, base+".txt", human.Bytes())
					golden(t, base+".json", append(js, '\n'))
				})
			}
		}
	}
}

func golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from golden:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// The ceilings each shape must reach. These are the model's theorems restated
// over our observations: cilockInJob_is_l2, isolatedBuilder_is_l3,
// localRun_is_l1, asBuilt_is_alps1.
func TestShapeCeilings(t *testing.T) {
	want := map[string][2]string{
		"local-key":               {"L1", "ALPS-0"},
		"local-key-no-provenance": {"none", "ALPS-0"},
		"local-enrolled-agent":    {"L1", "ALPS-0"},
		"inline-gha-keyless":      {"L2", "ALPS-0"},
		"self-hosted-keyless":     {"L1", "ALPS-0"},
		"provenance-workflow":     {"L3", "ALPS-0"},
		"run-failed":              {"none", "unknown"},
		"gitlab-saas-keyless":     {"L2", "ALPS-0"},
		"circleci-keyless":        {"L1", "ALPS-0"},
		"gitlab-self-managed-key": {"none", "ALPS-0"},
	}
	for name, o := range shapes {
		g := Compute(o, ScopeRun, AudienceHuman)
		if got := [2]string{g.SLSABuild.Ceiling, g.ALPS.Ceiling}; got != want[name] {
			t.Errorf("%s: ceilings %v, want %v", name, got, want[name])
		}
	}
}

// levelToken finds a level name on a line. Every such line must present the
// level as a ceiling, a target, or an unavailable requirement; any other line
// naming a level could read as an assigned one.
var levelToken = regexp.MustCompile(`\b(L[1-3]|ALPS-[0-3])\b`)

var levelFramed = regexp.MustCompile(`: ceiling (none|L[1-3]|unknown|ALPS-[0-3]) \(|^\s*to reach (L[1-3]|ALPS-[0-3]):$|` +
	`^\s*ALPS-3: requires cilockd \(not yet available\)$|^\s*L3: not reachable on this CI today: `)

// claimsVerified is the phrasing of an assigned level, in either order.
var claimsVerified = regexp.MustCompile(`(?i)verified[_ ]level\W*(L[1-3]|ALPS-[0-3])|(verified|certified|achieved|meets|is) (at |as )?(SLSA )?(build )?(L[1-3]|ALPS-[0-3])\b|\b(L[1-3]|ALPS-[0-3]) (is |was )?(verified|certified|achieved)`)

// TestNeverClaimsAVerifiedLevel runs every combination of observations through
// both renderings and requires that neither ever states a verified level, that
// verified_level is null, that the notice is always present, that ALPS 3 is
// never offered as an action, and that nothing tells anyone to run cilockd.
func TestNeverClaimsAVerifiedLevel(t *testing.T) {
	principals := []string{PrincipalUnknown, PrincipalKey, PrincipalHuman, PrincipalAgent, PrincipalWorkflow}
	platforms := append([]string{""}, ciPlatforms...)
	n := 0
	for mask := 0; mask < 1<<8; mask++ {
		for i, p := range principals {
			o := Observations{
				Signed: mask&1 != 0, Provenance: mask&2 != 0, Timestamped: mask&4 != 0,
				HostedRunner: mask&8 != 0, TrustedBuilder: mask&16 != 0,
				BoundaryByObserver: mask&32 != 0, Isolated: mask&64 != 0, CI: mask&128 != 0,
				Principal: p, CIPlatform: platforms[(mask+i)%len(platforms)],
			}
			for _, aud := range []string{AudienceHuman, AudienceAgent} {
				for _, scope := range []string{ScopeRun, ScopeVerify} {
					n++
					g := Compute(o, scope, aud)
					var h bytes.Buffer
					g.WriteHuman(&h, "")
					if !strings.Contains(h.String(), "NOT verified levels") {
						t.Fatalf("%+v: human output lacks the not-verified notice:\n%s", o, h.String())
					}
					for _, line := range strings.Split(h.String(), "\n") {
						if claimsVerified.MatchString(line) {
							t.Fatalf("%+v: line reads as a verified level: %q", o, line)
						}
						// Step actions may cite a workflow path, never a level,
						// so only structural lines may carry a level token.
						if levelToken.MatchString(line) && !levelFramed.MatchString(line) {
							t.Fatalf("%+v: line names a level outside a ceiling/target frame: %q", o, line)
						}
					}
					js, _ := json.Marshal(g)
					var raw map[string]map[string]any
					_ = json.Unmarshal(js, &raw)
					for _, std := range []string{"slsa_build", "alps"} {
						v, present := raw[std]["verified_level"]
						if !present || v != nil {
							t.Fatalf("%+v: %s.verified_level = %v (present=%v), want null", o, std, v, present)
						}
					}
					for _, s := range g.NextSteps {
						if s.Standard == StandardALPS && s.TargetLevel == "ALPS-3" {
							t.Fatalf("%+v: ALPS 3 offered as an action: %+v", o, s)
						}
						if strings.Contains(strings.ToLower(s.Action+s.Command+s.Snippet), "cilockd") {
							t.Fatalf("%+v: a next step mentions cilockd: %+v", o, s)
						}
						if s.Status == StatusPlanned && (s.Snippet != "" || s.Command != "") {
							t.Fatalf("%+v: planned step %s carries a copyable snippet/command", o, s.ID)
						}
					}
				}
			}
		}
	}
	t.Logf("%d guidance renderings checked", n)
}

// TestAgentPhrasing: the agent audience gets the imperative agent_action text,
// and the provenance workflow is announced as coming, never as a file to use.
func TestAgentPhrasing(t *testing.T) {
	g := Compute(shapes["inline-gha-keyless"], ScopeRun, AudienceAgent)
	var l3 *NextStep
	for i := range g.NextSteps {
		if g.NextSteps[i].ID == "slsa-provenance-workflow" {
			l3 = &g.NextSteps[i]
		}
	}
	if l3 == nil {
		t.Fatalf("no L3 step for inline GitHub Actions: %+v", g.NextSteps)
	}
	if l3.Status != StatusPlanned || !strings.HasPrefix(l3.Action, "Coming") || l3.Snippet != "" {
		t.Fatalf("L3 step must be a snippet-less 'Coming' while planned: %+v", l3)
	}
	cats, _ := Catalogs()
	for _, s := range cats[StandardSLSABuild].Steps {
		if s.ID == l3.ID && l3.Action != s.AgentAction {
			t.Fatalf("agent audience got %q, want the catalog's agent_action", l3.Action)
		}
	}
}
