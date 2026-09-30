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

package options

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cijobtoken"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// formal:differential cilock-ci TestSigningRouteMatchesLeanModel

// ciEnvCase is one generated CI environment, as cilock sees it (environ) and
// as the Lean evaluator reads it (lean).
type ciEnvCase struct {
	environ []string
	lean    [][2]any
}

func (c *ciEnvCase) str(name, value string) {
	c.environ = append(c.environ, name+"="+value)
	c.lean = append(c.lean, [2]any{name, map[string]any{"t": "str", "s": value}})
}

func (c *ciEnvCase) jwt(name, iss string, aud []string, jobID string, exp int64) {
	payload := map[string]any{"iss": iss, "aud": aud, "job_id": jobID}
	if len(aud) == 1 {
		payload["aud"] = aud[0]
	}
	if exp != 0 {
		payload["exp"] = exp
	}
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	c.environ = append(c.environ, name+"="+enc(map[string]string{"alg": "RS256"})+"."+enc(payload)+"."+enc("sig"))
	c.lean = append(c.lean, [2]any{name, map[string]any{"t": "jwt", "iss": iss, "aud": aud, "jobId": jobID, "exp": exp}})
}

func (c *ciEnvCase) getenv(k string) string {
	v := ""
	for _, kv := range c.environ {
		if n, val, _ := strings.Cut(kv, "="); n == k {
			v = val
			break
		}
	}
	return v
}

// genCIEnv draws a CI environment: vendor markers (right, wrong and absent
// values), the GitLab job identity, and ID tokens for every audience cilock
// uses and some it must never use.
func genCIEnv(rng *rand.Rand, platform string) *ciEnvCase {
	c := &ciEnvCase{}
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	switch rng.Intn(7) {
	case 0, 1, 2:
		c.str("GITLAB_CI", pick("true", "true", "true", "false"))
		if rng.Intn(8) != 0 {
			c.str("CI_SERVER_URL", "https://gitlab.example")
		}
		if rng.Intn(8) != 0 {
			c.str("CI_JOB_ID", "10")
		}
	case 3, 4:
		c.str("GITHUB_ACTIONS", pick("true", "true", "false"))
		if rng.Intn(3) != 0 {
			c.str("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		}
		if rng.Intn(3) != 0 {
			c.str("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer")
		}
	case 5:
		c.str(pick("BUILDKITE", "CIRCLECI"), pick("true", "1"))
	}
	auds := [][]string{{"sigstore"}, {"sigstore"}, {platform + "/login"}, {platform + "/archivista"}, {"sigstore", platform + "/login"}, {"https://evil.example/login"}}
	for i, name := range []string{"SIGSTORE_ID_TOKEN", "CILOCK_LOGIN_ID_TOKEN", "CILOCK_ARCHIVISTA_ID_TOKEN", "MY_TOKEN", "CI_JOB_JWT"} {
		if rng.Intn(3) != 0 {
			continue
		}
		aud := auds[rng.Intn(len(auds))]
		if i < 3 && rng.Intn(2) == 0 { // the documented name usually carries its own audience
			aud = [][]string{{"sigstore"}, {platform + "/login"}, {platform + "/archivista"}}[i]
		}
		c.jwt(name, pick("https://gitlab.example", "https://gitlab.example", "https://other.example"), aud,
			pick("10", "10", "10", "11"), []int64{0, 0, 40, 100}[rng.Intn(4)])
	}
	if rng.Intn(6) == 0 {
		c.str("OTHER", pick("", "junk"))
	}
	if c.lean == nil {
		c.lean = [][2]any{}
	}
	return c
}

const diffNow = 50

// TestSigningRouteMatchesLeanModel runs generated CI environments and flags
// through decideSigningRoute (with its inputs read by the same functions
// PreflightIdentity uses) and through `route` in the Lean model
// (formal/cilock-ci, CilockCi/Plan.lean), and requires the same route, the
// same GitLab variable, and the same refusal reason.
func TestSigningRouteMatchesLeanModel(t *testing.T) {
	eval := leanCIEvaluator(t)
	rng := rand.New(rand.NewSource(20260929)) //nolint:gosec // deterministic test cases
	const platform = "https://platform.example"
	type goCase struct {
		in  signingInputs
		env *ciEnvCase
	}
	var cases []goCase
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	sessions := []sessionKind{sessionNone, sessionNone, sessionNone, sessionBearer, sessionWorkflow}
	for i := 0; i < 3000; i++ {
		env := genCIEnv(rng, platform)
		explicit := []string{"", "", "", "", "MY_TOKEN"}[rng.Intn(5)]
		in := signingInputs{
			PlatformDisabled: rng.Intn(12) == 0,
			LocalSigner:      rng.Intn(12) == 0,
			ExplicitToken:    rng.Intn(12) == 0,
			Session:          sessions[rng.Intn(len(sessions))],
			Provider:         auth.CIProviderFromEnv(env.getenv),
			GitHubCanMint:    auth.GitHubCanMint(env.getenv),
		}
		if in.Provider == auth.CIGitLab {
			job, _ := cijobtoken.JobFromEnv(env.getenv)
			in.GitLabFulcio, in.GitLabFulcioErr = cijobtoken.Select(env.environ, job, cijobtoken.FulcioAudience, explicit, diffNow)
		}
		var ex any
		if explicit != "" {
			ex = explicit
		}
		if err := enc.Encode(map[string]any{"fn": "route", "env": env.lean, "explicit": ex, "now": diffNow,
			"flags": map[string]any{"platformDisabled": in.PlatformDisabled, "localSigner": in.LocalSigner,
				"explicitToken": in.ExplicitToken, "session": string(in.Session)}}); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, goCase{in: in, env: env})
	}
	out := runLeanCIEvaluator(t, eval, buf.Bytes())
	if len(out) != len(cases) {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), len(cases))
	}
	seen := map[string]int{}
	for i, c := range cases {
		var want struct{ Route, Var, Why, Error string }
		if err := json.Unmarshal(out[i], &want); err != nil || want.Error != "" {
			t.Fatalf("case %d: lean result %s: %v", i, out[i], err)
		}
		got := decideSigningRoute(c.in, platform)
		key := got.Kind + "/" + got.Var + "/" + got.Why
		seen[got.Kind+"/"+got.Why]++
		if wantKey := want.Route + "/" + want.Var + "/" + want.Why; key != wantKey {
			t.Fatalf("case %d (inputs %+v env %q): Go %s, Lean %s", i, c.in, c.env.environ, key, wantKey)
		}
	}
	for _, k := range []string{routeOffline + "/", routeLocalKey + "/", routeExplicitToken + "/", routeSessionExchange + "/",
		routeGitHubMint + "/", routeGitLabToken + "/", routeSignerFetch + "/", routeRefuse + "/notSignedIn",
		routeRefuse + "/gitlab:missing", routeRefuse + "/gitlab:wrongAud", routeRefuse + "/gitlab:noJob"} {
		if seen[k] == 0 {
			t.Errorf("no case produced %s; the comparison did not exercise it (%v)", k, seen)
		}
	}
	t.Logf("%d cases agree: %v", len(cases), seen)
}

// leanCIEvaluator returns the built `cilock-ci-eval`, building it with lake
// when lake is on PATH (a no-op when the model is unchanged), or skips.
func leanCIEvaluator(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "formal", "cilock-ci"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, ".lake", "build", "bin", "cilock-ci-eval")
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("Lean evaluator not built and `lake` not on PATH; install elan to run the differential test")
	}
	build := exec.Command(lake, "build", "cilock-ci-eval")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build cilock-ci-eval: %v\n%s", err, out)
	}
	return bin
}

func runLeanCIEvaluator(t *testing.T, bin string, input []byte) [][]byte {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(input)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("cilock-ci-eval: %v", err)
	}
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	return lines
}
