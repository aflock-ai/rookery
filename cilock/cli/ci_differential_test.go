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
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cijobtoken"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// formal:differential cilock-ci TestLoginTierMatchesLeanModel

type ciEnv struct {
	environ []string
	lean    [][2]any
}

func (c *ciEnv) str(name, value string) {
	c.environ = append(c.environ, name+"="+value)
	c.lean = append(c.lean, [2]any{name, map[string]any{"t": "str", "s": value}})
}

func (c *ciEnv) jwt(name, iss string, aud []string, jobID string) {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	c.environ = append(c.environ, name+"="+enc(map[string]string{"alg": "RS256"})+"."+
		enc(map[string]any{"iss": iss, "aud": aud, "job_id": jobID})+"."+enc("sig"))
	c.lean = append(c.lean, [2]any{name, map[string]any{"t": "jwt", "iss": iss, "aud": aud, "jobId": jobID, "exp": 0}})
}

func (c *ciEnv) getenv(k string) string {
	for _, kv := range c.environ {
		if n, v, _ := strings.Cut(kv, "="); n == k {
			return v
		}
	}
	return ""
}

func genEnv(rng *rand.Rand, platform string) *ciEnv {
	c := &ciEnv{}
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	switch rng.Intn(6) {
	case 0, 1, 2:
		c.str("GITLAB_CI", pick("true", "true", "true", "false"))
		c.str("CI_SERVER_URL", "https://gitlab.example")
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
	}
	if rng.Intn(3) == 0 {
		c.str("CI", pick("true", "true", "false", "1"))
	}
	auds := [][]string{{platform + "/login"}, {platform + "/login"}, {"sigstore"}, {"https://evil.example/login"}, {"sigstore", platform + "/login"}}
	for _, name := range []string{"CILOCK_LOGIN_ID_TOKEN", "SIGSTORE_ID_TOKEN", "MY_TOKEN"} {
		if rng.Intn(2) == 0 {
			c.jwt(name, pick("https://gitlab.example", "https://gitlab.example", "https://other.example"), auds[rng.Intn(len(auds))], pick("10", "10", "11"))
		}
	}
	if c.lean == nil {
		c.lean = [][2]any{}
	}
	return c
}

// loginWhy names a decideLoginTierCI refusal the way the model does.
func loginWhy(err error) string {
	var r *cijobtoken.Refusal
	switch {
	case err == nil:
		return ""
	case errors.As(err, &r):
		return "gitlab:" + r.Kind
	case strings.Contains(err.Error(), "is not the default"):
		return "githubNonDefault"
	case strings.Contains(err.Error(), "--workflow-identity requested"):
		return "noIdentity"
	case errors.Is(err, errCINoIdentity):
		return "ciNoIdentity"
	case errors.Is(err, errInteractiveInCI):
		return "interactiveInCI"
	}
	return "unknown(" + err.Error() + ")"
}

// TestLoginTierMatchesLeanModel runs generated CI environments
// through decideLoginTierCI and through `tier` in the Lean model
// (formal/cilock-ci, CilockCi/Login.lean), and auth.CIProviderFromEnv
// against `provider` (CilockCi/Automode.lean). The model's
// login_only_via_match, gitlab_login_never_browser and gitlab_login_aud are
// about this code only while these agree. The detectors' side of automode is
// compared in cmd/cilock, where the shipped attestor set is linked.
func TestLoginTierMatchesLeanModel(t *testing.T) {
	eval := leanCIEval(t)
	rng := rand.New(rand.NewSource(20260929)) //nolint:gosec // deterministic test cases
	const defaultURL = "https://platform.default"
	type goCase struct {
		env *ciEnv
		in  loginTierInput
	}
	var cases []goCase
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := 0; i < 2000; i++ {
		url := []string{defaultURL, "https://platform.example"}[rng.Intn(2)]
		env := genEnv(rng, url)
		in := loginTierInput{
			interactive: rng.Intn(10) == 0, workflowIdentity: rng.Intn(3) == 0,
			provider: auth.CIProviderFromEnv(env.getenv), githubCanMint: auth.GitHubCanMint(env.getenv),
			url: url, defaultURL: defaultURL, ci: auth.InCI(env.getenv),
		}
		if rng.Intn(10) == 0 {
			in.token = "a.b.c"
		}
		if in.provider == auth.CIGitLab {
			job, _ := cijobtoken.JobFromEnv(env.getenv)
			_, in.gitlabLoginErr = cijobtoken.Select(env.environ, job, url+"/login", "", 50)
		}
		if err := enc.Encode(map[string]any{"fn": "login", "env": env.lean, "now": 50, "flags": map[string]any{
			"token": in.token != "", "interactive": in.interactive, "workflowFlag": in.workflowIdentity,
			"url": url, "defaultUrl": defaultURL}}); err != nil {
			t.Fatal(err)
		}
		if err := enc.Encode(map[string]any{"fn": "ci", "env": env.lean}); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, goCase{env: env, in: in})
	}
	out := runLeanCIEval(t, eval, buf.Bytes())
	if len(out) != 2*len(cases) {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), 2*len(cases))
	}
	tierName := map[loginTier]string{tierToken: "token", tierBrowser: "browser"}
	seen := map[string]int{}
	for i, c := range cases {
		var want struct{ Tier, Var, Why, Error string }
		if err := json.Unmarshal(out[2*i], &want); err != nil || want.Error != "" {
			t.Fatalf("case %d: lean result %s: %v", i, out[2*i], err)
		}
		tier, err := decideLoginTierCI(c.in)
		got := tierName[tier]
		switch {
		case err != nil:
			got = "refuse/" + loginWhy(err)
		case tier == tierWorkflow && c.in.provider == auth.CIGitLab:
			got = "gitlabWorkflow"
		case tier == tierWorkflow:
			got = "githubWorkflow"
		}
		exp := want.Tier
		if exp == "refuse" {
			exp += "/" + want.Why
		}
		seen[got]++
		if got != exp {
			t.Fatalf("case %d (%+v env %q): Go %s, Lean %s", i, c.in, c.env.environ, got, exp)
		}

		var ci struct {
			CI       []string `json:"ci"`
			Provider string   `json:"provider"`
		}
		if err := json.Unmarshal(out[2*i+1], &ci); err != nil {
			t.Fatalf("case %d: lean ci result %s: %v", i, out[2*i+1], err)
		}
		gotProvider := string(auth.CIProviderFromEnv(c.env.getenv))
		if gotProvider == "github" && !auth.GitHubCanMint(c.env.getenv) {
			gotProvider = "github-nomint"
		}
		if gotProvider != ci.Provider {
			t.Fatalf("case %d env %q: Go provider %s, Lean %s", i, c.env.environ, gotProvider, ci.Provider)
		}
	}
	for _, k := range []string{"token", "browser", "githubWorkflow", "gitlabWorkflow", "refuse/githubNonDefault",
		"refuse/noIdentity", "refuse/ciNoIdentity", "refuse/interactiveInCI", "refuse/gitlab:missing", "refuse/gitlab:wrongAud", "refuse/gitlab:noJob"} {
		if seen[k] == 0 {
			t.Errorf("no case produced %s (%v)", k, seen)
		}
	}
	t.Logf("%d login and provider cases agree: %v", len(cases), seen)
}

func leanCIEval(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "formal", "cilock-ci"))
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

func runLeanCIEval(t *testing.T, bin string, input []byte) [][]byte {
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
