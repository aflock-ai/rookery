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
	"bytes"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
)

// formal:differential cilock-ci TestTrustedTierMatchesLeanModel

// TestTrustedTierMatchesLeanModel runs generated CI jobs with no `cilock
// login` through the real ResolvePlatformDefaults and enforceEvidenceStorage,
// and through `trusted` in the Lean model (formal/cilock-ci,
// CilockCi/Trust.lean), whose theorems include held_never_silent and
// gitlab_held_needs_archivista_token. Compared: is the run a principal the
// evidence gate holds, is its upload on, and does the gate refuse.
//
// GitHub environments are left out: their ambient branch mints a token over
// the network. #10621's tests cover them.
func TestTrustedTierMatchesLeanModel(t *testing.T) {
	eval := leanCIEvaluator(t)
	rng := rand.New(rand.NewSource(20260929)) //nolint:gosec // deterministic test cases
	const platform = "https://platform.example"
	isolateCredentialStore(t)
	prevNow := nowUnix
	nowUnix = func() int64 { return diffNow }
	t.Cleanup(func() { nowUnix = prevNow })
	names := []string{"CI", "GITLAB_CI", "CI_SERVER_URL", "CI_JOB_ID", "GITHUB_ACTIONS", "ACTIONS_ID_TOKEN_REQUEST_URL",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "BUILDKITE", "CIRCLECI", "SIGSTORE_ID_TOKEN", "CILOCK_LOGIN_ID_TOKEN",
		"CILOCK_ARCHIVISTA_ID_TOKEN", "MY_TOKEN", "CI_JOB_JWT", "OTHER"}

	type goOut struct {
		held, enabled bool
		gate          string
	}
	type goCase struct {
		env  *ciEnvCase
		args []string
		out  goOut
	}
	var cases []goCase
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for len(cases) < 600 {
		env := genCIEnv(rng, platform)
		if env.getenv("GITHUB_ACTIONS") != "" || env.getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" {
			continue
		}
		for _, n := range names {
			t.Setenv(n, "")
		}
		for _, kv := range env.environ {
			k, v, _ := strings.Cut(kv, "=")
			t.Setenv(k, v)
		}
		args := []string{"--platform-url", platform}
		explicit, value, foreign, offline := false, false, false, false
		switch rng.Intn(4) {
		case 0:
			explicit, value = true, true
			args = append(args, "--enable-archivista=true")
		case 1:
			explicit = true
			args = append(args, "--enable-archivista=false")
		}
		if rng.Intn(4) == 0 {
			foreign = true
			args = append(args, "--archivista-server", "https://archivista.elsewhere.example")
		}
		if rng.Intn(10) == 0 {
			offline = true
			args = append(args, "--offline")
		}
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		ro.ResolvePlatformDefaults(cmd)
		out := goOut{
			held:    ro.platformPrincipal != nil && ro.platformPrincipal.Kind == "workflow identity",
			enabled: ro.ArchivistaOptions.Enable,
			gate:    "proceed",
		}
		if ro.enforceEvidenceStorage(explicit) != nil {
			out.gate = "refuse"
		}
		if err := enc.Encode(map[string]any{"fn": "trusted", "env": env.lean, "now": diffNow,
			"archivistaAud": platform + "/archivista",
			"flags": map[string]any{"platformDisabled": offline, "localSigner": false, "explicitToken": false,
				"session": string(sessionNone)},
			"store": map[string]any{"explicit": explicit, "value": value, "sameOrigin": !foreign}}); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, goCase{env: env, args: args, out: out})
	}
	res := runLeanCIEvaluator(t, eval, buf.Bytes())
	if len(res) != len(cases) {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(res), len(cases))
	}
	seen := map[string]int{}
	for i, c := range cases {
		var want struct {
			Held, Enabled bool
			Gate, Error   string
		}
		if err := json.Unmarshal(res[i], &want); err != nil || want.Error != "" {
			t.Fatalf("case %d: lean result %s: %v", i, res[i], err)
		}
		if want.Held != c.out.held || want.Enabled != c.out.enabled || want.Gate != c.out.gate {
			t.Fatalf("case %d (args %q env %q): Go %+v, Lean %+v", i, c.args, c.env.environ, c.out, want)
		}
		key := "held=" + map[bool]string{true: "y", false: "n"}[c.out.held] + " enabled=" +
			map[bool]string{true: "y", false: "n"}[c.out.enabled]
		seen[key]++
	}
	for _, k := range []string{"held=y enabled=y", "held=y enabled=n", "held=n enabled=y", "held=n enabled=n"} {
		if seen[k] == 0 {
			t.Errorf("no case produced %s (%v)", k, seen)
		}
	}
	t.Logf("%d trusted-tier cases agree: %v", len(cases), seen)
}
