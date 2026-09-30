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

package cijobtoken

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
)

// formal:differential cilock-ci TestSelectMatchesLeanModel

// genClaims is one generated token's claims, in both encodings.
type genClaims struct {
	Iss   string   `json:"iss"`
	Aud   []string `json:"aud"`
	JobID string   `json:"jobId"`
	Exp   int64    `json:"exp"`
}

type genVal struct {
	T string `json:"t"`
	S string `json:"s"`
	genClaims
}

// jwtOf encodes c as a compact JWT, with aud as a bare string or an array and
// job_id as a string or a number, the ways real issuers write them.
func jwtOf(rng *rand.Rand, c genClaims) string {
	payload := map[string]any{"iss": c.Iss, "job_id": c.JobID}
	if len(c.Aud) == 1 && rng.Intn(2) == 0 {
		payload["aud"] = c.Aud[0]
	} else {
		payload["aud"] = c.Aud
	}
	if c.JobID != "" && strings.Trim(c.JobID, "0123456789") == "" && c.JobID[0] != '0' && rng.Intn(2) == 0 {
		payload["job_id"] = json.Number(c.JobID)
	}
	if c.Exp != 0 {
		payload["exp"] = c.Exp
	}
	b, _ := json.Marshal(payload)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(b) + "." + enc([]byte("sig"))
}

// TestSelectMatchesLeanModel runs generated environments through Select and
// through `selectToken` in the Lean model (formal/cilock-ci,
// CilockCi/Token.lean) and requires the same answer: the same variable, or
// the same refusal. The model's theorems (select_sound, forwarded_aud_exact,
// explicit_respected) are about this code only while the two agree.
func TestSelectMatchesLeanModel(t *testing.T) {
	eval := leanEvaluator(t)
	rng := rand.New(rand.NewSource(20260929)) //nolint:gosec // deterministic test cases, not crypto
	pick := func(xs ...string) string { return xs[rng.Intn(len(xs))] }
	names := []string{"SIGSTORE_ID_TOKEN", "CILOCK_LOGIN_ID_TOKEN", "CILOCK_ARCHIVISTA_ID_TOKEN", "CILOCK_ID_TOKEN", "A_TOKEN", "Z_TOKEN", "CI_JOB_JWT"}
	auds := [][]string{{"sigstore"}, {"sigstore"}, {"sigstore"}, {"https://p/login"}, {"https://p/archivista"}, {"sigstore", "https://p/login"}, {}, {"https://evil/login"}}

	type goCase struct {
		environ  []string
		job      Job
		aud      string
		explicit string
		now      int64
	}
	var cases []goCase
	var in bytes.Buffer
	enc := json.NewEncoder(&in)
	for i := 0; i < 4000; i++ {
		c := goCase{
			job:      Job{ServerURL: pick("https://g", "https://g/", "https://g", "https://g", "https://g", "https://g", "https://g", "https://g", "https://g", ""), JobID: pick("10", "10", "10", "10", "10", "10", "10", "10", "10", "")},
			aud:      pick("sigstore", "sigstore", "sigstore", "https://p/login", "https://p/archivista", "sigstore", "https://p/login", "sigstore", "sigstore", ""),
			explicit: pick("", "", "", "SIGSTORE_ID_TOKEN", "A_TOKEN", "UNSET_VAR"),
			now:      50,
		}
		var env [][2]any
		seen := map[string]bool{}
		for n := rng.Intn(5); n > 0; n-- {
			name := names[rng.Intn(len(names))]
			if seen[name] {
				continue
			}
			seen[name] = true
			var v genVal
			var value string
			switch rng.Intn(6) {
			case 0:
				v = genVal{T: "str", S: pick("", "  ", "junk", "not.a.jwt")}
				value = v.S
			default:
				gc := genClaims{
					Iss:   pick("https://g", "https://g", "https://g", "https://g/", " https://g", "https://other"),
					Aud:   auds[rng.Intn(len(auds))],
					JobID: pick("10", "10", "10", "10", "11", ""),
					Exp:   []int64{0, 0, 40, 100}[rng.Intn(4)],
				}
				v = genVal{T: "jwt", genClaims: gc}
				value = jwtOf(rng, gc)
			}
			env = append(env, [2]any{name, v})
			c.environ = append(c.environ, name+"="+value)
		}
		if env == nil {
			env = [][2]any{}
		}
		var explicit any
		if c.explicit != "" {
			explicit = c.explicit
		}
		if err := enc.Encode(map[string]any{"fn": "select", "env": env, "serverUrl": c.job.ServerURL, "jobId": c.job.JobID,
			"aud": c.aud, "explicit": explicit, "now": c.now}); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, c)
	}

	out := runLeanEvaluator(t, eval, in.Bytes())
	if len(out) != len(cases) {
		t.Fatalf("lean evaluator returned %d results for %d cases", len(out), len(cases))
	}
	seen := map[string]int{}
	for i, c := range cases {
		var want struct {
			OK      string `json:"ok"`
			Refuse  string `json:"refuse"`
			Var     string `json:"var"`
			Error   string `json:"error"`
			Present bool
		}
		if err := json.Unmarshal(out[i], &want); err != nil || want.Error != "" {
			t.Fatalf("case %d: lean result %s: %v", i, out[i], err)
		}
		tok, err := Select(c.environ, c.job, c.aud, c.explicit, c.now)
		got := "ok:" + tok.Var
		if err != nil {
			got = "refuse:" + refusalKind(err)
		}
		exp := "ok:" + want.OK
		if want.Refuse != "" {
			exp = "refuse:" + want.Refuse
			if want.Var != "" {
				exp += ":" + want.Var
			}
		}
		seen[strings.SplitN(exp, ":", 3)[0]+":"+strings.SplitN(exp+":", ":", 3)[1]]++
		if got != exp {
			t.Fatalf("case %d (job %+v aud %q explicit %q env %q): Go %s, Lean %s", i, c.job, c.aud, c.explicit, c.environ, got, exp)
		}
	}
	// Guard against a vacuous pass: every outcome the model can produce occurred.
	for _, k := range []string{"refuse:noAudience", "refuse:noJob", "refuse:notJWT", "refuse:notThisJob", "refuse:expired",
		"refuse:explicitEmpty", "refuse:wrongAud", "refuse:missing"} {
		if seen[k] == 0 {
			t.Errorf("no case produced %s; the comparison did not exercise it (%v)", k, seen)
		}
	}
	ok := 0
	for k, n := range seen {
		if strings.HasPrefix(k, "ok:") {
			ok += n
		}
	}
	if ok < 200 {
		t.Errorf("only %d cases selected a token; the generator is starving the ok path", ok)
	}
	t.Logf("%d cases agree: %v", len(cases), seen)
}

// leanEvaluator returns the path of the built `cilock-ci-eval`, building it
// with lake when needed, or skips.
func leanEvaluator(t *testing.T) string {
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
	// Always build: lake is a no-op when the model is unchanged, and a stale
	// binary would compare the code against an old model.
	build := exec.Command(lake, "build", "cilock-ci-eval")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build cilock-ci-eval: %v\n%s", err, out)
	}
	return bin
}

func runLeanEvaluator(t *testing.T, bin string, input []byte) [][]byte {
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

// refusalKind names a Select refusal the way the model does.
func refusalKind(err error) string {
	var r *Refusal
	if !errors.As(err, &r) {
		return "not-a-refusal"
	}
	if r.Var != "" {
		return r.Kind + ":" + r.Var
	}
	return r.Kind
}
