// jade:ring local
// Copyright 2026 The Aflock Authors
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

// Differential test: the Go policy evaluators against the Lean model in
// formal/cilock-evaluators (the oracle executable built by `lake build`).
//
// Each case is generated at random, run through the real Go code, encoded as
// JSON and run through the Lean model, and the two verdicts are compared. The
// Lean side never re-implements a verdict; see CilockEvaluators/Oracle.lean.
//
// The test SKIPS when the oracle binary is absent (Lean is not provisioned on
// CI). Point CILOCK_EVALUATORS_ORACLE at a binary to use another build.
// FORMAL_DIFF_SEED and FORMAL_DIFF_N change the seed and the cases per kind.
//
// The markers below register each suite with the formal gate, which builds the
// oracle and runs the suite, and fails if it skips.
//
// formal:differential cilock-evaluators TestFormalDifferentialRego
// formal:differential cilock-evaluators TestFormalDifferentialAI
// formal:differential cilock-evaluators TestFormalDifferentialGate
// formal:differential cilock-evaluators TestFormalDifferentialVSA

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

const diffUnit = 10_000_000_000 // the Lean model's 1.0

// cilockEvaluatorsModel is the Lean project the oracle is built from. It is a
// path literal on purpose: `jade check formal-differential-inputs` reads it to
// prove a change to the model selects this test.
const cilockEvaluatorsModel = "../../formal/cilock-evaluators"

func diffOracle(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CILOCK_EVALUATORS_ORACLE"); p != "" {
		return p
	}
	p, err := filepath.Abs(filepath.Join(cilockEvaluatorsModel, ".lake", "build", "bin", "cilock-evaluators-oracle"))
	require.NoError(t, err)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("Lean oracle not built (%s); run `lake build` in formal/cilock-evaluators", p)
	}
	return p
}

func diffEnvInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// runOracle feeds every case to the Lean binary in one process.
func runOracle(t *testing.T, bin string, cases []any) []string {
	t.Helper()
	var in strings.Builder
	for _, c := range cases {
		b, err := json.Marshal(c)
		require.NoError(t, err)
		in.Write(b)
		in.WriteByte('\n')
	}
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(in.String())
	out, err := cmd.Output()
	require.NoError(t, err, "oracle failed")
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	require.Len(t, lines, len(cases), "oracle must answer every case")
	return lines
}

type diffMismatch struct {
	kind, goV, leanV, detail string
}

func reportMismatches(t *testing.T, kind string, ms []diffMismatch, total int) {
	t.Helper()
	t.Logf("%s: %d cases, %d mismatches", kind, total, len(ms))
	byClass := map[string]int{}
	for _, m := range ms {
		byClass[m.goV+" vs lean "+m.leanV]++
	}
	keys := make([]string, 0, len(byClass))
	for k := range byClass {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  go %s: %d", k, byClass[k])
	}
	for i, m := range ms {
		if i >= 5 {
			break
		}
		t.Logf("  example: go=%s lean=%s %s", m.goV, m.leanV, m.detail)
	}
	if len(ms) > 0 {
		t.Errorf("%s: %d/%d cases disagree with the Lean model", kind, len(ms), total)
	}
}

// ---------------------------------------------------------------------------
// Rego
// ---------------------------------------------------------------------------

type regoModJSON struct {
	Name   string `json:"name"`
	Pkg    string `json:"pkg"`
	Parses bool   `json:"parses"`
}

type denyJSON struct {
	Pkg string `json:"pkg"`
	K   string `json:"k"`
	N   int    `json:"n"`
}

type regoCaseJSON struct {
	Kind      string        `json:"kind"`
	RejectDup bool          `json:"rejectDup"`
	Fault     bool          `json:"fault"`
	Modules   []regoModJSON `json:"modules"`
	Deny      []denyJSON    `json:"deny"`
}

// denyKinds: the Rego text of a package's deny, and the value OPA returns for it
// on the given input. hasRef says whether the input carries `reftype`.
type denyKind struct {
	name  string
	body  string
	value func(hasRef bool) denyJSON
	fault bool
}

func coll(n int) func(bool) denyJSON {
	return func(bool) denyJSON { return denyJSON{K: "collection", N: n} }
}

var denyKinds = []denyKind{
	{"undefined", "allow := true", func(bool) denyJSON { return denyJSON{K: "undefined"} }, false},
	{"completeNotFiring", "deny = [\"x\"] { false }", func(bool) denyJSON { return denyJSON{K: "undefined"} }, false},
	{"emptySet", "deny[msg] { msg := \"x\"; false }", coll(0), false},
	{"oneString", "deny[msg] { msg := \"a\" }", coll(1), false},
	{"twoStrings", "deny[msg] { msg := \"a\" }\ndeny[msg] { msg := \"b\" }", coll(2), false},
	{"number", "deny[x] { x := 42 }", coll(1), false},
	{"scalarTrue", "deny := true", func(bool) denyJSON { return denyJSON{K: "scalar"} }, false},
	{"scalarString", "deny := \"x\"", func(bool) denyJSON { return denyJSON{K: "scalar"} }, false},
	{"scalarNumber", "deny := 7", func(bool) denyJSON { return denyJSON{K: "scalar"} }, false},
	{"emptyArray", "deny := []", coll(0), false},
	{"oneArray", "deny := [\"a\"]", coll(1), false},
	{"emptyObject", "deny := {}", coll(0), false},
	{"oneObject", "deny := {\"a\": 1}", coll(1), false},
	{"divZero", "deny[msg] { x := 1 / 0; msg := sprintf(\"%v\", [x]) }", coll(0), true},
	{"hoisted", "deny[msg] { not startswith(input.reftype, \"tag\"); msg := \"untagged\" }",
		func(hasRef bool) denyJSON {
			if hasRef {
				return denyJSON{K: "collection", N: 1}
			}
			return denyJSON{K: "collection", N: 0}
		}, false},
}

// genRegoModules builds 0-3 modules. The first module of a package owns its
// deny kind; a later module of the same package adds only a helper rule, so the
// merged package's deny is the owner's. A module may be made unparseable.
func genRegoModules(r *rand.Rand, withEmpty bool) ([]RegoPolicy, []regoModJSON, map[string]denyKind) {
	n := 1 + r.IntN(3)
	if withEmpty && r.IntN(10) == 0 {
		n = 0
	}
	pkgs := []string{"p1", "p2", "p3"}
	owner := map[string]denyKind{}
	var pols []RegoPolicy
	var mods []regoModJSON
	for i := 0; i < n; i++ {
		pkg := pkgs[r.IntN(len(pkgs))]
		name := fmt.Sprintf("m%d", i)
		var body string
		if _, ok := owner[pkg]; ok {
			body = fmt.Sprintf("helper_%d := 1", i)
		} else {
			k := denyKinds[r.IntN(len(denyKinds))]
			owner[pkg] = k
			body = k.body
		}
		parses := r.IntN(12) != 0
		src := fmt.Sprintf("package %s\n\n%s\n", pkg, body)
		if !parses {
			src = fmt.Sprintf("package %s\n\ndeny[msg] { msg := \n", pkg)
		}
		pols = append(pols, RegoPolicy{Name: name, Module: []byte(src)})
		mods = append(mods, regoModJSON{Name: name, Pkg: pkg, Parses: parses})
	}
	return pols, mods, owner
}

func regoRunJSON(owner map[string]denyKind, hasRef bool) ([]denyJSON, bool) {
	var deny []denyJSON
	fault := false
	for pkg, k := range owner {
		d := k.value(hasRef)
		d.Pkg = pkg
		deny = append(deny, d)
		fault = fault || k.fault
	}
	sort.Slice(deny, func(i, j int) bool { return deny[i].Pkg < deny[j].Pkg })
	return deny, fault
}

func regoAttestor(ref int, typ string, hasRef bool) attestation.Attestor {
	body := map[string]any{"ref": ref}
	if hasRef {
		body["reftype"] = "branch"
	}
	b, _ := json.Marshal(body)
	return attestation.NewRawAttestation(typ, b)
}

func classifyGoErr(err error) string {
	if err == nil {
		return "pass"
	}
	var refusal ErrAIEvaluationRefused
	if errors.As(err, &refusal) {
		return "refused"
	}
	var denied ErrPolicyDenied
	if errors.As(err, &denied) {
		return "deny"
	}
	return "error"
}

func TestFormalDifferentialRego(t *testing.T) {
	bin := diffOracle(t)
	r := rand.New(rand.NewPCG(uint64(diffEnvInt("FORMAL_DIFF_SEED", 1)), 7))
	n := diffEnvInt("FORMAL_DIFF_N", 600)
	saved := Hardening()
	defer SetHardening(saved)

	var cases []any
	var goV, details []string
	for i := 0; i < n; i++ {
		pols, mods, owner := genRegoModules(r, true)
		hasRef := r.IntN(2) == 0
		rejectDup := r.IntN(2) == 0
		SetHardening(HardeningOptions{RejectDuplicateRegoPackage: rejectDup})
		err := EvaluateRegoPolicy(regoAttestor(i, "https://example.com/t", hasRef), pols)
		goV = append(goV, classifyGoErr(err))
		deny, fault := regoRunJSON(owner, hasRef)
		cases = append(cases, regoCaseJSON{Kind: "rego", RejectDup: rejectDup, Fault: fault, Modules: nonNilMods(mods), Deny: nonNilDeny(deny)})
		details = append(details, fmt.Sprintf("mods=%v deny=%v rejectDup=%v err=%v", mods, deny, rejectDup, err))
	}
	lean := runOracle(t, bin, cases)
	var ms []diffMismatch
	for i := range cases {
		if goV[i] != lean[i] {
			ms = append(ms, diffMismatch{"rego", goV[i], lean[i], details[i]})
		}
	}
	reportMismatches(t, "rego", ms, len(cases))
}

// ---------------------------------------------------------------------------
// AI (typed decisions through the Jev provider, against a local server)
// ---------------------------------------------------------------------------

type modelJSON struct {
	Pinned []int  `json:"pinned,omitempty"`
	Other  string `json:"other"`
}

type aiPolicyJSON struct {
	Name     string         `json:"name"`
	Model    modelJSON      `json:"model"`
	Prompt   string         `json:"prompt"`
	Decision map[string]any `json:"decision"`
}

type aiItemJSON struct {
	Policy aiPolicyJSON   `json:"policy"`
	Reply  map[string]any `json:"reply"`
}

type aiCaseJSON struct {
	Kind  string       `json:"kind"`
	Items []aiItemJSON `json:"items"`
}

func modelOf(name string) modelJSON {
	var a, b, c int
	if _, err := fmt.Sscanf(name, "jev-%d.%d.%d", &a, &b, &c); err == nil && name == fmt.Sprintf("jev-%d.%d.%d", a, b, c) {
		return modelJSON{Pinned: []int{a, b, c}}
	}
	return modelJSON{Other: name}
}

// A grid value k/10^4 in [0, 1].
func gridP(k int) (float64, int64) { return float64(k) / 1e4, int64(k) * (diffUnit / 10_000) }

// A score grid value m/100.
func gridS(m int) (float64, int64) { return float64(m) / 100, int64(m) * (diffUnit / 100) }

type genAnswer struct {
	wire any  // what the server sends for this question (nil: omit)
	lean any  // the oracle's `ans`
	omit bool // the answer is missing
}

type genPolicy struct {
	pol  AiPolicy
	json aiPolicyJSON
	ans  genAnswer
}

func optBound(r *rand.Rand, gen func(int) (float64, int64), hi int) (*float64, any) {
	if r.IntN(3) == 0 {
		return nil, nil
	}
	k := r.IntN(hi + 1)
	switch r.IntN(6) { // the edges, where a boundary bug lives
	case 0:
		k = 0
	case 1:
		k = hi
	}
	f, l := gen(k)
	return &f, l
}

//nolint:gocyclo,funlen // one generator per decision kind and answer shape
func genAiPolicy(r *rand.Rand, name string) genPolicy {
	models := []string{"jev-1.13.0", "jev-1.13.0", "jev-1.13.0", "jev-1.13.0", "jev-1.14.0", "jev", ""}
	model := models[r.IntN(len(models))]
	p := AiPolicy{Name: name, Model: model}
	j := aiPolicyJSON{Name: name, Model: modelOf(model)}
	var ans genAnswer
	answerClass := r.IntN(20) // 0..15 valid, 16 missing, 17 bad, 18 wrong type, 19 out of range
	switch r.IntN(3) {
	case 0:
		mn, mnL := optBound(r, gridP, 10_000)
		mx, mxL := optBound(r, gridP, 10_000)
		p.Decision = &AiDecision{YesNo: &AiYesNo{Instructions: "q", Criteria: map[string]string{"true": "yes", "false": "no"}, MinProbability: mn, MaxProbability: mx}}
		j.Decision = map[string]any{"yesNo": map[string]any{"min": mnL, "max": mxL}}
		vf, vl := gridP(r.IntN(10_001))
		if mn != nil && r.IntN(3) == 0 {
			vf, vl = *mn, mnL.(int64)
		}
		ans = genAnswer{wire: map[string]any{"type": "noul", "noul": vf}, lean: map[string]any{"yesNo": vl}}
		switch answerClass {
		case 18:
			ans = genAnswer{wire: map[string]any{"type": "choice", "choice": "a", "confidence": 1, "probabilities": map[string]float64{"a": 1}},
				lean: map[string]any{"choice": map[string]any{"c": "a", "conf": int64(diffUnit)}}}
		case 19:
			ans = genAnswer{wire: map[string]any{"type": "noul", "noul": 1.5}, lean: map[string]any{"yesNo": int64(diffUnit) * 3 / 2}}
		}
	case 1:
		opts := map[string]string{"a": "A", "b": "B", "c": "C"}
		names := []string{"a", "b", "c"}
		pick := func() []string {
			var out []string
			for _, o := range append(names, "z") {
				if r.IntN(3) == 0 && (o != "z" || r.IntN(4) == 0) {
					out = append(out, o)
				}
			}
			return out
		}
		allow, deny := pick(), pick()
		mc, mcL := optBound(r, gridP, 10_000)
		p.Decision = &AiDecision{Choice: &AiChoice{Instructions: "q", Options: opts, Allow: allow, Deny: deny, MinConfidence: mc}}
		j.Decision = map[string]any{"choice": map[string]any{"options": names, "allow": nonNil(allow), "deny": nonNil(deny), "minConf": mcL}}
		c := names[r.IntN(3)]
		cf, cl := gridP(r.IntN(10_001))
		if mc != nil && r.IntN(3) == 0 {
			cf, cl = *mc, mcL.(int64)
		}
		probs := map[string]float64{"a": 0, "b": 0, "c": 0}
		probs[c] = 1
		ans = genAnswer{wire: map[string]any{"type": "choice", "choice": c, "confidence": cf, "probabilities": probs},
			lean: map[string]any{"choice": map[string]any{"c": c, "conf": cl}}}
		switch answerClass {
		case 18:
			ans = genAnswer{wire: map[string]any{"type": "noul", "noul": 0.5}, lean: map[string]any{"yesNo": int64(diffUnit / 2)}}
		case 19:
			probs := map[string]float64{"a": 1, "b": 0, "c": 0}
			ans = genAnswer{wire: map[string]any{"type": "choice", "choice": "zz", "confidence": 0.5, "probabilities": probs},
				lean: map[string]any{"choice": map[string]any{"c": "zz", "conf": int64(diffUnit / 2)}}}
		}
	default:
		lv := 1 + r.IntN(4)
		levels := make([]string, lv)
		legend := map[string]string{}
		for i := range levels {
			levels[i] = fmt.Sprintf("L%d", i)
			legend[strconv.Itoa(i)] = levels[i]
		}
		top := (lv - 1) * 100
		mn, mnL := optBound(r, gridS, top+30)
		mx, mxL := optBound(r, gridS, top+30)
		p.Decision = &AiDecision{Score: &AiScore{Instructions: "q", Levels: levels, MinScore: mn, MaxScore: mx}}
		j.Decision = map[string]any{"score": map[string]any{"levels": lv, "min": mnL, "max": mxL}}
		m := r.IntN(top + 1)
		sf, sl := gridS(m)
		if mn != nil && r.IntN(3) == 0 && mnL.(int64) <= int64(top)*(diffUnit/100) {
			sf, sl = *mn, mnL.(int64)
			m = int(sl / (diffUnit / 100))
		}
		probs := map[string]float64{}
		for i := range levels {
			probs[strconv.Itoa(i)] = 0
		}
		lo := m / 100
		frac := float64(m%100) / 100
		probs[strconv.Itoa(lo)] = 1 - frac
		if frac > 0 {
			probs[strconv.Itoa(lo+1)] = frac
		}
		ans = genAnswer{wire: map[string]any{"type": "score", "score": sf, "confidence": 0.9, "probabilities": probs, "legend": legend},
			lean: map[string]any{"score": sl}}
		switch answerClass {
		case 18:
			ans = genAnswer{wire: map[string]any{"type": "noul", "noul": 0.5}, lean: map[string]any{"yesNo": int64(diffUnit / 2)}}
		case 19:
			of, ol := gridS(top + 100)
			ans = genAnswer{wire: map[string]any{"type": "score", "score": of, "confidence": 0.9, "probabilities": probs, "legend": legend},
				lean: map[string]any{"score": ol}}
		}
	}
	switch answerClass {
	case 16:
		ans = genAnswer{omit: true, lean: "missing"}
	case 17:
		ans = genAnswer{wire: nil, lean: "bad"}
	}
	return genPolicy{pol: p, json: j, ans: ans}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// jevCase is one AI case: request-level behaviour plus per-question answers.
type jevCase struct {
	class    string // ok | transport | http | malformed
	code     int
	resolved string // echo | other | missing
	byName   map[string]genAnswer
}

func jevDiffServer(t *testing.T, cur **jevCase) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c := *cur
		var body struct {
			Model     string                     `json:"model"`
			Questions map[string]json.RawMessage `json:"questions"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		switch c.class {
		case "transport":
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					_ = conn.Close()
					return
				}
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		case "http":
			w.WriteHeader(c.code)
			_, _ = w.Write([]byte(`{"detail":"nope"}`))
			return
		case "malformed":
			_, _ = w.Write([]byte(`{"model":`))
			return
		}
		answers := map[string]any{}
		for name := range body.Questions {
			a := c.byName[name]
			if a.omit {
				continue
			}
			answers[name] = a.wire
		}
		env := map[string]any{"answers": answers}
		switch c.resolved {
		case "echo":
			env["model"] = body.Model
		case "other":
			env["model"] = "jev-9.9.9"
		}
		b, _ := json.Marshal(env)
		_, _ = w.Write(b)
	}))
}

func TestFormalDifferentialAI(t *testing.T) {
	bin := diffOracle(t)
	r := rand.New(rand.NewPCG(uint64(diffEnvInt("FORMAL_DIFF_SEED", 1)), 11))
	n := diffEnvInt("FORMAL_DIFF_N", 600)
	var cur *jevCase
	srv := jevDiffServer(t, &cur)
	defer srv.Close()
	provider := NewJevProvider("differential-key")
	att := regoAttestor(0, "https://example.com/t", false)

	var cases []any
	var goV, details []string
	for i := 0; i < n; i++ {
		k := 1 + r.IntN(3)
		var gps []genPolicy
		for q := 0; q < k; q++ {
			name := fmt.Sprintf("q%d", q)
			if q > 0 && r.IntN(20) == 0 {
				name = "q0" // duplicate name: an invalid set
			}
			gps = append(gps, genAiPolicy(r, name))
		}
		c := &jevCase{class: "ok", resolved: "echo", byName: map[string]genAnswer{}}
		switch x := r.IntN(20); {
		case x == 0:
			c.class = "transport"
		case x == 1:
			c.class, c.code = "http", []int{400, 401, 429, 500}[r.IntN(4)]
		case x == 2:
			c.class = "malformed"
		}
		switch x := r.IntN(20); {
		case x == 0:
			c.resolved = "other"
		case x == 1:
			c.resolved = "missing"
		}
		var pols []AiPolicy
		var items []aiItemJSON
		for _, g := range gps {
			pols = append(pols, g.pol)
			c.byName[g.pol.Name] = g.ans
			var reply map[string]any
			switch c.class {
			case "transport":
				reply = map[string]any{"t": "transport"}
			case "http":
				reply = map[string]any{"t": "http", "code": c.code}
			case "malformed":
				reply = map[string]any{"t": "malformed"}
			default:
				reply = map[string]any{"t": "envelope", "ans": g.ans.lean}
				switch c.resolved {
				case "echo":
					reply["resolved"] = g.json.Model
				case "other":
					reply["resolved"] = modelJSON{Pinned: []int{9, 9, 9}}
				}
			}
			items = append(items, aiItemJSON{Policy: g.json, Reply: reply})
		}
		cur = c
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resps, err := EvaluateAIPolicyWithProvider(ctx, att, pols, srv.URL, provider)
		cancel()
		v := classifyGoErr(err)
		if err == nil {
			for _, rs := range resps {
				if rs.Status == AiStatusFail {
					v = "deny"
				}
			}
		}
		goV = append(goV, v)
		cases = append(cases, aiCaseJSON{Kind: "ai", Items: items})
		pj, _ := json.Marshal(items)
		details = append(details, fmt.Sprintf("class=%s resolved=%s err=%v items=%s", c.class, c.resolved, err, pj))
	}
	lean := runOracle(t, bin, cases)
	var ms []diffMismatch
	for i := range cases {
		if goV[i] != lean[i] {
			ms = append(ms, diffMismatch{"ai", goV[i], lean[i], details[i]})
		}
	}
	reportMismatches(t, "ai", ms, len(cases))
}

// ---------------------------------------------------------------------------
// Step gate (gateOneContext) with Rego and an in-process batch provider
// ---------------------------------------------------------------------------

type stubOutcome struct {
	rs  []AiResponse
	err error
}

// stubProvider answers each (attestor ref, policy set) with a fixed outcome,
// honouring the provider contract or not, so the gate combinator itself is
// what is compared.
type stubProvider struct{ out map[string]stubOutcome }

func (s *stubProvider) key(att attestation.Attestor, pols []AiPolicy) string {
	b, _ := json.Marshal(att)
	var body struct {
		Ref int `json:"ref"`
	}
	_ = json.Unmarshal(b, &body)
	typ := ""
	if len(pols) > 0 {
		typ = strings.SplitN(pols[0].Name, "/", 2)[0]
	}
	return fmt.Sprintf("%d|%s", body.Ref, typ)
}

func (s *stubProvider) Evaluate(ctx context.Context, att attestation.Attestor, pol AiPolicy, url string) (AiResponse, error) {
	rs, err := s.EvaluateBatch(ctx, att, []AiPolicy{pol}, url)
	if len(rs) == 0 {
		return AiResponse{}, err
	}
	return rs[0], err
}

func (s *stubProvider) EvaluateBatch(_ context.Context, att attestation.Attestor, pols []AiPolicy, _ string) ([]AiResponse, error) {
	o := s.out[s.key(att, pols)]
	return o.rs, o.err
}

type gateExpectedJSON struct {
	Type string         `json:"type"`
	Rego []regoModJSON  `json:"rego"`
	AI   []aiPolicyJSON `json:"ai"`
}

type gateAttJSON struct {
	Ref  int    `json:"ref"`
	Type string `json:"type"`
}

type gateOutcomeJSON struct {
	Rs  []map[string]string `json:"rs"`
	Err any                 `json:"err"`
}

type gateRunJSON struct {
	Ref   int             `json:"ref"`
	Type  string          `json:"type"`
	Fault bool            `json:"fault"`
	Deny  []denyJSON      `json:"deny"`
	AI    gateOutcomeJSON `json:"ai"`
}

type gateCaseJSON struct {
	Kind      string `json:"kind"`
	RejectDup bool   `json:"rejectDup"`
	Step      struct {
		Name     string             `json:"name"`
		Expected []gateExpectedJSON `json:"expected"`
	} `json:"step"`
	Collection struct {
		Name      string        `json:"name"`
		Errors    bool          `json:"errors"`
		Attestors []gateAttJSON `json:"attestors"`
	} `json:"collection"`
	Runs []gateRunJSON `json:"runs"`
}

func genStubOutcome(r *rand.Rand, npol int) (stubOutcome, gateOutcomeJSON) {
	var o stubOutcome
	var j gateOutcomeJSON
	switch r.IntN(8) {
	case 0:
		o.err, j.Err = ErrAIEvaluationRefused{Code: "provider_unavailable"}, "refusal"
	case 1:
		o.err, j.Err = ErrPolicyDenied{Reasons: []string{"no"}}, "denied"
	case 2:
		o.err, j.Err = errors.New("boom"), "other"
	}
	count := npol
	if r.IntN(8) == 0 {
		count = r.IntN(npol + 1) // a provider that breaks the contract
	}
	statuses := []string{AiStatusPass, AiStatusPass, AiStatusPass, AiStatusFail, "", "pass"}
	j.Rs = []map[string]string{}
	for i := 0; i < count; i++ {
		st := statuses[r.IntN(len(statuses))]
		o.rs = append(o.rs, AiResponse{Status: st})
		j.Rs = append(j.Rs, map[string]string{"status": st})
	}
	return o, j
}

//nolint:gocyclo,funlen // builds one random step, collection and per-attestor evaluator outcomes
func TestFormalDifferentialGate(t *testing.T) {
	bin := diffOracle(t)
	r := rand.New(rand.NewPCG(uint64(diffEnvInt("FORMAL_DIFF_SEED", 1)), 13))
	n := diffEnvInt("FORMAL_DIFF_N", 600)
	saved := Hardening()
	defer SetHardening(saved)

	var cases []any
	var goV, details []string
	for i := 0; i < n; i++ {
		var c gateCaseJSON
		c.Kind = "gate"
		c.RejectDup = r.IntN(2) == 0
		SetHardening(HardeningOptions{RejectDuplicateRegoPackage: c.RejectDup})
		c.Step.Name = "build"
		step := Step{Name: "build"}
		owners := map[string]map[string]denyKind{}
		ntypes := r.IntN(3) // 0: a step with no requirements
		for ti := 0; ti < ntypes; ti++ {
			typ := fmt.Sprintf("t%d", ti)
			var pols []RegoPolicy
			var mods []regoModJSON
			if r.IntN(3) > 0 {
				pols, mods, owners[typ] = genRegoModules(r, false)
			} else {
				owners[typ] = map[string]denyKind{}
			}
			var ai []AiPolicy
			var aiJ []aiPolicyJSON
			for q := 0; q < r.IntN(3); q++ {
				name := fmt.Sprintf("%s/q%d", typ, q)
				mn := 0.5
				pol := AiPolicy{Name: name, Model: "jev-1.13.0", Decision: &AiDecision{YesNo: &AiYesNo{
					Instructions: "q", Criteria: map[string]string{"true": "y", "false": "n"}, MinProbability: &mn}}}
				ai = append(ai, pol)
				aiJ = append(aiJ, aiPolicyJSON{Name: name, Model: modelJSON{Pinned: []int{1, 13, 0}},
					Decision: map[string]any{"yesNo": map[string]any{"min": int64(diffUnit / 2), "max": nil}}})
			}
			step.Attestations = append(step.Attestations, Attestation{Type: typ, RegoPolicies: pols, AiPolicies: ai})
			c.Step.Expected = append(c.Step.Expected, gateExpectedJSON{Type: typ, Rego: nonNilMods(mods), AI: nonNilPols(aiJ)})
		}
		c.Collection.Name = "build"
		if r.IntN(10) == 0 {
			c.Collection.Name = "other"
		}
		coll := source.CollectionVerificationResult{}
		coll.Collection.Name = c.Collection.Name
		if r.IntN(10) == 0 {
			c.Collection.Errors = true
			coll.Errors = []error{errors.New("signature did not verify")}
		}
		stub := &stubProvider{out: map[string]stubOutcome{}}
		ref := 0
		c.Collection.Attestors = []gateAttJSON{}
		for _, typ := range []string{"t0", "t1", "t9"} {
			for k := 0; k < r.IntN(3); k++ {
				ref++
				hasRef := r.IntN(2) == 0
				coll.Collection.Attestations = append(coll.Collection.Attestations,
					attestation.CollectionAttestation{Type: typ, Attestation: regoAttestor(ref, typ, hasRef)})
				c.Collection.Attestors = append(c.Collection.Attestors, gateAttJSON{Ref: ref, Type: typ})
				owner := owners[typ]
				deny, fault := regoRunJSON(owner, hasRef)
				npol := 0
				for _, a := range step.Attestations {
					if a.Type == typ {
						npol = len(a.AiPolicies)
					}
				}
				so, oj := genStubOutcome(r, npol)
				stub.out[fmt.Sprintf("%d|%s", ref, typ)] = so
				c.Runs = append(c.Runs, gateRunJSON{Ref: ref, Type: typ, Fault: fault, Deny: nonNilDeny(deny), AI: oj})
			}
		}
		if c.Step.Expected == nil {
			c.Step.Expected = []gateExpectedJSON{}
		}
		if c.Runs == nil {
			c.Runs = []gateRunJSON{}
		}
		outcome, _, rc := step.gateOneContext(context.Background(), coll, "", nil, stub)
		var v string
		switch outcome {
		case gateWrongName:
			v = "wrongName"
		case gatePassed:
			v = "passed"
		default:
			var refusal ErrAIEvaluationRefused
			v = fmt.Sprintf("rejected:%v", errors.As(rc.Reason, &refusal))
		}
		goV = append(goV, v)
		cases = append(cases, c)
		cj, _ := json.Marshal(c)
		details = append(details, string(cj))
	}
	lean := runOracle(t, bin, cases)
	var ms []diffMismatch
	for i := range cases {
		if goV[i] != lean[i] {
			ms = append(ms, diffMismatch{"gate", goV[i], lean[i], details[i]})
		}
	}
	reportMismatches(t, "gate", ms, len(cases))
}

func nonNilMods(m []regoModJSON) []regoModJSON {
	if m == nil {
		return []regoModJSON{}
	}
	return m
}

func nonNilPols(p []aiPolicyJSON) []aiPolicyJSON {
	if p == nil {
		return []aiPolicyJSON{}
	}
	return p
}

func nonNilDeny(d []denyJSON) []denyJSON {
	if d == nil {
		return []denyJSON{}
	}
	return d
}

// ---------------------------------------------------------------------------
// VSA consumption through external attestations (VerifyWithExternals)
// ---------------------------------------------------------------------------

type vsaJSON struct {
	Subjects     []string `json:"subjects"`
	PolicyURI    string   `json:"policyUri"`
	PolicyDigest string   `json:"policyDigest"`
	TimeVerified int64    `json:"timeVerified"`
	Result       string   `json:"result"`
}

type vsaCandJSON struct {
	VSA    vsaJSON `json:"vsa"`
	Signer string  `json:"signer"`
	SigOK  bool    `json:"sigOk"`
}

type vsaExtJSON struct {
	Required   bool          `json:"required"`
	Consumer   string        `json:"consumer"`
	Expected   string        `json:"expected"`
	Candidates []vsaCandJSON `json:"candidates"`
}

type vsaCaseJSON struct {
	Kind      string       `json:"kind"`
	Requested string       `json:"requested"`
	Allowed   []string     `json:"allowed"`
	Now       int64        `json:"now"`
	Window    int64        `json:"window"`
	Externals []vsaExtJSON `json:"externals"`
}

func consumerRego(kind, expected string, now, window int64) []RegoPolicy {
	switch kind {
	case "resultOnly":
		return []RegoPolicy{{Name: "c", Module: []byte("package c\n\ndeny[msg] { input.verificationResult != \"PASSED\"; msg := \"result\" }\n")}}
	case "exact":
		nowNs := now * int64(time.Second)
		oldest := (now - window) * int64(time.Second)
		return []RegoPolicy{{Name: "c", Module: []byte(fmt.Sprintf(`package c

deny[msg] { input.verificationResult != "PASSED"; msg := "result" }
deny[msg] { input.policy.digest.sha256 != %q; msg := "digest" }
deny[msg] { t := time.parse_rfc3339_ns(input.timeVerified); t > %d; msg := "future" }
deny[msg] { t := time.parse_rfc3339_ns(input.timeVerified); t < %d; msg := "stale" }
`, expected, nowNs, oldest))}}
	}
	return nil
}

//nolint:gocyclo,funlen // builds one random externals-only policy and its candidate VSAs
func TestFormalDifferentialVSA(t *testing.T) {
	bin := diffOracle(t)
	r := rand.New(rand.NewPCG(uint64(diffEnvInt("FORMAL_DIFF_SEED", 1)), 17))
	n := diffEnvInt("FORMAL_DIFF_N", 600)
	verA, keyA := newECDSAVerifier(t)
	verB, _ := newECDSAVerifier(t)
	const now, window = int64(1_900_000_000), int64(3600)
	const requested = "art"

	var cases []any
	var goV, details []string
	for i := 0; i < n; i++ {
		c := vsaCaseJSON{Kind: "vsa", Requested: requested, Allowed: []string{"A"}, Now: now, Window: window}
		var cands []vsaCandJSON
		var envs []source.StatementEnvelope
		for k := 0; k < r.IntN(4); k++ {
			subj := []string{requested}
			if r.IntN(5) == 0 {
				subj = []string{"elsewhere"}
			}
			digest := []string{"d1", "d2"}[r.IntN(2)]
			subj = append(subj, digest) // the policy subject (policyverify.go Subjects)
			result := []string{"PASSED", "FAILED"}[r.IntN(2)]
			tv := now - window*2 + r.Int64N(window*3)
			if r.IntN(4) == 0 {
				tv = now - window // exactly at the window edge
			}
			signer := []string{"A", "B"}[r.IntN(2)]
			sigOK := r.IntN(10) != 0
			cj := vsaCandJSON{VSA: vsaJSON{Subjects: subj, PolicyURI: "https://aflock.ai/policy/v0.1", PolicyDigest: digest, TimeVerified: tv, Result: result}, Signer: signer, SigOK: sigOK}
			cands = append(cands, cj)

			pred, _ := json.Marshal(map[string]any{
				"verifier":           map[string]string{"id": "aflock"},
				"timeVerified":       time.Unix(tv, 0).UTC().Format(time.RFC3339),
				"policy":             map[string]any{"uri": cj.VSA.PolicyURI, "digest": map[string]string{"sha256": digest}},
				"inputAttestations":  []any{},
				"verificationResult": result,
			})
			var subjects []intoto.Subject
			for _, s := range subj {
				subjects = append(subjects, intoto.Subject{Name: s, Digest: map[string]string{"sha256": s}})
			}
			stmt := intoto.Statement{Type: intoto.StatementType, PredicateType: vsaPredicateType, Subject: subjects, Predicate: pred}
			payload, _ := json.Marshal(stmt)
			env := source.StatementEnvelope{
				Envelope:  dsse.Envelope{Payload: payload, PayloadType: intoto.PayloadType},
				Statement: stmt,
				Attestor:  attestation.NewRawAttestation(vsaPredicateType, pred),
				Reference: fmt.Sprintf("vsa-%d-%d", i, k),
			}
			bound := subj[0] == requested
			switch {
			case !bound:
				// The verified source's substitution guard (source/verified.go).
				env.Errors = []error{source.ErrExternalSubjectNotRequested}
			case !sigOK:
				env.Errors = []error{errors.New("signature did not verify")}
			default:
				if signer == "A" {
					env.Verifiers = []cryptoutil.Verifier{verA}
				} else {
					env.Verifiers = []cryptoutil.Verifier{verB}
				}
			}
			envs = append(envs, env)
		}
		if cands == nil {
			cands = []vsaCandJSON{}
		}
		p := Policy{Expires: futureExpiry(), ExternalAttestations: map[string]ExternalAttestation{}}
		for e := 0; e < 1+r.IntN(2); e++ {
			consumer := []string{"none", "resultOnly", "exact"}[r.IntN(3)]
			expected := []string{"d1", "d2"}[r.IntN(2)]
			required := r.IntN(3) > 0
			name := fmt.Sprintf("e%d", e)
			p.ExternalAttestations[name] = ExternalAttestation{
				Name: name, PredicateType: vsaPredicateType, Required: required,
				Functionaries: []Functionary{{PublicKeyID: keyA}},
				RegoPolicies:  consumerRego(consumer, expected, now, window),
			}
			c.Externals = append(c.Externals, vsaExtJSON{Required: required, Consumer: consumer, Expected: expected, Candidates: cands})
		}
		src := &stepAwareVerifiedSource{byPredicate: map[string][]source.StatementEnvelope{vsaPredicateType: envs}}
		pass, _, _, err := p.VerifyWithExternals(context.Background(), WithVerifiedSource(src), WithSubjectDigests([]string{"sha256:" + requested}))
		var v string
		if err != nil {
			var refusal ErrAIEvaluationRefused
			v = fmt.Sprintf("failed:%v", errors.As(err, &refusal))
		} else {
			v = fmt.Sprintf("accepted:%v", pass)
		}
		goV = append(goV, v)
		cases = append(cases, c)
		cj, _ := json.Marshal(c)
		details = append(details, fmt.Sprintf("err=%v case=%s", err, cj))
	}
	lean := runOracle(t, bin, cases)
	var ms []diffMismatch
	for i := range cases {
		if goV[i] != lean[i] {
			ms = append(ms, diffMismatch{"vsa", goV[i], lean[i], details[i]})
		}
	}
	reportMismatches(t, "vsa", ms, len(cases))
}
