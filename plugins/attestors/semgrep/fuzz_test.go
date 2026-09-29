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

//go:build audit

package semgrep

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// FuzzReportAttest drives arbitrary bytes through the real attestor: Attest
// must never panic, and whenever it accepts a report every semgrep:finding
// subject must be a 64-hex id that appears on a live finding in the Summary.
func FuzzReportAttest(f *testing.F) {
	f.Add(`{"version":"1.119.0","results":[],"errors":[],"paths":{"scanned":[]}}`)
	f.Add(`{"version":"1.119.0","results":[{"check_id":"r","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":2},"extra":{"message":"m","metadata":{"cwe":"CWE-89"},"severity":"ERROR","fingerprint":"requires login","lines":"requires login"}}],"errors":[],"paths":{"scanned":["a.py"]}}`)
	f.Add(`{"results":[{"path":"a.py"}],"errors":[],"paths":{}}`)
	f.Add(`{"version":"1.119.0","results":[],"errors":[{"code":2,"level":"error","type":"SemgrepError","message":"rule failed"}],"paths":{"scanned":[]}}`)
	f.Add(`{"results":"nope","errors":[],"paths":{}}`)
	f.Add(`{"version":"1.119.0","results":[{"check_id":"r","path":"a.py"`)
	f.Add(`{"results":[],"errors":[],"paths":{"scanned":["a.py"]},"results":[{"check_id":"r","path":"a.py","start":{"line":1}}]}`)
	f.Add(`{"x":1e400,"results":[{"check_id":"r","path":"a.py","start":{"line":1}}],"errors":[],"paths":{"scanned":[]}}`)
	f.Add(`{"results":[],"errors":[{"code":2,"level":"warn","type":[ "Timeout",  {"b":1, "a":2} ],"message":"m"}],"paths":{"scanned":[]}}`)
	f.Add(`{"totally":"unrelated"}`)
	f.Add(`[]`)
	f.Add(`null`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, raw string) {
		ctx := contextWithFiles(t, map[string][]byte{"semgrep.json": []byte(raw)})
		a := New()
		if err := a.Attest(ctx); err != nil {
			// Refusing is always legal, but a document encoding/json reads as
			// Semgrep output must never be skipped as "not a report".
			if attestation.IsSoftError(err) && decodesAsSemgrep([]byte(raw)) {
				t.Fatalf("the decoder reads Semgrep output but it was skipped: %v: %q", err, raw)
			}
			return
		}
		// A report that does not decode whole (cut off mid-write) is never signed.
		if !json.Valid([]byte(raw)) {
			t.Fatalf("attested a report that is not valid JSON: %q", raw)
		}
		// One view: the signed Summary is exactly what a stock encoding/json
		// reading of the verbatim report yields. Any divergence between the
		// attestor's parse and the decoder a verifier uses fails here.
		var stock cliOutput
		if err := json.Unmarshal(a.Report, &stock); err != nil {
			t.Fatalf("attested report the stock decoder rejects: %v: %q", err, raw)
		}
		want, _ := json.Marshal(buildSummary(stock, ctx.Materials(), ctx.WorkingDir()))
		got, _ := json.Marshal(a.Summary)
		if string(want) != string(got) {
			t.Fatalf("signed summary differs from the stock decoder's reading of the report:\nsigned %s\nstock  %s\ninput  %q", got, want, raw)
		}
		live := map[string]bool{}
		for _, fd := range a.Summary.Findings {
			if !fd.IsIgnored {
				live[fd.ID] = true
			}
		}
		for key := range a.Subjects() {
			if !strings.HasPrefix(key, "semgrep:finding:") {
				continue
			}
			id := strings.TrimPrefix(key, "semgrep:finding:")
			if len(id) != 64 {
				t.Fatalf("finding subject is not 64-hex: %q", key)
			}
			if !live[id] {
				t.Fatalf("finding subject %q has no live finding in the summary", id)
			}
			if strings.Contains(key, "requires login") {
				t.Fatalf("login placeholder leaked into a subject: %q", key)
			}
		}
		if a.Summary.TotalFindings != len(a.Summary.Findings) {
			t.Fatalf("totalFindings %d != len(findings) %d", a.Summary.TotalFindings, len(a.Summary.Findings))
		}
		// Every accepted finding carries the identity the sniff requires.
		for _, fd := range a.Summary.Findings {
			if fd.RuleID == "" || fd.Path == "" || fd.StartLine < 1 {
				t.Fatalf("accepted a finding without identity: %+v", fd)
			}
		}
		// Fail closed: ANY errors[] entry, at any level, must mark the scan
		// incomplete — removing that guard would leave this fuzzer red.
		if len(a.Summary.Errors) > 0 && a.Summary.ScanComplete {
			t.Fatalf("errors[] is non-empty (%d) but scanComplete is true", len(a.Summary.Errors))
		}
	})
}

// FuzzStringList: any JSON value decodes without error into a list of only
// the string members.
func FuzzStringList(f *testing.F) {
	f.Add(`"CWE-89"`)
	f.Add(`["CWE-89","CWE-78"]`)
	f.Add(`["a",1,null,{"x":1}]`)
	f.Add(`{"not":"list"}`)
	f.Add(`42`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, raw string) {
		var s stringList
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			// Only a syntactically invalid document may error; a valid one of
			// any shape must decode.
			if json.Valid([]byte(raw)) {
				t.Fatalf("valid JSON %q errored: %v", raw, err)
			}
		}
	})
}

// FuzzNormalizeSeverity: the output is always one of the known buckets.
func FuzzNormalizeSeverity(f *testing.F) {
	for _, s := range []string{"ERROR", "WARNING", "HIGH", "critical", "", "bogus"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		switch normalizeSeverity(in) {
		case sevCritical, sevHigh, sevMedium, sevLow, sevInfo, sevUnknown:
		default:
			t.Fatalf("normalizeSeverity(%q) returned an unknown bucket", in)
		}
	})
}
