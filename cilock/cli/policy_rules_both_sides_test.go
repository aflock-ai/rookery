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

import "testing"

// fullblind49 and fullblind50 never delivered: a Pushgate refusal read
// "unexpected command argv: [...]" and the agent could not tell what its own
// rule wanted. Every seeded rule that compares evidence against a value the
// author pinned must print both sides: what the rule requires, and what the
// evidence held.

func TestCommandPinDenyPrintsExpectedAndGot(t *testing.T) {
	requireDenied(t,
		evalRule(t, ruleCommandPin, `["go","vet","./..."]`,
			map[string]any{"cmd": []any{"sh", "-c", "go vet ./... > vet.txt"}}, nil),
		`command must be ["go", "vet", "./..."]; got ["sh", "-c", "go vet ./... > vet.txt"]`)
}

func TestTrivyDenyPrintsTheBlockedSeverities(t *testing.T) {
	pred := map[string]any{"summary": map[string]any{"bySeverity": map[string]any{"critical": map[string]any{"fail": 2}}}}
	requireDenied(t, evalRule(t, ruleTrivySeverity, `["critical","high"]`, pred, nil),
		`trivy: 2 failed critical finding(s); this rule blocks every finding at ["critical", "high"]`)
}

func TestTraceAllowlistDeniesPrintTheAllowlist(t *testing.T) {
	paths := []string{"/usr/bin/make", "/work/app/out.o"}
	proc := func(extra map[string]any) map[string]any {
		p := map[string]any{"processid": 7, "execPathId": 0, "exeDigestId": 0, "programDigestId": 0}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	conn := map[string]any{"network": map[string]any{"connections": []any{
		map[string]any{"syscall": "connect", "family": "AF_INET", "address": "93.184.216.34", "port": 443, "hostname": "evil.example"},
	}}}
	requireDenied(t, evalRule(t, ruleTraceNetwork, `["10.0.0.53","172.16.4.10"]`, v02([]map[string]any{proc(conn)}, paths, []string{"d0"}), nil),
		`is not in the allowlist ["10.0.0.53", "172.16.4.10"]`)

	dns := map[string]any{"network": map[string]any{"dnsLookups": []any{map[string]any{"serverAddress": "8.8.8.8"}}}}
	requireDenied(t, evalRule(t, ruleTraceNetwork, `["1.1.1.1"]`, v02([]map[string]any{proc(dns)}, paths, []string{"d0"}), nil),
		`DNS lookup via 8.8.8.8 is not in the allowlist ["1.1.1.1"]`)

	requireDenied(t, evalRule(t, ruleTraceExec, `["/usr/bin/cc"]`, v02([]map[string]any{proc(nil)}, paths, []string{"d0"}), nil),
		`process 7 ran /usr/bin/make, which is not in the allowlist ["/usr/bin/cc"]`)

	w := map[string]any{"fileOps": map[string]any{"writes": []any{map[string]any{"path": "/tmp/x"}}}}
	requireDenied(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(w)}, paths, []string{"d0"}), nil),
		`writes: /tmp/x was modified outside the allowed paths ["/work/app/"]`)
}
