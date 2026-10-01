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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"

	// Register the attestors whose predicate types the catalog names, so the
	// catalog can be checked against the registry that records them.
	_ "github.com/aflock-ai/rookery/plugins/attestors/github-review"
	_ "github.com/aflock-ai/rookery/plugins/attestors/govulncheck"
	_ "github.com/aflock-ai/rookery/plugins/attestors/k8smanifest"
	_ "github.com/aflock-ai/rookery/plugins/attestors/sarif"
	_ "github.com/aflock-ai/rookery/plugins/attestors/secretscan"
	_ "github.com/aflock-ai/rookery/plugins/attestors/slsa"
	_ "github.com/aflock-ai/rookery/plugins/attestors/test-results"
	_ "github.com/aflock-ai/rookery/plugins/attestors/trivy"
	_ "github.com/aflock-ai/rookery/plugins/attestors/vex"
)

func TestProductAndProvenanceRules(t *testing.T) {
	require.NoError(t, evalRule(t, ruleProductRecorded, "", map[string]any{"treeSize": 2, "merkleRoot": "ab"}, nil))
	requireDenied(t, evalRule(t, ruleProductRecorded, "", map[string]any{"treeSize": 0, "merkleRoot": ""}, nil), "recorded no products")
	dep := map[string]any{"uri": "git+https://x", "digest": map[string]any{"sha1": "0123456789abcdef0123456789abcdef01234567"}}
	require.NoError(t, evalRule(t, ruleSLSAProvenance, "", map[string]any{"buildDefinition": map[string]any{"resolvedDependencies": []any{dep}}}, nil))
	// A digest object is not a digest: each shape below names no input.
	for name, dg := range map[string]any{
		"empty object":        map[string]any{},
		"empty value":         map[string]any{"sha256": ""},
		"non-hex value":       map[string]any{"sha256": "not-a-digest-not-a-digest-not-a-digest"},
		"short value":         map[string]any{"sha1": "a"},
		"number value":        map[string]any{"sha256": 1},
		"one bad beside good": map[string]any{"sha1": "0123456789abcdef0123456789abcdef01234567", "sha256": ""},
		"uppercase hex":       map[string]any{"sha1": "0123456789ABCDEF0123456789ABCDEF01234567"},
		"array not object":    []any{"0123456789abcdef0123456789abcdef01234567"},
	} {
		bad := map[string]any{"uri": "u", "digest": dg}
		requireDenied(t, evalRule(t, ruleSLSAProvenance, "", map[string]any{"buildDefinition": map[string]any{"resolvedDependencies": []any{dep, bad}}}, nil), "u has no digest", name)
	}
	requireDenied(t, evalRule(t, ruleSLSAProvenance, "", map[string]any{"buildDefinition": map[string]any{"resolvedDependencies": []any{}}}, nil), "names no build inputs")
	requireDenied(t, evalRule(t, ruleSLSAProvenance, "", map[string]any{"buildDefinition": map[string]any{"resolvedDependencies": []any{map[string]any{"uri": "u"}}}}, nil), "u has no digest")
	require.NoError(t, evalRule(t, ruleSBOMInventory, "", map[string]any{"_sbomFormat": "cyclonedx", "components": []any{map[string]any{"name": "x"}}}, nil))
	requireDenied(t, evalRule(t, ruleSBOMInventory, "", map[string]any{"_sbomFormat": "spdx", "packages": []any{}}, nil), "lists no components")
	requireDenied(t, evalRule(t, ruleSBOMInventory, "", map[string]any{"_sbomFormat": "cyclonedx", "packages": []any{1}}, nil), "unreadable evidence")
}

func TestSecretscanAndTrivyAndReviewRules(t *testing.T) {
	require.NoError(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{}}, nil))
	require.NoError(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{}, "scope": map[string]any{"files": "diff"}}, nil))
	requireDenied(t, evalRule(t, ruleSecretscanClean, "", map[string]any{"findings": []any{map[string]any{"ruleId": "aws-key", "location": "file:a.go"}}}, nil), "rule aws-key at file:a.go")
	by := func(n int) map[string]any {
		return map[string]any{"summary": map[string]any{"bySeverity": map[string]any{"critical": map[string]any{"fail": n}}}}
	}
	require.NoError(t, evalRule(t, ruleTrivySeverity, `["critical","high"]`, by(0), nil))
	requireDenied(t, evalRule(t, ruleTrivySeverity, `["critical","high"]`, by(2), nil), "2 failed critical")
	// Codex round 8 on #10195: a count below zero is not a count of zero.
	requireDenied(t, evalRule(t, ruleTrivySeverity, `["critical","high"]`, by(-1), nil), "unreadable evidence: trivy bySeverity.critical.fail is -1, not a count")
	_, err := renderRule(ruleTrivySeverity, json.RawMessage(`["severe"]`))
	require.Error(t, err)
	review := func(state, commit string) map[string]any {
		return map[string]any{"commit_sha": "c1", "prs": []any{map[string]any{"reviews": []any{map[string]any{"state": state, "commit_id": commit}}}}}
	}
	require.NoError(t, evalRule(t, ruleReviewApproved, "", review("APPROVED", "c1"), nil))
	requireDenied(t, evalRule(t, ruleReviewApproved, "", review("APPROVED", "c0"), nil), "no APPROVED review on commit c1")
	requireDenied(t, evalRule(t, ruleReviewApproved, "", map[string]any{"commit_sha": "c1", "prs": []any{}}, nil), "no APPROVED review")
	// An empty commit and a review with no commit_id are not a match.
	noID := map[string]any{"commit_sha": "", "prs": []any{map[string]any{"reviews": []any{map[string]any{"state": "APPROVED"}}}}}
	requireDenied(t, evalRule(t, ruleReviewApproved, "", noID, nil), "unreadable evidence")
	noID["commit_sha"] = "c1"
	requireDenied(t, evalRule(t, ruleReviewApproved, "", noID, nil), "no APPROVED review on commit c1")
}

// govulncheckPred builds a symbol-level govulncheck predicate with the given
// findings; aliases maps a GO id to the aliases its osv record carries.
func govulncheckPred(findings []map[string]any, aliases map[string][]string) map[string]any {
	reach, unreach := 0, 0
	fs := make([]any, 0, len(findings))
	for _, f := range findings {
		if f["reachable"] == true {
			reach++
		} else {
			unreach++
		}
		fs = append(fs, f)
	}
	report := make([]any, 0, len(aliases))
	for id, as := range aliases {
		list := make([]any, 0, len(as))
		for _, a := range as {
			list = append(list, a)
		}
		report = append(report, map[string]any{"osv": map[string]any{"id": id, "aliases": list}})
	}
	return map[string]any{
		"summary": map[string]any{"scanLevel": "symbol", "reachableCount": reach, "unreachableCount": unreach,
			"totalFindings": len(fs), "findings": fs, "scanRoots": []any{"example.com/app"}},
		"report": report,
	}
}

func vexSteps(statements ...map[string]any) map[string]any {
	st := make([]any, 0, len(statements))
	for _, s := range statements {
		st = append(st, s)
	}
	return map[string]any{"vex": map[string]any{"collections": []any{map[string]any{
		"attestations": map[string]any{typeVEX: map[string]any{"vexDocument": map[string]any{"statements": st}}},
	}}}}
}

func vexStatement(vuln, product, status, justification string) map[string]any {
	s := map[string]any{"vulnerability": map[string]any{"name": vuln}, "products": []any{map[string]any{"@id": product}}, "status": status}
	if justification != "" {
		s["justification"] = justification
	}
	return s
}

func TestGovulncheckVEXCoverage(t *testing.T) {
	const param = `{"vexStep":"vex","products":["pkg:golang/example.com/app"]}`
	const product = "pkg:golang/example.com/app"
	pred := govulncheckPred([]map[string]any{
		{"osvId": "GO-2024-0001", "reachable": false},
		{"osvId": "GO-2024-0002", "reachable": true},
	}, map[string][]string{"GO-2024-0001": {"CVE-2024-1111"}, "GO-2024-0002": {"GHSA-aaaa-bbbb-cccc"}})

	t.Run("every finding covered admits", func(t *testing.T) {
		steps := vexSteps(
			vexStatement("CVE-2024-1111", product, "not_affected", "vulnerable_code_not_in_execute_path"),
			vexStatement("GHSA-aaaa-bbbb-cccc", product, "fixed", ""),
		)
		require.NoError(t, evalRule(t, ruleGovulncheckVEX, param, pred, steps))
	})
	t.Run("a finding named by its GO id is covered too", func(t *testing.T) {
		steps := vexSteps(
			vexStatement("GO-2024-0001", product, "fixed", ""),
			vexStatement("GO-2024-0002", product, "fixed", ""),
		)
		require.NoError(t, evalRule(t, ruleGovulncheckVEX, param, pred, steps))
	})
	t.Run("one uncovered finding refuses", func(t *testing.T) {
		steps := vexSteps(vexStatement("CVE-2024-1111", product, "not_affected", "vulnerable_code_not_in_execute_path"))
		requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, pred, steps), "GO-2024-0002 is not covered")
	})
	t.Run("not_affected without a justification refuses", func(t *testing.T) {
		steps := vexSteps(
			vexStatement("CVE-2024-1111", product, "not_affected", ""),
			vexStatement("GHSA-aaaa-bbbb-cccc", product, "fixed", ""),
		)
		requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, pred, steps), "GO-2024-0001 is not covered")
	})
	t.Run("affected and under_investigation refuse", func(t *testing.T) {
		for _, status := range []string{"affected", "under_investigation"} {
			steps := vexSteps(
				vexStatement("CVE-2024-1111", product, status, ""),
				vexStatement("GHSA-aaaa-bbbb-cccc", product, "fixed", ""),
			)
			requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, pred, steps), "GO-2024-0001 is not covered")
		}
	})
	t.Run("a statement for another product does not cover", func(t *testing.T) {
		steps := vexSteps(
			vexStatement("CVE-2024-1111", "pkg:golang/example.com/other", "fixed", ""),
			vexStatement("GHSA-aaaa-bbbb-cccc", product, "fixed", ""),
		)
		requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, pred, steps), "GO-2024-0001 is not covered")
	})
	t.Run("no readable VEX refuses", func(t *testing.T) {
		requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, pred, map[string]any{"other": map[string]any{}}), "no readable OpenVEX document from step vex")
	})
	t.Run("no findings admits with a VEX document present", func(t *testing.T) {
		clean := govulncheckPred(nil, nil)
		require.NoError(t, evalRule(t, ruleGovulncheckVEX, param, clean, vexSteps(vexStatement("CVE-2024-9", product, "fixed", ""))))
	})
	t.Run("a null findings list is clean only when every count is zero", func(t *testing.T) {
		noVEX := map[string]any{"other": map[string]any{}}
		summary := func(findings any, reach, unreach, total any) map[string]any {
			return map[string]any{"summary": map[string]any{"findings": findings, "reachableCount": reach,
				"unreachableCount": unreach, "totalFindings": total, "scanRoots": []any{"example.com/app"}}}
		}
		require.NoError(t, evalRule(t, ruleGovulncheckVEX, param, summary(nil, 0, 0, 0), noVEX))
		one := []any{map[string]any{"osvId": "GO-1", "reachable": true}}
		for name, pred := range map[string]map[string]any{
			"null list, reachable 3":                   summary(nil, 3, 0, 3),
			"null list, unreachable 1":                 summary(nil, 0, 1, 1),
			"null list, total 2":                       summary(nil, 0, 0, 2),
			"empty list, reachable 1":                  summary([]any{}, 1, 0, 1),
			"one finding, counts say two":              summary(one, 2, 0, 2),
			"one finding, total zero":                  summary(one, 1, 0, 0),
			"reachable finding counted as unreachable": summary(one, 0, 1, 1),
			"counts missing":                           {"summary": map[string]any{"findings": nil, "scanRoots": []any{"example.com/app"}}},
			"counts not numbers":                       summary(nil, "0", 0, 0),
		} {
			requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, pred, noVEX), "unreadable evidence", name)
		}
	})
}

// The nine cases attestation/policy/vex_per_vuln_test.go proves against the
// verifier, run through the seeded rule with no product constraint.
func TestGovulncheckVEXPassesTheVerifierProvenCases(t *testing.T) {
	const param = `{"vexStep":"vex","products":[]}`
	findings := func(ids ...string) map[string]any {
		fs := make([]any, 0, len(ids))
		for _, id := range ids {
			fs = append(fs, map[string]any{"osvId": id, "reachable": false})
		}
		return map[string]any{"summary": map[string]any{"findings": fs, "reachableCount": 0,
			"unreachableCount": len(fs), "totalFindings": len(fs), "scanRoots": []any{"example.com/app"}}}
	}
	vex := func(statements ...map[string]any) map[string]any { return vexSteps(statements...) }
	noVEX := map[string]any{"vex": map[string]any{"collections": []any{}}}
	notAffected := func(id string) map[string]any {
		return map[string]any{"vulnerability": map[string]any{"name": id}, "status": "not_affected",
			"justification": "vulnerable_code_not_in_execute_path"}
	}
	cases := []struct {
		name  string
		pred  map[string]any
		steps map[string]any
		admit bool
	}{
		{"three unreachable advisories, each explained", findings("GO-2026-5932", "GO-2026-6354", "GO-2026-6355"),
			vex(notAffected("GO-2026-5932"), notAffected("GO-2026-6354"), notAffected("GO-2026-6355")), true},
		{"one advisory without a statement", findings("GO-2026-5932", "GO-2026-6354"), vex(notAffected("GO-2026-5932")), false},
		{"not_affected with no justification", findings("GO-1"),
			vex(map[string]any{"vulnerability": map[string]any{"name": "GO-1"}, "status": "not_affected"}), false},
		{"affected is not an explanation", findings("GO-1"),
			vex(map[string]any{"vulnerability": map[string]any{"name": "GO-1"}, "status": "affected"}), false},
		{"fixed covers it", findings("GO-1"), vex(map[string]any{"vulnerability": map[string]any{"name": "GO-1"}, "status": "fixed"}), true},
		{"covered through an alias", findings("GO-1"),
			vex(map[string]any{"vulnerability": map[string]any{"name": "CVE-2026-1", "aliases": []any{"GO-1"}}, "status": "fixed"}), true},
		{"findings and no VEX step at all", findings("GO-1"), noVEX, false},
		{"no findings needs no VEX", findings(), noVEX, true},
		{"a statement for a different vulnerability", findings("GO-1"), vex(notAffected("GO-2")), false},
	}
	for _, c := range cases {
		err := evalRule(t, ruleGovulncheckVEX, param, c.pred, c.steps)
		if c.admit {
			require.NoError(t, err, c.name)
		} else {
			require.Error(t, err, c.name)
		}
	}
}

func TestSARIFVEXCoverage(t *testing.T) {
	const param = `{"vexStep":"vex","products":["sha256:abc"]}`
	pred := map[string]any{"report": map[string]any{"runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "grype"}},
		"results": []any{map[string]any{"ruleId": "CVE-2024-2222", "level": "error"}},
	}}}}
	require.NoError(t, evalRule(t, ruleSARIFVEX, param, pred, vexSteps(vexStatement("CVE-2024-2222", "sha256:abc", "not_affected", "component_not_present"))))
	requireDenied(t, evalRule(t, ruleSARIFVEX, param, pred, vexSteps(vexStatement("CVE-2024-9999", "sha256:abc", "fixed", ""))), "CVE-2024-2222 is not covered")

	// Codex round 5 on #10195: a run whose invocation did not finish has no
	// complete result list, so empty results there are not "nothing to
	// cover" and not "no errors".
	failed := map[string]any{"report": map[string]any{"runs": []any{map[string]any{
		"tool":        map[string]any{"driver": map[string]any{"name": "grype"}},
		"results":     []any{},
		"invocations": []any{map[string]any{"executionSuccessful": false}},
	}}}}
	requireDenied(t, evalRule(t, ruleSARIFVEX, param, failed, vexSteps()), "unreadable evidence")
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", failed, nil), "unreadable evidence")
	unsaid := map[string]any{"report": map[string]any{"runs": []any{map[string]any{
		"tool":        map[string]any{"driver": map[string]any{"name": "grype"}},
		"results":     []any{},
		"invocations": []any{map[string]any{}},
	}}}}
	requireDenied(t, evalRule(t, ruleSARIFVEX, param, unsaid, vexSteps()), "unreadable evidence")
	requireDenied(t, evalRule(t, ruleSARIFNoErrors, "", unsaid, nil), "unreadable evidence")
	finished := map[string]any{"report": map[string]any{"runs": []any{map[string]any{
		"tool":        map[string]any{"driver": map[string]any{"name": "grype"}},
		"results":     []any{},
		"invocations": []any{map[string]any{"executionSuccessful": true}},
	}}}}
	require.NoError(t, evalRule(t, ruleSARIFVEX, param, finished, vexSteps()))
	require.NoError(t, evalRule(t, ruleSARIFNoErrors, "", finished, nil))
}

// v02 builds a traced command-run predicate the way v2_marshal.go interns it.
func v02(procs []map[string]any, paths []string, digests []string) map[string]any {
	ps := make([]any, 0, len(procs))
	for _, p := range procs {
		ps = append(ps, p)
	}
	pl := make([]any, 0, len(paths))
	for _, p := range paths {
		pl = append(pl, p)
	}
	dl := make([]any, 0, len(digests))
	for _, d := range digests {
		dl = append(dl, map[string]any{"digests": map[string]any{"sha256": d}})
	}
	return map[string]any{"exitcode": 0, "cmd": []any{"make"}, "processes": ps, "paths": pl, "digests": dl}
}

const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestTraceRules(t *testing.T) {
	paths := []string{"/usr/bin/make", "/work/app/out.o", "/home/u/.ssh/id_ed25519", "/work/app/.git/config", "/etc/ssl/cert.pem", "/etc/ssl/private/server.key", "/etc/ssl/certs/ca-bundle.pem", "/etc/ssl/cert.pem.key", "/etc/ssl/certs/../private/server.key", "/home/u/.kube/./config", "home/u/.netrc"}
	proc := func(extra map[string]any) map[string]any {
		p := map[string]any{"processid": 7, "execPathId": 0, "exeDigestId": 0, "programDigestId": 0}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}

	t.Run("untraced evidence refused", func(t *testing.T) {
		requireDenied(t, evalRule(t, ruleTracePresent, "", map[string]any{"exitcode": 0, "processes": nil}, nil), "untraced evidence")
		for id, param := range map[string]string{ruleTraceNetwork: `["10.0.0.1"]`, ruleTraceExec: `["/x"]`, ruleTraceWrites: `["/x"]`} {
			requireDenied(t, evalRule(t, id, param, map[string]any{"exitcode": 0}, nil), "untraced evidence")
		}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", map[string]any{"exitcode": 0}, nil), "untraced evidence")
		require.NoError(t, evalRule(t, ruleTracePresent, "", v02([]map[string]any{proc(nil)}, paths, []string{"d0"}), nil))
	})

	t.Run("network call refused", func(t *testing.T) {
		conn := map[string]any{"network": map[string]any{"connections": []any{
			map[string]any{"syscall": "connect", "family": "AF_INET", "address": "93.184.216.34", "port": 443, "hostname": "evil.example"},
			map[string]any{"syscall": "connect", "family": "AF_UNIX", "address": "/var/run/nscd"},
		}}}
		pred := v02([]map[string]any{proc(conn)}, paths, []string{"d0"})
		requireDenied(t, evalRule(t, ruleTraceNetwork, `["10.0.0.1"]`, pred, nil), "93.184.216.34 port 443 (SNI evil.example, client-asserted) is not in the allowlist")
		// The SNI is whatever the client wrote into its ClientHello; the trace
		// binds it to nothing (DNS lookups record only the server), so a
		// connection to an attacker's address with an allowed SNI is refused.
		_, err := renderRule(ruleTraceNetwork, json.RawMessage(`["evil.example"]`))
		require.ErrorContains(t, err, "IP addresses only", "the SNI cannot be allowlisted at all")
		require.NoError(t, evalRule(t, ruleTraceNetwork, `["93.184.216.34"]`, pred, nil), "the kernel-observed address admits; AF_UNIX is not network")
		// Codex round 1 on #10908: the allowlist is IP addresses only, so the
		// attestor's placeholder for a destination it could not observe can
		// never be allowlisted, and an observed address that is not an IP
		// admits nothing even if it were.
		_, err = renderRule(ruleTraceNetwork, json.RawMessage(`["(host-not-observable)"]`))
		require.ErrorContains(t, err, "IP addresses only")
		_, err = renderRule(ruleTraceNetwork, json.RawMessage(`["proxy.golang.org"]`))
		require.ErrorContains(t, err, "IP addresses only")
		unobserved := map[string]any{"network": map[string]any{"connections": []any{
			map[string]any{"syscall": "connect", "family": "AF_INET", "address": "(host-not-observable)", "port": 0},
		}}}
		requireDenied(t, evalRule(t, ruleTraceNetwork, `["93.184.216.34"]`, v02([]map[string]any{proc(unobserved)}, paths, []string{"d0"}), nil), "(host-not-observable) port 0")
		dns := map[string]any{"network": map[string]any{"dnsLookups": []any{map[string]any{"serverAddress": "8.8.8.8", "serverPort": 53}}}}
		requireDenied(t, evalRule(t, ruleTraceNetwork, `[]`, v02([]map[string]any{proc(dns)}, paths, []string{"d0"}), nil), "DNS lookup via 8.8.8.8")
	})

	t.Run("unexpected executable refused", func(t *testing.T) {
		pred := v02([]map[string]any{proc(nil), proc(map[string]any{"processid": 8, "execPathId": -1, "exeDigestId": -1, "programDigestId": -1})}, paths, []string{hex64})
		requireDenied(t, evalRule(t, ruleTraceExec, `["/usr/bin/make"]`, pred, nil), "process 8 ran an unrecorded executable")
		only := v02([]map[string]any{proc(nil)}, paths, []string{hex64})
		require.NoError(t, evalRule(t, ruleTraceExec, `["/usr/bin/make"]`, only, nil))
		require.NoError(t, evalRule(t, ruleTraceExec, `["`+hex64+`"]`, only, nil), "an allowed image digest admits")
		// Codex round 2 on #10908: a path entry admits only a path, a digest
		// entry only a sha256; evidence whose "digest" is an allowed path
		// admits nothing, and the allowlist takes nothing else.
		forged := v02([]map[string]any{{"processid": 9, "execPathId": 1, "exeDigestId": 0, "programDigestId": 0}}, []string{"/usr/bin/make", "/tmp/unapproved"}, []string{"/usr/bin/make"})
		requireDenied(t, evalRule(t, ruleTraceExec, `["/usr/bin/make"]`, forged, nil), "process 9 ran /tmp/unapproved")
		_, err := renderRule(ruleTraceExec, json.RawMessage(`["d0"]`))
		require.ErrorContains(t, err, "absolute paths and sha256 digests only")
		requireDenied(t, evalRule(t, ruleTraceExec, `["/usr/bin/cc"]`, only, nil), "process 7 ran /usr/bin/make")
	})

	t.Run("writes outside the workspace or into .git refused", func(t *testing.T) {
		ok := map[string]any{"fileOps": map[string]any{"writes": []any{map[string]any{"path": "/work/app/out.o"}}}}
		require.NoError(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(ok)}, paths, []string{"d0"}), nil))
		gitw := map[string]any{"fileOps": map[string]any{"renames": []any{map[string]any{"oldPath": "/work/app/x", "newPath": "/work/app/.git/config"}}}}
		requireDenied(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(gitw)}, paths, []string{"d0"}), nil), "/work/app/.git/config is inside .git")
		// Codex round 3 on #10908: a relative path has no known destination,
		// so neither the prefix test nor the .git test can judge it; the
		// allowlist takes absolute prefixes only.
		rel := map[string]any{"fileOps": map[string]any{"writes": []any{map[string]any{"path": ".git/config"}}}}
		requireDenied(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(rel)}, paths, []string{"d0"}), nil), "writes: .git/config is not an absolute path")
		_, err := renderRule(ruleTraceWrites, json.RawMessage(`["."]`))
		require.ErrorContains(t, err, "absolute path prefixes only")
		out := map[string]any{"writtenFiles": []any{map[string]any{"pathId": 2, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(out)}, paths, []string{"d0"}), nil), "/home/u/.ssh/id_ed25519 was modified outside")
	})

	// Codex round 3 on #10195: a collection the rules iterate that is not an
	// array yields nothing to refuse, and a path index the table does not
	// resolve became "", which nothing refuses either. Both are unreadable
	// evidence.
	t.Run("a collection that is not an array is unreadable", func(t *testing.T) {
		net := map[string]any{"network": map[string]any{"connections": false}}
		requireDenied(t, evalRule(t, ruleTraceNetwork, `[]`, v02([]map[string]any{proc(net)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7's network.connections is not an array")
		dns := map[string]any{"network": map[string]any{"dnsLookups": "none"}}
		requireDenied(t, evalRule(t, ruleTraceNetwork, `[]`, v02([]map[string]any{proc(dns)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7's network.dnsLookups is not an array")
		ops := map[string]any{"fileOps": map[string]any{"writes": false}}
		requireDenied(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(ops)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7's fileOps.writes is not an array")
		wf := map[string]any{"writtenFiles": map[string]any{}}
		requireDenied(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(wf)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7's writtenFiles is not an array")
		of := map[string]any{"openedFiles": false}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(of)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7's openedFiles is not an array")
		uh := map[string]any{"unhashedOpens": 3}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(uh)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7's unhashedOpens is not an array")
	})

	t.Run("a path index the trace does not record is unreadable", func(t *testing.T) {
		of := map[string]any{"openedFiles": []any{map[string]any{"pathId": 99, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(of)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7 opened path index 99, which the trace does not record")
		uh := map[string]any{"unhashedOpens": []any{map[string]any{}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(uh)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7 opened path index -1, which the trace does not record")
		wf := map[string]any{"writtenFiles": []any{map[string]any{"pathId": "1"}}}
		requireDenied(t, evalRule(t, ruleTraceWrites, `["/work/app/"]`, v02([]map[string]any{proc(wf)}, paths, []string{"d0"}), nil), "unreadable evidence: process 7 wrote path index 1, which the trace does not record")
	})

	t.Run("credential reads refused, CA bundles are not credentials", func(t *testing.T) {
		read := map[string]any{"openedFiles": []any{map[string]any{"pathId": 2, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(read)}, paths, []string{"d0"}), nil), "opened /home/u/.ssh/id_ed25519")
		ca := map[string]any{"openedFiles": []any{map[string]any{"pathId": 4, "digestId": 0}, map[string]any{"pathId": 6, "digestId": 0}}}
		require.NoError(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(ca)}, paths, []string{"d0"}), nil))
		// Codex round 4 on #10195: the exemption is the public certificate
		// stores, not every file under /etc/ssl.
		key := map[string]any{"openedFiles": []any{map[string]any{"pathId": 5, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(key)}, paths, []string{"d0"}), nil), "opened /etc/ssl/private/server.key, a credential path")
		// Round 5: a bundle file is matched exactly, and an exempt directory
		// only with a normalized path.
		prefixed := map[string]any{"openedFiles": []any{map[string]any{"pathId": 7, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(prefixed)}, paths, []string{"d0"}), nil), "opened /etc/ssl/cert.pem.key, a credential path")
		dotdot := map[string]any{"openedFiles": []any{map[string]any{"pathId": 8, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(dotdot)}, paths, []string{"d0"}), nil), "opened /etc/ssl/certs/../private/server.key, a credential path")
		// Round 7: an opened path that is not normalized, or not absolute,
		// hides what it resolves to from every substring check.
		dot := map[string]any{"openedFiles": []any{map[string]any{"pathId": 9, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(dot)}, paths, []string{"d0"}), nil), "reads: /home/u/.kube/./config is not a normalized absolute path")
		rel := map[string]any{"openedFiles": []any{map[string]any{"pathId": 10, "digestId": 0}}}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", v02([]map[string]any{proc(rel)}, paths, []string{"d0"}), nil), "reads: home/u/.netrc is not a normalized absolute path")
	})
}

// The catalog's predicate types are the ones the attestors actually register.
func TestCatalogTypesMatchTheRegistry(t *testing.T) {
	for typ, a := range catalogAttestors {
		if a.Always || typ == typeCycloneDX || typ == typeSPDX {
			continue
		}
		f, ok := attestation.FactoryByName(a.Name)
		if !ok {
			continue // not linked into this test binary; the type is checked where it is
		}
		require.Equal(t, typ, f().Type(), "catalog type for attestor %s", a.Name)
	}
	for _, name := range []string{"test-results", "sarif", "secretscan", "govulncheck", "trivy", "slsa", "vex", "github-review", "k8smanifest"} {
		_, ok := attestation.FactoryByName(name)
		require.True(t, ok, "attestor %s must be registered for this check to mean anything", name)
	}
	for _, id := range sortedRuleIDs() {
		_, ok := catalogAttestors[ruleTemplates[id].Type]
		require.True(t, ok, fmt.Sprintf("rule %s attaches to a type the catalog does not describe", id))
	}
}

// products-from ties each of this step's products to the upstream step's by
// sha256. A leaf with no digest, on either side, ties nothing to anything.
func TestProductsFromRule(t *testing.T) {
	const (
		dA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		dB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	leaf := func(path string, digest any) map[string]any {
		l := map[string]any{"path": path}
		if digest != nil {
			l["fileDigest"] = digest
		}
		return l
	}
	mine := func(leaves ...map[string]any) map[string]any {
		ls := make([]any, 0, len(leaves))
		for _, l := range leaves {
			ls = append(ls, l)
		}
		return map[string]any{"leaves": ls}
	}
	upstream := func(leaves ...map[string]any) map[string]any {
		return map[string]any{"build": map[string]any{"collections": []any{map[string]any{
			"attestations": map[string]any{"https://aflock.ai/attestations/product/v0.3": mine(leaves...)},
		}}}}
	}
	const param = `"build"`

	require.NoError(t, evalRule(t, ruleProductsFrom, param, mine(leaf("app", dA)), upstream(leaf("bin/app", dA), leaf("x", dB))))
	requireDenied(t, evalRule(t, ruleProductsFrom, param, mine(leaf("app", dB)), upstream(leaf("bin/app", dA))), "app is not, by digest, a product of step build")

	for name, c := range map[string]struct {
		mine, up map[string]any
		want     string
	}{
		"both sides lack a digest":         {mine(leaf("app", nil)), upstream(leaf("other", nil)), "app has no sha256 fileDigest"},
		"both sides carry an empty digest": {mine(leaf("app", "")), upstream(leaf("other", "")), "app has no sha256 fileDigest"},
		"mine lacks, upstream has one":     {mine(leaf("app", nil)), upstream(leaf("bin/app", dA)), "app has no sha256 fileDigest"},
		"a non-hex digest on both sides":   {mine(leaf("app", "zz")), upstream(leaf("bin/app", "zz")), "app has no sha256 fileDigest"},
		"a number digest on both sides":    {mine(leaf("app", 7)), upstream(leaf("bin/app", 7)), "app has no sha256 fileDigest"},
		"upstream leaf lacks the digest":   {mine(leaf("app", dA)), upstream(leaf("bin/app", nil)), "app is not, by digest, a product of step build"},
		"one good leaf beside one without": {mine(leaf("app", dA), leaf("extra", nil)), upstream(leaf("bin/app", dA), leaf("y", nil)), "extra has no sha256 fileDigest"},
	} {
		requireDenied(t, evalRule(t, ruleProductsFrom, param, c.mine, c.up), c.want, name)
	}
}

// Evidence the spec ("What each rule admits", docs/design/cilock-policy-init.md)
// refuses, which the rules once admitted.
func TestSeededRulesRefuseMalformedEvidence(t *testing.T) {
	t.Run("trace-present needs process objects", func(t *testing.T) {
		pred := map[string]any{"processes": []any{2}, "paths": []any{}}
		requireDenied(t, evalRule(t, ruleTracePresent, "", pred, nil), "untraced evidence")
	})
	writes := func(paths ...any) map[string]any {
		ws := make([]any, 0, len(paths))
		for _, p := range paths {
			ws = append(ws, map[string]any{"path": p})
		}
		return v02([]map[string]any{{"fileOps": map[string]any{"writes": ws}}}, []string{"/usr/bin/make"}, nil)
	}
	const prefixes = `["/work/"]`
	t.Run("trace-writes admits a normalized path under the prefix", func(t *testing.T) {
		require.NoError(t, evalRule(t, ruleTraceWrites, prefixes, writes("/work/a/b.o"), nil))
	})
	t.Run("trace-writes refuses a path that climbs out of the prefix", func(t *testing.T) {
		for _, p := range []string{"/work/../etc/passwd", "/work/a/..", "/work/./a", "/work/a/.", "/work//a"} {
			requireDenied(t, evalRule(t, ruleTraceWrites, prefixes, writes(p), nil), "not normalized", p)
		}
	})
	t.Run("trace-writes refuses a path that is not a string", func(t *testing.T) {
		requireDenied(t, evalRule(t, ruleTraceWrites, prefixes, writes("/work/a", false), nil), "unreadable evidence")
	})
	t.Run("trace-credential-reads refuses an opened path that is not a string", func(t *testing.T) {
		pred := v02([]map[string]any{{"openedFiles": []any{map[string]any{"pathId": 0}}}}, nil, nil)
		pred["paths"] = []any{5}
		requireDenied(t, evalRule(t, ruleTraceSensitiveReads, "", pred, nil), "unreadable evidence")
	})
	t.Run("govulncheck-vex-covered needs scan roots", func(t *testing.T) {
		const param = `{"vexStep":"vex","products":[]}`
		noVEX := map[string]any{"other": map[string]any{}}
		summary := map[string]any{"findings": nil, "reachableCount": 0, "unreachableCount": 0, "totalFindings": 0}
		requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, map[string]any{"summary": summary}, noVEX), "unreadable evidence")
		for _, roots := range []any{[]any{}, "example.com/app", nil} {
			summary["scanRoots"] = roots
			requireDenied(t, evalRule(t, ruleGovulncheckVEX, param, map[string]any{"summary": summary}, noVEX), "unreadable evidence", roots)
		}
		summary["scanRoots"] = []any{"example.com/app"}
		require.NoError(t, evalRule(t, ruleGovulncheckVEX, param, map[string]any{"summary": summary}, noVEX))
	})
}
