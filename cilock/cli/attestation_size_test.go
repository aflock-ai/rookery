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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// --max-attestation-bytes
// =====================================================================
//
// Since #9276 the local ring's push-tests attestation carried the whole
// `go test -json` stream: 45.6 MB and 47.1 MB per envelope, measured
// 2026-09-15. The platform parses every envelope matching a commit three
// times per push evaluation at ~0.4 s/MB (0.95 s median with no large
// envelope; 18.6 s with one 45 MB envelope; 32 s with two) against a 25 s
// edge budget. These tests pin the guardrail that turns the next such
// regression into a refusal at mint time: the default, the precedence, the
// refusal text, and the two places it must NOT apply (verify, companions).

func TestMaxAttestationBytesDefaultIs4MiBOnRunAndSign(t *testing.T) {
	for _, cmd := range []struct {
		name string
		flag string
	}{{"run", RunCmd().Flags().Lookup(options.MaxAttestationBytesFlag).DefValue}, {"sign", SignCmd().Flags().Lookup(options.MaxAttestationBytesFlag).DefValue}} {
		require.Equal(t, "4MiB", cmd.flag, "%s default", cmd.name)
	}
	require.Equal(t, 4<<20, options.DefaultMaxAttestationBytes)
	// verify reads evidence, it does not mint it: old oversized envelopes must
	// stay verifiable, so it has no such flag at all.
	require.Nil(t, VerifyCmd().Flags().Lookup(options.MaxAttestationBytesFlag), "verify must not grow a size limit")
}

// The production failure, reduced: a collection over the limit is refused
// after the wrapped command ran and BEFORE anything is signed, written or
// uploaded. The same run under the default signs and writes.
func TestRunRefusesAnOversizedCollectionBeforeWritingIt(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, _, key := inventoryRunFixture(t)
	marker := filepath.Join(ro.WorkingDir, "executed")
	out := filepath.Join(t.TempDir(), "run.json")

	cmd := RunCmd()
	cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "material,product", "-k", key, "--workingdir", ro.WorkingDir,
		"--capture-mode", "walk", "--max-attestation-bytes", "256", "-o", out, "--", "touch", marker})
	err := cmd.ExecuteContext(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "attestation too large")
	require.Contains(t, err.Error(), "256", "the refusal names the limit")
	require.Contains(t, err.Error(), "--"+options.MaxAttestationBytesFlag)
	require.Contains(t, err.Error(), options.MaxAttestationBytesEnv)
	require.Contains(t, err.Error(), "material/v0.3", "the breakdown names the attestors by short name")
	require.FileExists(t, marker, "the size is only known after the command ran")
	require.NoFileExists(t, out, "an oversized statement must never reach disk")

	// Env is honoured when the flag is absent.
	t.Setenv(options.MaxAttestationBytesEnv, "256")
	cmd = RunCmd()
	cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "material,product", "-k", key, "--workingdir", ro.WorkingDir,
		"--capture-mode", "walk", "-o", out, "--", "true"})
	err = cmd.ExecuteContext(t.Context())
	require.ErrorContains(t, err, "attestation too large")
	require.NoFileExists(t, out)

	// The flag wins over env; 0 opts out with one warning line and signs.
	var stderr string
	_, stderr, err = inventoryCapture(t, func() error {
		cmd := RunCmd()
		cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "material,product", "-k", key, "--workingdir", ro.WorkingDir,
			"--capture-mode", "walk", "--max-attestation-bytes", "0", "-o", out, "--", "true"})
		return cmd.ExecuteContext(t.Context())
	})
	require.NoError(t, err)
	require.FileExists(t, out)
	require.Contains(t, stderr, "warning: --max-attestation-bytes=0: no attestation size limit")
	require.Equal(t, 1, strings.Count(stderr, "no attestation size limit"), "exactly one warning line")
}

func TestRunSignsUnderTheDefaultLimit(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, _, key := inventoryRunFixture(t)
	out := filepath.Join(t.TempDir(), "run.json")
	cmd := RunCmd()
	cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "material,product", "-k", key, "--workingdir", ro.WorkingDir,
		"--capture-mode", "walk", "-o", out, "--", "true"})
	require.NoError(t, cmd.ExecuteContext(t.Context()))
	require.FileExists(t, out)
}

// msgLines splits a refusal into lines and returns an index helper, so the
// assertions read as "the remedy is the line under its attestor" rather than
// as substring soup over the whole message.
func msgLines(t *testing.T, msg string) ([]string, func(string) int) {
	t.Helper()
	lines := strings.Split(msg, "\n")
	return lines, func(sub string) int {
		for i, l := range lines {
			if strings.Contains(l, sub) {
				return i
			}
		}
		t.Fatalf("%q not in:\n%s", sub, msg)
		return -1
	}
}

func TestFormatStatementTooLargeNamesContributorsAndRemedies(t *testing.T) {
	// Every contributor here holds a real share of the statement, so every
	// one earns a remedy. The suppression rule for trivial contributors is
	// pinned separately, in TestFormatStatementTooLargeSuppressesRemediesForTrivialContributors.
	e := &workflow.StatementTooLargeError{
		PredicateType: attestation.CollectionType,
		Bytes:         49_380_120,
		Limit:         4 << 20,
		Contributors: []workflow.StatementContributor{
			{Type: commandrun.Type, Bytes: 25_000_000},
			{Type: product.Type, Bytes: 12_000_000},
			{Type: material.Type, Bytes: 7_000_000},
			{Type: "https://aflock.ai/attestations/git/v0.1", Bytes: 5_300_000},
		},
	}
	msg := formatStatementTooLarge(e).Error()

	require.True(t, strings.HasPrefix(msg, "attestation too large:"), msg)
	require.Contains(t, msg, "47.1 MiB", "human total")
	require.Contains(t, msg, "49,380,120 bytes", "exact total")
	require.Contains(t, msg, "4MiB limit", "the limit as the operator would write it")
	require.Contains(t, msg, "--"+options.MaxAttestationBytesFlag)
	require.Contains(t, msg, options.MaxAttestationBytesEnv)
	require.Contains(t, msg, "0.4 s/MB", "the reason for the limit")
	require.Contains(t, msg, "25 s", "the budget it protects")
	require.Contains(t, msg, "about 20 s per push", "49.4 MB x 0.4 s/MB, the cost this refusal prevents")

	// Largest first, short names, one remedy each.
	lines, idx := msgLines(t, msg)
	require.Less(t, idx("command-run/v0.2"), idx("product/v0.3"))
	require.Less(t, idx("product/v0.3"), idx("material/v0.3"))
	require.Less(t, idx("material/v0.3"), idx("git/v0.1"))

	require.Contains(t, lines[idx("command-run/v0.2")+1], "stdout", "command-run remedy: the stream")
	require.Contains(t, lines[idx("command-run/v0.2")+1], "redirect", "command-run remedy: redirect it to a product file")
	require.Contains(t, lines[idx("product/v0.3")+1], "--attestor-product-exclude-glob")
	require.Contains(t, lines[idx("material/v0.3")+1], "--material-manifest")
	require.Contains(t, lines[idx("material/v0.3")+1], "no include/exclude glob", "material remedy states the fact size_advice.go states")
	require.Contains(t, lines[idx("git/v0.1")+1], "-a", "generic remedy: drop it from the attestor list")
	require.Contains(t, lines[idx("git/v0.1")+1], "--"+options.MaxAttestationBytesFlag)
}

// A remedy is an instruction, and an instruction that cannot help is worse
// than silence: an operator told to narrow their product globs will try it
// before re-reading the 144-byte figure on the line above. Sizes are always
// printed — that is the measurement — but a remedy is printed only for the
// largest contributor and for anything holding a real share of the statement.
func TestFormatStatementTooLargeSuppressesRemediesForTrivialContributors(t *testing.T) {
	e := &workflow.StatementTooLargeError{
		PredicateType: attestation.CollectionType,
		Bytes:         284_042,
		Limit:         8 << 10,
		Contributors: []workflow.StatementContributor{
			{Type: commandrun.Type, Bytes: 267_000}, // 94%
			{Type: "https://aflock.ai/attestations/git/v0.1", Bytes: 8_500},
			{Type: material.Type, Bytes: 334},
			{Type: product.Type, Bytes: 144},
		},
	}
	msg := formatStatementTooLarge(e).Error()
	lines, idx := msgLines(t, msg)

	// Every contributor's size is still reported.
	require.Contains(t, msg, "260.7 KiB")
	require.Contains(t, msg, "334 B")
	require.Contains(t, msg, "144 B")

	// The dominant one carries its remedy...
	require.Contains(t, lines[idx("command-run/v0.2")+1], "redirect")
	// ...and the three that cannot move the number do not.
	require.NotContains(t, msg, "--attestor-product-exclude-glob",
		"a 144-byte product predicate must not be handed a product-glob remedy")
	require.NotContains(t, msg, "--material-manifest",
		"a 334-byte material predicate must not be handed a manifest remedy")
	require.NotContains(t, msg, "drop the attestor from -a",
		"an 8.5 KB git predicate must not be handed the generic remedy")

	// Counted, not inferred: header + "largest contributors:" + four
	// contributor lines + exactly one remedy. A rule that silently stopped
	// printing the dominant remedy too would pass every NotContains above.
	require.Len(t, lines, 7, "one remedy among four contributors:\n%s", msg)
	require.Equal(t, idx("command-run/v0.2")+1, idx("redirect"), "the remedy sits under its attestor")

	// The per-push cost clause is dropped rather than rounded to "about 0 s":
	// 284 KB is 0.11 s, and printing "0 s" argues against the limit.
	require.NotContains(t, msg, "0 s per push")
	require.NotContains(t, msg, "per push", "no cost clause below one second")
}

// Every flag a remedy names must be one `cilock run` accepts, or the message
// costs a gate cycle before the operator learns it was never valid (#9230).
func TestStatementTooLargeRemediesNameRealRunFlags(t *testing.T) {
	flags := RunCmd().Flags()
	flagRe := regexp.MustCompile(`--[a-z][a-z0-9-]*`)
	for _, typeURI := range []string{commandrun.Type, product.Type, material.Type, "https://aflock.ai/attestations/git/v0.1", ""} {
		for _, name := range flagRe.FindAllString(remedyFor(typeURI), -1) {
			require.NotNil(t, flags.Lookup(strings.TrimPrefix(name, "--")), "remedy for %q names %s, which cilock run does not accept", typeURI, name)
		}
	}
}

// `cilock sign` refuses a file over the limit before it looks for a signer
// or opens the output, and an already-signed statement handed to it is
// explained with the same breakdown `cilock run` gives.
func TestSignRefusesAnOversizedFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "signed.json")
	so := options.SignOptions{OutFilePath: out, DataType: "https://witness.testifysec.com/policy/v0.1", MaxAttestationBytes: 64}

	err := signBytes(context.Background(), so, bytes.Repeat([]byte("p"), 65), &fakeSignerForTesting{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "attestation too large")
	require.NotContains(t, err.Error(), "fake signer", "the size check runs before the signer is touched")
	require.NoFileExists(t, out, "a refused input must not create or truncate the output")

	// At the limit the check passes and the (fake) signer is reached.
	err = signBytes(context.Background(), so, bytes.Repeat([]byte("p"), 64), &fakeSignerForTesting{})
	require.ErrorContains(t, err, "fake signer")

	// Zero is unlimited, matching run and the direct runSign callers that
	// never set the field.
	so.MaxAttestationBytes = 0
	err = signBytes(context.Background(), so, bytes.Repeat([]byte("p"), 1<<20), &fakeSignerForTesting{})
	require.ErrorContains(t, err, "fake signer")
}

func TestSignRefusalBreaksDownACollectionStatement(t *testing.T) {
	stmt := oversizedCollectionStatement(t, 1<<16)
	so := options.SignOptions{OutFilePath: filepath.Join(t.TempDir(), "signed.json"), DataType: intoto.PayloadType, MaxAttestationBytes: 4096}
	err := signBytes(context.Background(), so, stmt, &fakeSignerForTesting{})
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "attestation too large")
	require.Contains(t, msg, "command-run/v0.2", "the largest attestor is named")
	require.Contains(t, msg, "stdout", "with its remedy")
	require.Contains(t, msg, "4KiB limit")

	// The same bytes through the cobra command, so the flag is wired.
	in := filepath.Join(t.TempDir(), "stmt.json")
	require.NoError(t, os.WriteFile(in, stmt, 0o600))
	cmd := SignCmd()
	cmd.SetArgs([]string{"-f", in, "-o", so.OutFilePath, "--platform-url", "", "--max-attestation-bytes", "4KiB"})
	err = cmd.Execute()
	require.ErrorContains(t, err, "attestation too large")
	require.NoFileExists(t, so.OutFilePath)
}

// Verification of old evidence must keep working whatever the mint-time
// limit is: an envelope far over 4 MiB loads and verifies.
func TestVerifyStillReadsAnOversizedEnvelope(t *testing.T) {
	stmt := oversizedCollectionStatement(t, 5<<20)
	require.Greater(t, len(stmt), options.DefaultMaxAttestationBytes)
	_, signer, _ := inventoryRunFixture(t)
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(stmt), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	raw, err := json.Marshal(env)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "old.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	loaded, err := loadEnvelopeFromFile(path)
	require.NoError(t, err, "verify's loader must not refuse by size")
	require.Equal(t, len(stmt), len(loaded.Payload))
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	checked, err := loaded.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err)
	require.Len(t, checked, 1)

	// And the best-effort loader used for --attestations files.
	envs, err := loadEnvelopesBestEffort(path)
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

// oversizedCollectionStatement builds a collection statement whose
// command-run entry carries about n bytes of stdout: the shape of the
// production envelopes this limit exists for.
func oversizedCollectionStatement(t *testing.T, n int) []byte {
	t.Helper()
	type entry struct {
		Type        string          `json:"type"`
		Attestation json.RawMessage `json:"attestation"`
	}
	stdout, err := json.Marshal(map[string]any{"cmd": []string{"go", "test", "-json", "./..."}, "stdout": strings.Repeat(`{"Action":"output"}`+"\n", n/20), "exitcode": 0})
	require.NoError(t, err)
	git, err := json.Marshal(map[string]string{"commithash": strings.Repeat("a", 40)})
	require.NoError(t, err)
	predicate, err := json.Marshal(map[string]any{"name": "push-tests", "attestations": []entry{
		{Type: "https://aflock.ai/attestations/git/v0.1", Attestation: git},
		{Type: commandrun.Type, Attestation: stdout},
	}})
	require.NoError(t, err)
	stmt, err := json.Marshal(map[string]any{
		"_type":         intoto.StatementType,
		"predicateType": attestation.CollectionType,
		"subject":       []any{},
		"predicate":     json.RawMessage(predicate),
	})
	require.NoError(t, err)
	return stmt
}
