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

package govulncheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A package-level finding: what govulncheck emits for an imported vulnerable
// package BEFORE it waits on the call graph (x/vuln internal/vulncheck/source.go
// emitPackageFindings, then wg.Wait()). A stream that stops here has findings
// but no symbol-level ones, so it reads as reachableCount 0.
const pkgFinding = `{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8",` +
	`"trace":[{"module":"golang.org/x/text","version":"v0.3.7","package":"golang.org/x/text/language"}]}}`

// indentStream writes records the way govulncheck does (jsonhandler.go:22).
func indentStream(t *testing.T, records ...string) []byte {
	t.Helper()
	var stream bytes.Buffer
	for _, r := range records {
		require.NoError(t, json.Indent(&stream, []byte(r), "", "  "))
		stream.WriteByte('\n')
	}
	return stream.Bytes()
}

// scanRun is one collection as `cilock run` builds it: command-run executes
// the wrapped command, product hashes vulns.json, govulncheck reads it. A nil
// execute attestor means the collection has no command-run at all.
func scanRun(t *testing.T, stream []byte, execute attestation.Attestor) (*Attestor, error) {
	t.Helper()
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vulns.json"), stream, 0o644))
	gv := New()
	attestors := []attestation.Attestor{product.New(), gv}
	if execute != nil {
		attestors = append([]attestation.Attestor{execute}, attestors...)
	}
	ctx, err := attestation.NewContext("test", attestors, attestation.WithWorkingDir(tmp))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor.Name() == Name {
			return gv, c.Error
		}
	}
	t.Fatalf("govulncheck attestor did not run")
	return nil, nil
}

// exits is a wrapped command that exits with the given shell status, the way
// `sh -c 'govulncheck -json ./... > vulns.json'` carries govulncheck's status.
func exits(status string, opts ...commandrun.Option) attestation.Attestor {
	return commandrun.New(append([]commandrun.Option{
		commandrun.WithCommand([]string{"sh", "-c", "exit " + status}),
		commandrun.WithSilent(true),
	}, opts...)...)
}

// tracedCommandRun is a command-run whose trace is supplied by the test, so the
// per-process exit status of a traced govulncheck can be pinned without a
// tracer. It registers under command-run's own name, as the real one does.
type tracedCommandRun struct{ data *commandrun.CommandRun }

func (f *tracedCommandRun) Name() string                                   { return commandrun.Name }
func (f *tracedCommandRun) Type() string                                   { return commandrun.Type }
func (f *tracedCommandRun) RunType() attestation.RunType                   { return commandrun.RunType }
func (f *tracedCommandRun) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *tracedCommandRun) Schema() *jsonschema.Schema                     { return nil }
func (f *tracedCommandRun) Data() *commandrun.CommandRun                   { return f.data }

func wrapperTracing(govulncheckExit int) attestation.Attestor {
	return &tracedCommandRun{data: &commandrun.CommandRun{
		Cmd:      []string{"sh", "-c", "govulncheck -json ./... > vulns.json || true"},
		ExitCode: 0,
		Processes: []commandrun.ProcessInfo{
			{Program: "/bin/sh", ProcessID: 10, Cmdline: "sh -c govulncheck -json ./... > vulns.json || true"},
			{Program: "/home/ci/go/bin/govulncheck", ProcessID: 11, ParentPID: 10, Cmdline: "govulncheck -json ./...", ExitCode: govulncheckExit},
		},
	}}
}

// TestAttest_CompletionNeedsTheScannersExitStatus pins what proves a
// govulncheck scan finished. The -json protocol has no terminal record: the
// last thing a clean source scan writes can be the "Checking the code..."
// progress record (x/vuln internal/vulncheck/source.go:78-88), and a scan that
// fails AFTER that record (the symbol-mode call-graph path, source.go:104-107
// then witness.go:53; a write error; a kill) leaves exactly the same prefix.
// The JSON handler has no Flush (jsonhandler.go), so the only signal that
// separates the two is govulncheck's exit status, which in -json mode is 0 on
// success whatever it found (the exit 3 for findings is text mode only,
// internal/scan/text.go:84). The attestor reads it from the collection's
// command-run; when it cannot, the scan is not attested.
func TestAttest_CompletionNeedsTheScannersExitStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the wrapped commands are sh scripts")
	}
	checkedClean := indentStream(t, cfgRecord("v1.1.4", "source"), sbomWithRoot, progFetching, osvRecord, progCheckSource)
	checkedThenPkgFinding := indentStream(t, cfgRecord("v1.1.4", "source"), sbomWithRoot, progFetching, osvRecord, progCheckSource, pkgFinding)
	fullPkgFinding := indentStream(t, pkgFinding)
	cutMidRecord := append(indentStream(t, cfgRecord("v1.1.4", "source"), sbomWithRoot, progFetching, osvRecord, progCheckSource),
		fullPkgFinding[:len(fullPkgFinding)/2]...)
	stderrInFile := append(indentStream(t, cfgRecord("v1.1.4", "source"), sbomWithRoot, progFetching, osvRecord, progCheckSource),
		[]byte("govulncheck: loading packages: exit status 1\n")...)

	refused := []struct {
		name    string
		stream  []byte
		execute func() attestation.Attestor
		wantErr []string
	}{
		{
			name:    "stream ends right after the checking record and govulncheck exited 1",
			stream:  checkedClean,
			execute: func() attestation.Attestor { return exits("1") },
			wantErr: []string{"vulns.json", "exited with status 1"},
		},
		{
			name:   "same failure under --ignore-command-exit-code",
			stream: checkedClean,
			execute: func() attestation.Attestor {
				return exits("1", commandrun.WithIgnoreExitCode(true))
			},
			wantErr: []string{"vulns.json", "exited with status 1"},
		},
		{
			name:    "stream ends mid-findings at a record boundary (call-graph panic, exit 2)",
			stream:  checkedThenPkgFinding,
			execute: func() attestation.Attestor { return exits("2") },
			wantErr: []string{"vulns.json", "exited with status 2"},
		},
		{
			name:    "stream is cut off inside a record",
			stream:  cutMidRecord,
			execute: func() attestation.Attestor { return exits("0") },
			wantErr: []string{"vulns.json", "cut off"},
		},
		{
			name:    "govulncheck's stderr error was redirected into the stream",
			stream:  stderrInFile,
			execute: func() attestation.Attestor { return exits("1") },
			wantErr: []string{"vulns.json", "cut off"},
		},
		{
			name:    "no command-run in the collection, so no exit status to read",
			stream:  checkedClean,
			execute: func() attestation.Attestor { return nil },
			wantErr: []string{"vulns.json", "no command-run"},
		},
		{
			name:   "wrapped command could not be observed",
			stream: checkedClean,
			execute: func() attestation.Attestor {
				return commandrun.New(commandrun.WithCommand([]string{"/nonexistent/govulncheck"}), commandrun.WithSilent(true))
			},
			wantErr: []string{"vulns.json", "command-run failed"},
		},
		{
			name:    "traced govulncheck exited 1 behind a wrapper that swallowed it",
			stream:  checkedClean,
			execute: func() attestation.Attestor { return wrapperTracing(1) },
			wantErr: []string{"vulns.json", "govulncheck process", "exited with status 1"},
		},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			gv, err := scanRun(t, tc.stream, tc.execute())
			require.Error(t, err, "a scan whose completion is not established must not be attested")
			assert.False(t, attestation.IsSoftError(err), "an unfinished scan must be fatal, not a soft skip")
			assert.False(t, attestation.EvidenceIsRecordable(err), "the unfinished scan's payload must be dropped")
			for _, want := range tc.wantErr {
				assert.Contains(t, err.Error(), want)
			}
			assert.Empty(t, gv.ReportFile, "no report may be recorded from an unfinished scan")
			assert.Empty(t, gv.Report)
			assert.Empty(t, gv.Summary.ScanMode, "no summary may be recorded from an unfinished scan")
		})
	}

	t.Run("refused/empty stream is never attested", func(t *testing.T) {
		gv, err := scanRun(t, nil, exits("1"))
		require.Error(t, err)
		assert.Empty(t, gv.ReportFile)
		assert.Empty(t, gv.Report)
	})

	vulnFound, err := os.ReadFile(filepath.Join("testdata", "govulncheck-vuln-found.json"))
	require.NoError(t, err)

	t.Run("attested/complete clean scan, exit 0", func(t *testing.T) {
		gv, err := scanRun(t, checkedClean, exits("0"))
		require.NoError(t, err)
		assert.Equal(t, "vulns.json", gv.ReportFile)
		assert.Equal(t, 0, gv.Summary.TotalFindings)
	})
	t.Run("attested/complete scan with findings, exit 0", func(t *testing.T) {
		gv, err := scanRun(t, vulnFound, exits("0"))
		require.NoError(t, err)
		assert.Equal(t, "vulns.json", gv.ReportFile)
		assert.NotZero(t, gv.Summary.ReachableCount)
	})
	t.Run("attested/complete scan with findings under --ignore-command-exit-code, exit 0", func(t *testing.T) {
		gv, err := scanRun(t, vulnFound, exits("0", commandrun.WithIgnoreExitCode(true)))
		require.NoError(t, err)
		assert.NotZero(t, gv.Summary.ReachableCount)
	})
	t.Run("attested/traced govulncheck with no failure recorded, wrapper exit 0", func(t *testing.T) {
		gv, err := scanRun(t, checkedClean, wrapperTracing(0))
		require.NoError(t, err)
		assert.Equal(t, "vulns.json", gv.ReportFile)
	})
}
