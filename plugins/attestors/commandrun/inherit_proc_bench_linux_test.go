// Copyright 2026 The Rookery Contributors
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

//go:build linux

package commandrun

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// runTracedCommandForBench is like runTracedCommandWithCtx but takes a
// *testing.B. Duplicated because *testing.T and *testing.B don't
// share an interface that exposes both TempDir + Helper + Logf.
func runTracedCommandForBench(b *testing.B, dir string, argv []string) (*ptraceContext, []ProcessInfo) {
	b.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	actx, err := attestation.NewContext("test",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(dir),
	)
	if err != nil {
		b.Fatal(err)
	}

	rc := &CommandRun{
		Cmd:           argv,
		enableTracing: true,
		silent:        true,
	}

	c := exec.Command(rc.Cmd[0], rc.Cmd[1:]...) //nolint:gosec
	c.Dir = dir
	stdoutBuf, stderrBuf := bytes.Buffer{}, bytes.Buffer{}
	c.Stdout = io.MultiWriter(&stdoutBuf)
	c.Stderr = io.MultiWriter(&stderrBuf)
	enableTracing(c)
	if err := c.Start(); err != nil {
		b.Fatal(err)
	}

	pctx, _ := rc.traceWithContext(c, actx)
	_ = c.Wait()
	rc.Processes = pctx.procInfoArray()
	return pctx, rc.Processes
}

// BenchmarkInheritProc_ForkExecHeavy measures /proc/<pid>/status reads
// avoided during a fork+exec-heavy workload. The benchmark body runs
// `bash -c 'true ; true ; true ; true ; true'` under tracing and
// reports statusReadsSkipped / statusReadsTotal at the end so we can
// see the optimization in action.
//
// Run: GOWORK=off go test -bench BenchmarkInheritProc -run '^$' -benchtime=10x
//
// Numbers from a single run are exposed as custom benchmark metrics:
//
//	statusReadsTotal / op
//	statusReadsSkipped / op
//	pctSkipped         %
func BenchmarkInheritProc_ForkExecHeavy(b *testing.B) {
	if _, err := exec.LookPath("bash"); err != nil {
		b.Skip("bash not in PATH")
	}
	echoPath, err := exec.LookPath("echo")
	if err != nil {
		b.Skip("echo not in PATH")
	}

	var totalReads, skippedReads int64
	dir := b.TempDir()
	script := echoPath + " a ; " + echoPath + " b ; " + echoPath + " c ; " +
		echoPath + " d ; " + echoPath + " e"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pctx, _ := runTracedCommandForBench(b, dir, []string{"bash", "-c", script})
		totalReads += int64(pctx.statusReadsTotal)
		skippedReads += int64(pctx.statusReadsSkipped)
	}
	b.StopTimer()

	if b.N > 0 {
		b.ReportMetric(float64(totalReads)/float64(b.N), "statusReads/op")
		b.ReportMetric(float64(skippedReads)/float64(b.N), "skipped/op")
		if totalReads > 0 {
			pct := 100.0 * float64(skippedReads) / float64(totalReads)
			b.ReportMetric(pct, "pctSkipped")
		}
	}
}
