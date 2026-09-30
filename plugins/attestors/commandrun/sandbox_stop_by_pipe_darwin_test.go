//go:build darwin

// jade:ring local

package commandrun

import (
	"testing"
	"time"
)

// A collector launched through sudo cannot be signalled by us, so shutdown
// stops it by closing its stdout: log's next write gets SIGPIPE, log exits,
// sudo exits with it. This drives that stop path on the direct collector,
// which is the one this machine can run, and proves the process really ends
// and shutdown returns inside its bound rather than hanging on a reader that
// never sees EOF.
func TestSandboxStopByClosingPipeEndsCollector(t *testing.T) {
	s, err := startSandboxSession()
	if err != nil {
		t.Fatalf("startSandboxSession: %v", err)
	}
	s.stopByClosingPipe = true

	start := time.Now()
	s.shutdown()
	took := time.Since(start)

	if s.collector.ProcessState == nil {
		t.Fatalf("shutdown returned after %s but the collector (pid %d) was never reaped", took, s.collector.Process.Pid)
	}
	if took > collectorStopBound {
		t.Fatalf("shutdown took %s, over its %s bound", took, collectorStopBound)
	}
	s.mu.Lock()
	readerErr := s.readerErr
	s.mu.Unlock()
	if readerErr != nil {
		t.Fatalf("closing the pipe on purpose was recorded as a reader failure: %v", readerErr)
	}
	if s.endedEarly.Load() {
		t.Fatal("a requested stop was recorded as the stream ending early")
	}
}
