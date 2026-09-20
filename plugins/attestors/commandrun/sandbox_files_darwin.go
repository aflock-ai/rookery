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

//go:build darwin

package commandrun

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"golang.org/x/sys/unix"
)

const (
	opFileRead             = "file-read-data"
	maxReadSnapshotBytes   = 64 << 10
	maxReadCaptureBytes    = 4 << 20
	maxReadCaptureAttempts = 256
)

type darwinReadConfig struct {
	workdir string
	enabled bool
}

type darwinReadCapture struct {
	root      *os.Root
	workdir   string
	proven    bool
	remaining int64
	attempts  int
}

func (s *sandboxSession) configureReadCapture(configs []darwinReadConfig) error {
	s.profile = sandboxProfile
	if len(configs) == 0 || !configs[0].enabled {
		return nil
	}
	dir := configs[0].workdir
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("macOS read capture: workspace: %w", err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("macOS read capture: open workspace: %w", err)
	}
	s.readCapture = &darwinReadCapture{root: root, workdir: dir, remaining: maxReadCaptureBytes}
	s.profile += fileReadReportRule(dir)
	return nil
}

func (s *sandboxSession) profileForRun() string {
	if s.profile != "" {
		return s.profile
	}
	return sandboxProfile
}

func (s *sandboxSession) closeReadCapture() {
	if s.readCapture != nil {
		_ = s.readCapture.root.Close()
	}
}

func (s *sandboxSession) readCanary() error {
	f, err := os.CreateTemp("", "cilock-read-canary-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, writeErr := f.WriteString("cilock read canary\n")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	path, err := filepath.EvalSymlinks(f.Name())
	if err != nil {
		return err
	}
	quoted := "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
	probe, ok := s.startHeldProbe("read _ 2>/dev/null; exec /bin/cat "+quoted,
		s.profileForRun()+`(allow file-read-data (literal `+strconv.Quote(path)+`) (with report))`)
	if !ok {
		return fmt.Errorf("macOS read capture: cannot start file-read probe")
	}
	probe.release()
	defer s.reapProbe(probe)
	deadline := time.Now().Add(probeWindow)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, ev := range s.events {
			if ev.pid == probe.pid && ev.canary && ev.op == opFileRead && ev.detail == path && !ev.denied {
				s.readCapture.proven = true
			}
		}
		proven := s.readCapture.proven
		s.mu.Unlock()
		if proven {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return fmt.Errorf("macOS read capture: file-read probe was not observed; refusing requested capture")
}

// Called with s.mu held. The unified log is machine-wide: do not open any
// reported file until live kernel facts establish that the process is ours.
func (s *sandboxSession) captureReadEvent(ev sandboxEvent) *FileSnapshot {
	if !s.ownsReadPID(ev.pid) {
		return &FileSnapshot{Status: "attribution-unproven-at-capture"}
	}
	return s.readCapture.snapshot(ev.detail)
}

func (c *darwinReadCapture) snapshot(path string) *FileSnapshot {
	result := &FileSnapshot{}
	if !filepath.IsAbs(path) {
		result.Status = "path-unresolved"
		return result
	}
	rel, err := filepath.Rel(c.workdir, filepath.Clean(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		result.Status = "outside-workspace"
		return result
	}
	if c.attempts >= maxReadCaptureAttempts || c.remaining <= 0 {
		result.Status = "capture-budget-exceeded"
		return result
	}
	c.attempts++
	// Root confines all symlink traversal. O_NONBLOCK avoids hanging on a FIFO
	// before Stat can reject it. No fallback follows an escaping symlink.
	f, err := c.root.OpenFile(rel, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		result.Status = readSnapshotOpenStatus(err)
		return result
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil {
		result.Status = "stat-failed"
		return result
	}
	if !before.Mode().IsRegular() {
		result.Status = "not-regular"
		return result
	}
	result.SizeBytes = before.Size()
	if before.Size() > maxReadSnapshotBytes {
		result.Status = "oversize"
		return result
	}
	limit := int64(maxReadSnapshotBytes + 1)
	if c.remaining < limit {
		limit = c.remaining
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	c.remaining -= int64(len(data))
	if err != nil {
		result.Status = "read-failed"
		return result
	}
	if int64(len(data)) == limit {
		result.Status = "size-or-budget-exceeded"
		return result
	}
	after, err := f.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || int64(len(data)) != before.Size() {
		result.Status = "changed-during-capture"
		return result
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		result.Status = "binary"
		return result
	}
	sum := sha256.Sum256(data)
	result.Digest = cryptoutil.DigestSet{{Hash: crypto.SHA256}: hex.EncodeToString(sum[:])}
	result.Content = string(data)
	result.Status = "captured-at-collector-open"
	return result
}

// Cached membership is insufficient before opening a file: a recycled PID
// could belong to another user of the machine. Re-prove the live ancestor
// chain against the recorded root incarnation, or withhold the snapshot.
func (s *sandboxSession) ownsReadPID(pid int) bool {
	if s.rootPid == 0 || !s.rootFacts.ok {
		return false
	}
	for hops := 0; hops < maxAncestryHops; hops++ {
		facts := pollProcFacts(pid)
		if !facts.ok {
			return false
		}
		if pid == s.rootPid {
			return samePidIncarnation(facts, s.rootFacts)
		}
		if facts.ppid <= 1 || facts.ppid == pid || !startedAfter(facts, s.rootFacts) {
			return false
		}
		pid = facts.ppid
	}
	return false
}

// Restrict generation in the kernel: filtering after delivery still pays the
// system/toolchain read volume and can exhaust the session's event budget.
func fileReadReportRule(workdir string) string {
	return `(allow file-read-data (subpath ` + strconv.Quote(workdir) + `) (with report))`
}

// Classify only what the open error establishes. Missing does not prove deletion,
// and lexical containment does not exclude a symlink escaping os.Root. Go exposes
// no public sentinel for that refusal, so other errors retain a scoped-open label.
func readSnapshotOpenStatus(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing-at-capture"
	case errors.Is(err, os.ErrPermission):
		return "permission-denied"
	default:
		return "scoped-open-failed"
	}
}
