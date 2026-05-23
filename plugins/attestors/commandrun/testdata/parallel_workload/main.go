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

// parallel_workload is a controllable test harness for benchmarking the
// trace attestor under parallel-build-like workloads. It forks N child
// processes (using exec.Command, not goroutines, so each child is a
// distinct PID the tracer must follow). Each child performs M syscalls
// of a chosen type and exits.
//
// Usage:
//
//	parallel_workload -children=8 -ops=1000 -kind=openat -dir=/tmp/wl
//
// Kinds:
//
//	openat   - openat() M times on existing files
//	write    - write() to a new file, M bytes
//	linkat   - linkat() M times to create hardlinks
//	mkdir    - mkdir() then rmdir() pairs
//	mixed    - rotating mix of the above
//
// The harness writes a JSON summary to stdout at completion with PID
// list + per-child op counts, so the trace attestor's ProcessInfo can
// be validated against ground truth.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
)

type childResult struct {
	PID  int    `json:"pid"`
	Kind string `json:"kind"`
	Ops  int    `json:"ops"`
	Err  string `json:"err,omitempty"`
}

type summary struct {
	Children []childResult `json:"children"`
	Kind     string        `json:"kind"`
	OpsEach  int           `json:"opsEach"`
}

func main() {
	children := flag.Int("children", 4, "number of child processes to spawn")
	ops := flag.Int("ops", 100, "syscalls per child")
	kind := flag.String("kind", "openat", "syscall kind: openat|write|linkat|mkdir|mixed")
	dir := flag.String("dir", "", "working dir (auto if empty)")
	worker := flag.Bool("__worker", false, "internal: run as child worker")
	flag.Parse()

	if *worker {
		// Child mode — perform the syscalls and exit.
		runChild(*kind, *ops, *dir)
		return
	}

	if *dir == "" {
		var err error
		*dir, err = os.MkdirTemp("", "parallel-wl-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "mkdtemp:", err)
			os.Exit(1)
		}
		defer os.RemoveAll(*dir) //nolint:errcheck
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	if *kind == "openat" {
		// Pre-create files the children will openat.
		for i := 0; i < *ops; i++ {
			path := filepath.Join(*dir, "in_"+strconv.Itoa(i))
			if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "seed:", err)
				os.Exit(1)
			}
		}
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "executable:", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	results := make([]childResult, *children)
	for i := 0; i < *children; i++ {
		i := i
		childDir := filepath.Join(*dir, "c"+strconv.Itoa(i))
		_ = os.MkdirAll(childDir, 0o755)
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(exe,
				"-__worker",
				"-kind="+*kind,
				"-ops="+strconv.Itoa(*ops),
				"-dir="+childDir)
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			r := childResult{Kind: *kind, Ops: *ops}
			if cmd.Process != nil {
				r.PID = cmd.Process.Pid
			}
			if err != nil {
				r.Err = err.Error()
			}
			results[i] = r
		}()
	}
	wg.Wait()

	out := summary{Children: results, Kind: *kind, OpsEach: *ops}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func runChild(kind string, ops int, dir string) {
	switch kind {
	case "openat":
		runOpenat(ops, dir)
	case "write":
		runWrite(ops, dir)
	case "linkat":
		runLinkat(ops, dir)
	case "mkdir":
		runMkdir(ops, dir)
	case "mixed":
		// rotate through the kinds
		each := ops / 4
		runOpenat(each, dir)
		runWrite(each, dir)
		runLinkat(each, dir)
		runMkdir(each, dir)
	default:
		fmt.Fprintln(os.Stderr, "unknown kind:", kind)
		os.Exit(2)
	}
}

func runOpenat(ops int, dir string) {
	// Open M existing files. Path is the parent dir's input/in_N (parent
	// pre-created them).
	parent := filepath.Dir(dir)
	for i := 0; i < ops; i++ {
		path := filepath.Join(parent, "in_"+strconv.Itoa(i%ops))
		f, err := os.Open(path) //nolint:gosec
		if err != nil {
			// If parent didn't pre-create them, the openat still happens
			// even on failure — the attestor records the attempt.
			continue
		}
		_ = f.Close()
	}
}

func runWrite(ops int, dir string) {
	target := filepath.Join(dir, "out")
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck
	buf := []byte("x")
	for i := 0; i < ops; i++ {
		_, _ = f.Write(buf)
	}
}

func runLinkat(ops int, dir string) {
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("link-src"), 0o600); err != nil {
		return
	}
	for i := 0; i < ops; i++ {
		dst := filepath.Join(dir, "lnk_"+strconv.Itoa(i))
		_ = os.Link(src, dst)
	}
}

func runMkdir(ops int, dir string) {
	for i := 0; i < ops; i++ {
		d := filepath.Join(dir, "d_"+strconv.Itoa(i))
		_ = os.Mkdir(d, 0o755)
		_ = os.Remove(d)
	}
}
