// jade:ring local
// Copyright 2021 The Witness Contributors
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

//go:build windows

package commandrun

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// While the hashing handle is open nobody else can open the file for write,
// so an equal-length rewrite with a restored mtime cannot land mid-read
// (issue #10571). If the share mode ever admits writers again this fails.
func TestWindowsHashingHandleDeniesWriters(t *testing.T) {
	p := filepath.Join(t.TempDir(), "prog.exe")
	if err := os.WriteFile(p, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openForHashing(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if w, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
		w.Close()
		t.Fatal("a writer opened the file while the hashing handle was held")
	}
}

// A same-size rewrite with mtime restored between the stats changes
// ChangeTime, which the bracket compares; the stat carries a handle identity
// and never degrades to size and modification time.
func TestWindowsBracketCarriesHandleIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "prog.exe")
	if err := os.WriteFile(p, []byte("AAAA"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openForHashing(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := statForBracket(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := identityFromInfo(st); !ok {
		t.Fatal("the handle stat carries no identity")
	}
	f.Close()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := identityFromInfo(fi); ok {
		t.Fatal("a plain name stat (size and mtime) must not be comparable")
	}

	f, err = openForHashing(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, _ := statForBracket(f)
	time.Sleep(20 * time.Millisecond)
	after, _ := statForBracket(f)
	if err := observedUnchanged(before, after); err != nil {
		t.Fatalf("an undisturbed handle must compare equal: %v", err)
	}
}
