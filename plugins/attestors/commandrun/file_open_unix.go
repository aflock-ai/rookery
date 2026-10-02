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

//go:build !windows

package commandrun

import (
	"os"
	"syscall"
)

// openForHashing resolves `path` EXACTLY ONCE and hands back the descriptor
// that resolution produced. Every stat afterwards is an fstat of this
// descriptor, so a name swapped after the open cannot change what is hashed
// or what the digest is reported for.
//
// O_NONBLOCK keeps the open of a FIFO from blocking on a writer that will
// never come; digestOpenFile then refuses it, because the descriptor's fstat
// says it is not a regular file. That is stricter than the code this
// replaces, which stat'd the name, saw "not a directory", and went on to
// open and read it -- draining a pipe the tracee was waiting on, or reading
// a character device without end.
func openForHashing(path string) (*os.File, error) {
	pathResolutions.Add(1)
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: hashing a path the tracee named is this attestor's whole job
}

// bracketBefore and statForBracket: off Windows the identity is in the
// ordinary stat of the descriptor, so the settle's own stat is the pre-read
// stat and the post-read stat is f.Stat().
func bracketBefore(_ *os.File, settled os.FileInfo) (os.FileInfo, error) { return settled, nil }

func statForBracket(f *os.File) (os.FileInfo, error) { return f.Stat() }
