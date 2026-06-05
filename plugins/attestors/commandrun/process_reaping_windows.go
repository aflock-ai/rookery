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

import "os/exec"

// configureProcessReaping is a no-op on Windows: there is no Setpgid /
// process-group signalling in syscall.SysProcAttr, and syscall.Kill does
// not exist. The c.WaitDelay set by the caller still bounds the post-exit
// I/O wait and force-closes the pipes, so c.Wait() can never hang forever
// even without group reaping.
func configureProcessReaping(c *exec.Cmd) {}
