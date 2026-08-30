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

//go:build !unix

package instructionfile

// unixSwapCases contributes nothing outside the Unix syscall family: mkfifo has
// no portable equivalent, and the platforms that lack it also lack the
// no-follow open flag the sweep is characterizing.
func unixSwapCases() []swapCase { return nil }
