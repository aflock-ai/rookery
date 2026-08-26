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

//go:build unix

package alpsevidence

// platformHasUnixBuildTag is the expectation TestFifoRegressionsAreInTheBuild
// checks against, DERIVED from the same constraint rather than restated as a
// hand-maintained GOOS list. The list it replaced named windows, js and plan9
// as the non-unix platforms and was wrong about wasip1, which also carries no
// unix tag. Anything the toolchain adds later is covered without an edit.
const platformHasUnixBuildTag = true
