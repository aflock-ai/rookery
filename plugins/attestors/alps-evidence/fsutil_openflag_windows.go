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

//go:build windows

package alpsevidence

// Non-Unix platforms have neither O_NONBLOCK nor O_NOFOLLOW in the portable
// os.OpenFile contract. Their process source reports agent observation as
// unavailable, so provider config readers are never reached in a live run.
const platformOpenFlags = 0

func isSymlinkRefusal(error) bool { return false }
