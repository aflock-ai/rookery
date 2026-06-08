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

package cli

import "testing"

// TestShouldWarnNotUploaded pins the policy for the "signed locally; not
// uploaded" first-run warning: it fires ONLY when a platform was configured but
// the run signed without enabling the Archivista upload, the run did not fatally
// fail, and the operator is not on the machine-readable JSON path.
func TestShouldWarnNotUploaded(t *testing.T) {
	cases := []struct {
		name              string
		platformURL       string
		archivistaEnabled bool
		runFailed         bool
		jsonOutput        bool
		want              bool
	}{
		{
			name:        "platform set, upload off, success, text → warn",
			platformURL: "https://platform.example.com",
			want:        true,
		},
		{
			name:              "upload enabled → no warn (it WAS uploaded)",
			platformURL:       "https://platform.example.com",
			archivistaEnabled: true,
			want:              false,
		},
		{
			name:        "offline (no platform) → no warn",
			platformURL: "",
			want:        false,
		},
		{
			name:        "failed run → no warn (nothing completed to upload)",
			platformURL: "https://platform.example.com",
			runFailed:   true,
			want:        false,
		},
		{
			name:        "json output → no warn (Uploaded:false carries it)",
			platformURL: "https://platform.example.com",
			jsonOutput:  true,
			want:        false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldWarnNotUploaded(tc.platformURL, tc.archivistaEnabled, tc.runFailed, tc.jsonOutput)
			if got != tc.want {
				t.Fatalf("shouldWarnNotUploaded(%q, enabled=%v, failed=%v, json=%v) = %v, want %v",
					tc.platformURL, tc.archivistaEnabled, tc.runFailed, tc.jsonOutput, got, tc.want)
			}
		})
	}
}
