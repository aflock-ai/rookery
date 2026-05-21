// Copyright 2025 The Aflock Authors
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

package ociref

import "testing"

// TestParse_ShortRefs exercises the docker-hub-style implicit defaults that
// `name.ParseReference` from go-containerregistry handled. These are the most
// common inputs we'll see in real Kubernetes manifests.
func TestParse_ShortRefs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantHost  string
		wantRepo  string
		wantTag   string
		wantDgst  string
		expectErr bool
	}{
		{
			name:     "bare name → docker.io/library defaults",
			input:    "nginx",
			wantHost: "registry-1.docker.io",
			wantRepo: "library/nginx",
			wantTag:  "latest",
		},
		{
			name:     "bare name with tag",
			input:    "nginx:1.27",
			wantHost: "registry-1.docker.io",
			wantRepo: "library/nginx",
			wantTag:  "1.27",
		},
		{
			name:     "two-component name (user/img) defaults host",
			input:    "library/nginx:1.27",
			wantHost: "registry-1.docker.io",
			wantRepo: "library/nginx",
			wantTag:  "1.27",
		},
		{
			name:     "fully-qualified host + repo",
			input:    "gcr.io/google-containers/pause",
			wantHost: "gcr.io",
			wantRepo: "google-containers/pause",
			wantTag:  "latest",
		},
		{
			name:     "fully-qualified with tag",
			input:    "gcr.io/google-containers/pause:3.1",
			wantHost: "gcr.io",
			wantRepo: "google-containers/pause",
			wantTag:  "3.1",
		},
		{
			name:     "registry with port",
			input:    "localhost:5000/img:latest",
			wantHost: "localhost:5000",
			wantRepo: "img",
			wantTag:  "latest",
		},
		{
			name:     "digest reference",
			input:    "nginx@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			wantHost: "registry-1.docker.io",
			wantRepo: "library/nginx",
			wantDgst: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			name:     "fully qualified with digest",
			input:    "gcr.io/foo/bar@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			wantHost: "gcr.io",
			wantRepo: "foo/bar",
			wantDgst: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		},
		{
			name:      "empty ref errors",
			input:     "",
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := Parse(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got ref=%+v", ref)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ref.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", ref.Host, tc.wantHost)
			}
			if ref.Repo != tc.wantRepo {
				t.Errorf("Repo = %q, want %q", ref.Repo, tc.wantRepo)
			}
			if ref.Tag != tc.wantTag {
				t.Errorf("Tag = %q, want %q", ref.Tag, tc.wantTag)
			}
			if ref.Digest != tc.wantDgst {
				t.Errorf("Digest = %q, want %q", ref.Digest, tc.wantDgst)
			}
		})
	}
}

// TestParse_IdentifierForRequest covers the convenience that gives back the
// pull-by-identifier — digest if set, otherwise tag.
func TestParse_IdentifierForRequest(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nginx", "latest"},
		{"nginx:1.27", "1.27"},
		{"foo@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"sha256:0000000000000000000000000000000000000000000000000000000000000000"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			ref, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := ref.Identifier(); got != tc.want {
				t.Errorf("Identifier() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParse_RejectsObviouslyMalformed catches inputs that would break URL
// construction downstream.
func TestParse_RejectsObviouslyMalformed(t *testing.T) {
	for _, in := range []string{
		":",
		"@",
		"foo:",
		"foo@",
		"foo@sha256:short",         // digest is the right shape but too short
		"foo@nosuchalgo:abcdef0123", // unknown digest algorithm
	} {
		t.Run(in, func(t *testing.T) {
			if _, err := Parse(in); err == nil {
				t.Errorf("expected error for input %q", in)
			}
		})
	}
}
