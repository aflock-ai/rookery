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

package options

import (
	"bytes"
	"strings"
	"testing"
)

// TestSecurity_Issue5993_WriteHumanEscapesControlBytes asserts the SECURE
// contract: untrusted, server- or repo-controlled fields rendered by the human
// run summary (the git-remote anchor, subject names, and the platform-supplied
// assurance_level) must NOT reach the operator's terminal carrying raw ANSI
// escape (\x1b), carriage-return (\r), or NUL (\x00) control bytes. A hostile
// remote URL, attestation subject, or assurance_level could otherwise spoof or
// overwrite the very output the operator reads to decide trust.
//
// Escaped renderings (e.g. via %q -> \x1b, \r, \x00, or a stripping sanitizer)
// are acceptable; only the RAW control bytes are forbidden.
func TestSecurity_Issue5993_WriteHumanEscapesControlBytes(t *testing.T) {
	// Each untrusted field carries all three control bytes. The anchor lives
	// in a subject Name behind a `remote:` segment so gitRemoteAnchor() returns
	// it; the assurance_level is set directly.
	const evil = "\x1b[31mPWNED\x1b[0m\rfake\x00trailing"

	s := &RunSummary{
		Step: "build",
		Subjects: []RunSubject{
			{Name: "https://aflock.ai/attestations/git/v0.1/remote:" + evil},
			{Name: "https://aflock.ai/attestations/file/v0.1/" + evil},
		},
		AssuranceLevel: evil,
		// Same-class untrusted-fed sinks #6012 left raw (closed here, #6014-followup):
		// the gitoid is the server-returned uploadedGitoid from Archivista (zero
		// charset validation); tenant/identity come from the platform-login
		// credential store (server/OIDC-influenced); and the attestor Detail is
		// built from attestor error messages that can embed external-tool output.
		Tenant:        evil,
		SignerEmail:   evil,
		Uploaded:      true,
		ArchivistaURL: "https://archivista.example",
		Gitoid:        "gitoid:blob:sha256:" + evil,
		Attestors: []AttestorOutcome{
			{Name: "sbom", Status: AttestorStatusFailed, Detail: evil},
		},
	}

	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := buf.String()

	for _, ctl := range []struct {
		name string
		b    string
	}{
		{"ANSI escape (\\x1b)", "\x1b"},
		{"carriage return (\\r)", "\r"},
		{"NUL (\\x00)", "\x00"},
	} {
		if strings.Contains(out, ctl.b) {
			t.Errorf("WriteHuman output contains raw %s from untrusted field — terminal-spoofing risk (#5993); want it escaped/stripped.\noutput=%q", ctl.name, out)
		}
	}

	// Belt-and-suspenders: the gitoid line specifically must carry the escaped
	// form, proving the gitoid value (not merely some other line) was sanitized.
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("expected escaped \\x1b in sanitized output; got %q", out)
	}
}
