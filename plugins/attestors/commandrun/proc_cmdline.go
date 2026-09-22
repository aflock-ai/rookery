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

package commandrun

import (
	"strings"

	"github.com/aflock-ai/rookery/attestation/redact"
)

// procCmdline turns the bytes of /proc/<pid>/cmdline, argv joined by NULs,
// into the Cmdline a traced process is signed with: the elements joined by
// one space, with the ends trimmed.
//
// Each element loses the userinfo of a URL in it BEFORE the join, read whole
// as redactArgv reads the top-level cmd (redact.URLCredentialsInArg). The
// join is where the argv boundaries go: a password holding a space
// ("http://u:my pw@proxy:3128", a credential to Node's WHATWG parser) is one
// element here and two words in the joined line, where the end-of-run text
// scrub (redactProcessCmdlines) finds no URL in either. The traced
// top-level process has the same argv as cmd, so without this the password
// redactArgv takes out of cmd would be signed again in Cmdlines[].
//
// An element whose redaction names no host ends in "******@". When another
// element follows, a '/' is written after it, as the text scrub writes one,
// so the next element is not read as the host.
//
// The values of sensitive environment variables are masked first, over the
// whole cmdline (redactSensitiveEnvValuesInCmdline), as redactArgv and
// redactOutput mask them before the URL scrub. That scrub finds a value byte
// for byte, and the URL scrub rewrites the bytes: once the userinfo of
// API_TOKEN="https://u:pw@host/?token=..." is gone, the end-of-run pass no
// longer finds the value, and the query token, which is not userinfo, would
// be signed.
func procCmdline(raw string) string {
	raw = redactSensitiveEnvValuesInCmdline(raw)
	args := strings.Split(raw, "\x00")
	last := len(args) - 1
	for last >= 0 && strings.TrimSpace(args[last]) == "" {
		last--
	}
	for i, arg := range args {
		redacted := redact.URLCredentialsInArg(arg)
		if redacted != arg && i < last && strings.HasSuffix(redacted, redact.Marker+"@") {
			redacted += "/"
		}
		args[i] = redacted
	}
	return strings.TrimSpace(strings.Join(args, " "))
}
