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

package redact

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// textCases is shared by TestURLCredentialsInText, which pins each output,
// and TestURLCredentialsInTextNamesNoOtherHost.
var textCases = []struct {
	name, in, want string
}{
	// The leak the e1 review found: printed environment and a proxy flag.
	{"printed proxy variable", "HTTP_PROXY=http://u:p1secret-proxy@proxy:3128\n", "HTTP_PROXY=http://******@proxy:3128\n"},
	{"curl proxy flag", "curl -x http://u:p1secret-proxy@proxy:3128 https://example.com", "curl -x http://******@proxy:3128 https://example.com"},
	{"scheme-less proxy flag", "curl -x u:pw@proxy:3128 https://example.com", "curl -x ******@proxy:3128 https://example.com"},
	{"flag with equals", "--proxy=u:pw@proxy:3128", "******@proxy:3128"},
	{"scheme-less assignment", "HTTPS_PROXY=u:pw@proxy:3128", "******@proxy:3128"},
	{"quoted shell assignment", `export HTTPS_PROXY="u:pw@proxy:3128";`, `export ******@proxy:3128";`},
	{"json value", `{"proxy":"http://u:pw@proxy:3128"}`, `{"proxy":"http://******@proxy:3128"}`},
	// WHATWG ends the authority at the '\' and dials "domain", Python dials
	// proxy: no host is named.
	{"windows domain user", `set HTTPS_PROXY=DOMAIN\user:pw@proxy:8080`, `set ******@`},
	{"git clone token", "Cloning https://x-access-token:ghs_abc@github.com/o/r.git\n", "Cloning https://******@github.com/o/r.git\n"},
	{"several lines, one credential each", "a http://u:one@h1\r\nb https://v:two@h2/x\n", "a http://******@h1\r\nb https://******@h2/x\n"},
	{"separators kept byte for byte", "\t http://u:p@h \x00 x@y\f", "\t http://******@h \x00 x@y\f"},
	// A tab ends a word like a space does. Read as one word, the URL
	// would run to the email's at-sign and take the address with it.
	{"tab-separated columns", "http://u:p@proxy:3128\talice@example.com\n", "http://******@proxy:3128\talice@example.com\n"},
	{"carriage return ends a word", "http://u:p@proxy:3128\ralice@example.com", "http://******@proxy:3128\ralice@example.com"},

	// The e1 re-review's blocking finding: "******@github.com" would claim
	// the fetch came from github.com, while Go, WHATWG and curl connect to
	// evil.example. Python's proxy parser reads a userinfo through the
	// '/', so the URL keeps no host.
	{"at-sign in the path after a plain host", "echo fetching https://evil.example/payload.sh@github.com/actions/runner\n", "echo fetching https://******@/\n"},
	{"two at-signs in the authority", "curl https://a@evil.example@github.com/x\n", "curl https://******@/\n"},
	// Python's proxy parser takes a userinfo through a '?' or '#' to a
	// later at-sign, and sends that tail as the password.
	{"credential, query, later at-sign", "curl -x http://u:first@proxy-a?p1sec-tail@proxy-b:3128 x\n", "curl -x http://******@/ x\n"},
	{"credential, fragment, later at-sign", "HTTP_PROXY=http://u:first@proxy-a#p1sec-tail@proxy-b:3128\n", "HTTP_PROXY=http://******@/\n"},
	{"credential, query, later at-sign, quoted", `export HTTP_PROXY="http://u:first@proxy-a?p1sec-tail@proxy-b:3128";`, `export HTTP_PROXY="http://******@/";`},
	{"credential, path, later at-sign", "pip install git+https://u:p1sec@git.example/o/r.git@v1.2\n", "pip install git+https://******@git.example/o/r.git@v1.2\n"},
	// An empty userinfo does not end the search: Python's proxy parser
	// sends "p4sec" to proxy-b.
	{"empty userinfo, query, later userinfo", "curl -x http://@proxy-a?user:p4sec@proxy-b:3128 https://example.com", "curl -x http://******@/ https://example.com"},
	{"empty userinfo, fragment, later userinfo, assignment", "HTTP_PROXY=http://@proxy-a#user:p4sec@proxy-b:3128\n", "HTTP_PROXY=http://******@/\n"},
	{"empty userinfo, query and fragment, later userinfo", "curl -x http://@proxy-a?q#user:p4sec@proxy-b:3128 x", "curl -x http://******@/ x"},
	{"empty userinfo, query, later userinfo, json", `{"proxy":"http://@proxy-a?user:p4sec@proxy-b:3128"}`, `{"proxy":"http://******@/"}`},
	{"empty userinfo, path, later at-sign", "curl -x http://@proxy-a/tail@proxy-b:3128 x", "curl -x http://@proxy-a/tail@proxy-b:3128 x"},
	// A word is read whole as well as after a "KEY=": '=' is a byte of a
	// credential (base64 pads with it), so the part before it can be a
	// token. Where the whole word reads as a credential, the key goes with
	// it.
	{"positional padded token", "curl -x cDRzZWNyZXQ=@proxy:3128 https://example.com", "curl -x ******@proxy:3128 https://example.com"},
	{"positional double-padded token", "curl -x cDRzZWNyZQ==@proxy:3128 x", "curl -x ******@proxy:3128 x"},
	{"padded user and a password", "curl -x cDRzZWNyZXQ=:p4sec@proxy:3128 x", "curl -x ******@proxy:3128 x"},
	{"equals inside a user", "curl -x p4usr=tail:p4sec@proxy:3128 x", "curl -x ******@proxy:3128 x"},
	{"equals inside a token", "curl -x p4tok=tail@proxy:3128 x", "curl -x ******@proxy:3128 x"},
	// The whole reading comes first: after its key, this value keeps no
	// host, and nothing is left for the whole reading to take the key with.
	{"equals inside a user, slash in the password", "curl -x p4usr=tail:p4/sec@proxy:3128 x", "curl -x ******@/ x"},
	{"quoted padded token", `curl -x "cDRzZWNyZXQ=@proxy:3128" x`, `curl -x "******@proxy:3128" x`},
	{"padded token after an assignment", "HTTPS_PROXY=cDRzZWNyZXQ=@proxy:3128\n", "******@proxy:3128\n"},
	{"equals inside a password", "curl -x u:q16a=q16b@proxy:3128 x", "curl -x ******@proxy:3128 x"},
	{"padded token with a scheme", "curl -x http://cDRzZWNyZXQ=@proxy:3128 x", "curl -x http://******@proxy:3128 x"},
	{"padded token, json value", `{"proxy":"cDRzZWNyZXQ=@proxy:3128"}`, `{"proxy":"******@proxy:3128"}`},
	// The same without a scheme: Go and curl dial evil.example, only
	// Python's proxy parser reads github.com.
	{"scheme-less path at-sign", "evil.example:8080/payload.sh@github.com/actions/runner\n", "******@/\n"},
	{"scheme-less query at-sign", "curl -x evil.example:80?@github.com x", "curl -x ******@/ x"},
	{"scheme-less fragment at-sign", "curl -x evil.example:80#@github.com x", "curl -x ******@/ x"},
	{"scheme-less backslash at-sign", `curl -x evil.example:80\@github.com x`, "curl -x ******@/ x"},
	{"whatwg scheme without slashes", "fetch http:evil.example/x@github.com", "fetch ******@"},
	{"whatwg backslash scheme", `fetch http:\\evil.example\x@github.com`, "fetch ******@"},
	{"go module path behind a proxy host", "GOPROXY=goproxy.internal:8080/mod@v1.2.3", "******@"},
	// JSON with escaped slashes, PHP json_encode's default.
	{"json with escaped slashes", `{"url":"https:\/\/u:S3CR3T@repo.example.com\/packages.json"}`, `{"url":"https:\/\/******@repo.example.com\/packages.json"}`},
	{"json with escaped slashes, at-sign in the path", `{"url":"https:\/\/evil.example\/x@github.com"}`, `{"url":"https:\/\/******@/"}`},
	// A scheme-less credential inside JSON, a Python dict, brackets, or
	// at the end of a sentence.
	{"scheme-less json value", `{"proxy":"u:S3CR3T@proxy:3128"}`, `{"proxy":"******@proxy:3128"}`},
	{"scheme-less python dict value", `{'http': 'u:S3CR3T@proxy:3128'}`, `{'http': '******@proxy:3128'}`},
	{"scheme-less in square brackets", "[u:S3CR3T@proxy:3128]", "[******@proxy:3128]"},
	{"scheme-less in angle brackets", "<u:S3CR3T@proxy:3128>", "<******@proxy:3128>"},
	{"scheme-less in braces", "{u:S3CR3T@proxy:3128}", "{******@proxy:3128}"},
	{"scheme-less at the end of a sentence", "via u:S3CR3T@proxy:3128.", "via ******@proxy:3128."},
	{"scheme-less before a colon", "proxy u:S3CR3T@proxy:3128: refused", "proxy ******@proxy:3128: refused"},
	// A host that is only a '.' is not taken off as the end of a sentence.
	{"host that is a dot", "u:S3CR3T@.", "******@."},
	// The wider trim redacts the inner URL; only the narrower one then
	// sees the scheme-less credential around it.
	{"word fixpoint across both trims", "mailto:http://http://a@.", "******@/."},
	// A host dropped before trailing punctuation is followed by a '/', so
	// the punctuation is not read as the host.
	{"dropped host before a comma", "see http://a@evil.example@github.com, ok", "see http://******@/, ok"},
	{"dropped host before a quote", `{"url":"https://evil.example/x@github.com"}`, `{"url":"https://******@/"}`},
	// Python's proxy parser reads "sec<ret/part" as the password. Only the
	// unescaped byte closing the quote that opens a URL ends it in text, so
	// the compact JSON log and the XML line below keep their email address.
	{"password with a byte no url holds, json field", `{"proxy":"http://u:sec<ret/part@proxy:3128","n":1}`, `{"proxy":"http://******@/}`},
	{"password with an escaped quote, json field", `{"proxy":"http://u:sec\"ret/part@proxy:3128","n":1}`, `{"proxy":"http://******@/}`},
	{"password with a byte no url holds, glued", "proxy=http://u:sec`ret/part@proxy:3128,no_proxy=localhost", "proxy=http://******@"},
	{"password with an unescaped quote, quoted", `echo "http://u:sec"ret/part@proxy:3128"`, `echo "http://******@/"`},

	// A token in the username slot of "user@host:port" is sent by Go and
	// curl with an empty password; a port says it is not an email address.
	{"scheme-less user and port", "curl -x ghp_usertoken@proxy:3128 x", "curl -x ******@proxy:3128 x"},
	{"scheme-less user and port, assignment", "ALL_PROXY=tok@proxy:3128\n", "******@proxy:3128\n"},
	// Text cuts a word at a space, so of a password holding one only the
	// part before the space survives: the residual URLCredentialsInText
	// documents. The part after it is "user@host:port" and goes.
	{"scheme-less space in password, in text", "HTTPS_PROXY=u:my secret@proxy:3128\n", "HTTPS_PROXY=u:my ******@proxy:3128\n"},

	// Text that must come back unchanged.
	{"email then a port-less host", "mail alice@example.com: ok", "mail alice@example.com: ok"},
	{"prose with a colon, in text", "Contact: help@example.com\n", "Contact: help@example.com\n"},
	{"compact json log", `{"level":"info","url":"https://api.example.com/v1","author":"alice@example.com","status":"PASS"}`, `{"level":"info","url":"https://api.example.com/v1","author":"alice@example.com","status":"PASS"}`},
	{"json email", `{"author":"alice@example.com"}`, `{"author":"alice@example.com"}`},
	{"xml line with an email", "<url>https://h.example/x</url><email>a@b.example</email>", "<url>https://h.example/x</url><email>a@b.example</email>"},
	{"url then an email on a later line", "https://jira.example/browse/ABC-1 fix\n\nSigned-off-by: Alice <alice@example.com>\n", "https://jira.example/browse/ABC-1 fix\n\nSigned-off-by: Alice <alice@example.com>\n"},
	{"url then a bare email", "see https://example.com/x or mail alice@example.com", "see https://example.com/x or mail alice@example.com"},
	{"scp-style git remote", "git@github.com:org/repo.git", "git@github.com:org/repo.git"},
	{"go module version", "go: downloading github.com/foo/bar@v1.2.3", "go: downloading github.com/foo/bar@v1.2.3"},
	{"package urls", "pkg:npm/lodash@4.17.21 pkg:golang/github.com/foo/bar@v1.2.3", "pkg:npm/lodash@4.17.21 pkg:golang/github.com/foo/bar@v1.2.3"},
	{"image digest", "docker.io/library/node@sha256:" + testDigest, "docker.io/library/node@sha256:" + testDigest},
	{"path list", "PATH=/usr/bin:/opt/homebrew/opt/python@3.11/bin", "PATH=/usr/bin:/opt/homebrew/opt/python@3.11/bin"},
	{"mailto and action refs", "mailto:alice@example.com actions/checkout@v4 @scope/pkg@1.2.3", "mailto:alice@example.com actions/checkout@v4 @scope/pkg@1.2.3"},
	{"no at-sign", "time=12:00:01 GET https://example.com/x 200", "time=12:00:01 GET https://example.com/x 200"},
	// An assignment whose value is an email address or an scp-style remote
	// reads as no credential whole or after its key.
	{"assignment of an email", "user=alice@example.com author=Alice", "user=alice@example.com author=Alice"},
	{"assignment of an scp-style remote", "ssh_url=git@github.com:org/repo.git", "ssh_url=git@github.com:org/repo.git"},
	{"assignments without an at-sign", "GOFLAGS=-mod=mod CGO_ENABLED=0 a=b==", "GOFLAGS=-mod=mod CGO_ENABLED=0 a=b=="},
	{"empty", "", ""},

	// Deliberate over-redaction: an at-sign past a plain host is a path
	// for Go, WHATWG and curl, and ends a userinfo for Python's proxy
	// parser. Shape cannot tell which, so the URL keeps no host.
	{"pip vcs ref", "pip install git+https://github.com/org/repo@v1.2.3", "pip install git+https://******@"},
	// Deliberate over-redaction: a package URL after a "KEY=" is not the
	// reference shape once the word is read whole, and Python's proxy
	// parser reads user "PURL=pkg" and password "npm/lodash" in it.
	{"package url after an assignment", "PURL=pkg:npm/lodash@4.17.21", "******@"},
	{"scoped npm url", "https://www.npmjs.com/package/@scope/pkg", "https://******@"},
}

func TestURLCredentialsInText(t *testing.T) {
	for _, tc := range textCases {
		t.Run(tc.name, func(t *testing.T) {
			got := URLCredentialsInText(tc.in)
			require.Equal(t, tc.want, got, "input %q", tc.in)
			assert.Equal(t, got, URLCredentialsInText(got), "redaction must be idempotent")
		})
	}
}

// checkTextNamesNoOtherHost is checkNamesNoOtherHost for text. Text is
// many values, and a redaction that removes the first URL of a line moves a
// whole-line reading onto the next one, so every reading of the output, whole
// or by field, may name only a host that some reading of the input names.
func checkTextNamesNoOtherHost(t *testing.T, real, signed string) {
	t.Helper()
	checkEachHostIsNamedBy(t, real, signed, hostReadings(signed))
}

// No redacted text names a host that its original does not.
func TestURLCredentialsInTextNamesNoOtherHost(t *testing.T) {
	for _, tc := range textCases {
		t.Run(tc.name, func(t *testing.T) {
			checkTextNamesNoOtherHost(t, tc.in, URLCredentialsInText(tc.in))
		})
	}
}

func TestURLCredentialsInArg(t *testing.T) {
	for in, want := range map[string]string{
		// An element that is a URL is read whole.
		"http://u:my p3secret@proxy:3128":   "http://******@proxy:3128",
		"  http://u:my p3secret@proxy:3128": "  http://******@proxy:3128",
		"jdbc:postgresql://u:my pw@db/app":  "******@",
		// Anything else is text, where a password holding a space is two
		// words and neither is a URL: the residual URLCredentialsInText
		// documents. The word after the space is "user@host:port", which
		// Go and curl send as a user, so it goes.
		"echo http://u:my p3secret@proxy:3128": "echo http://u:my ******@proxy:3128",
		// An element that is a scheme-less proxy value is read whole too:
		// Python's urllib sends a password holding a space or a tab.
		// Read whole, "HTTP_PROXY=u" and "--proxy=u" are users: '=' is a
		// byte of a credential, so the key is not taken on trust and goes
		// with the userinfo (see URLCredentialsInArg).
		"u:my secret@proxy:3128":             "******@proxy:3128",
		"HTTP_PROXY=u:my secret@proxy:3128":  "******@proxy:3128",
		"--proxy=u:my\tsecret@proxy:3128":    "******@proxy:3128",
		"my user:my secret@proxy:3128":       "******@proxy:3128",
		"ghp_usertoken@proxy:3128":           "******@proxy:3128",
		"--proxy=ghp_usertoken@proxy:3128":   "******@proxy:3128",
		"alice@example.com":                  "alice@example.com",
		"Reviewed-by: Alice <a@example.com>": "Reviewed-by: Alice <a@example.com>",
		"plain value with spaces":            "plain value with spaces",
		"--proxy=u:p@proxy:3128":             "******@proxy:3128",
		// A positional proxy value whose token is padded: read after the
		// "KEY=" it seems to open with, the token is the key and the value
		// is an empty userinfo.
		"cDRzZWNyZXQ=@proxy:3128":             "******@proxy:3128",
		"cDRzZWNyZQ==@proxy:3128":             "******@proxy:3128",
		"cDRzZWNyZXQ=:p4sec@proxy:3128":       "******@proxy:3128",
		"p4usr=tail:p4sec@proxy:3128":         "******@proxy:3128",
		"p4tok=tail@proxy:3128":               "******@proxy:3128",
		"p4tok=tail:my p4sec@proxy:3128":      "******@proxy:3128",
		"p4usr=tail:p4/sec@proxy:3128":        "******@",
		"--proxy=cDRzZWNyZXQ=@proxy:3128":     "******@proxy:3128",
		"u:q16a=q16b@proxy:3128":              "******@proxy:3128",
		"http://cDRzZWNyZXQ=@proxy:3128":      "http://******@proxy:3128",
		"user=alice@example.com":              "user=alice@example.com",
		"ssh_url=git@github.com:org/repo.git": "ssh_url=git@github.com:org/repo.git",
		"GOFLAGS=-mod=mod":                    "GOFLAGS=-mod=mod",
		// An empty userinfo does not end the search (see URLCredentials).
		"http://@proxy-a?user:p4sec@proxy-b:3128":            "http://******@",
		"--proxy=http://@proxy-a#user:p4sec@proxy-b:3128":    "--proxy=http://******@",
		"HTTP_PROXY=http://@proxy-a?user:p4sec@proxy-b:3128": "HTTP_PROXY=http://******@",
		"http://@proxy-a/tail@proxy-b:3128":                  "http://@proxy-a/tail@proxy-b:3128",
		`echo "fetching http://u:p@h"; true`:                 `echo "fetching http://******@h"; true`,
		// A script whose first word ends in '=' is not a flag.
		`echo "HTTP_PROXY=http://u:p@proxy:3128"; echo "u:q@proxy:3128" 1>&2`: `echo "HTTP_PROXY=http://******@proxy:3128"; echo "******@proxy:3128" 1>&2`,
		"see http://u:p@h and a@b.example":                                    "see http://******@h and a@b.example",
		// So is a flag whose value is a URL.
		"--url=http://u:my p3secret@proxy:3128": "--url=http://******@proxy:3128",
		// WHATWG removes every tab, LF and CR before it parses, so each of
		// these is http://u:p3secret@proxy:3128 to Node. The element is
		// recognised in that reading and read whole; as text it splits at
		// the tab and "/u:p3secret@proxy:3128" reads as a path.
		"http:/\t/u:p3secret@proxy:3128": "******@",
		"http:\t//u:p3secret@proxy:3128": "******@",
		"http:/\n/u:p3secret@proxy:3128": "******@",
		// A tab inside the scheme leaves a URL inside text, whose userinfo
		// already goes and whose host every reading shares.
		"ht\ttp://u:p3secret@proxy:3128":             "ht\ttp://******@proxy:3128",
		"--proxy=http:/\t/u:p3secret@proxy:3128":     "--proxy=******@",
		"HTTPS_PROXY=http:/\r/u:p3secret@proxy:3128": "HTTPS_PROXY=******@",
		// Python's proxy parser reads a later at-sign as the end of the
		// userinfo when no '/' comes between (see URLCredentials).
		"http://u:first@proxy-a?p3secret@proxy-b:3128":         "http://******@",
		"--proxy=http://u:first@proxy-a#p3secret@proxy-b:3128": "--proxy=http://******@",
		"http://u:first@proxy-a/tail@proxy-b:3128":             "http://******@proxy-a/tail@proxy-b:3128",
	} {
		assert.Equal(t, want, URLCredentialsInArg(in), "input %q", in)
	}
}

// A word is exactly what URLCredentials reads, so for a value with no URL
// space and no assignment or quote around it the two agree. This pins the
// text form to the environment form, so the two cannot drift apart.
func TestURLCredentialsInTextAgreesWithURLCredentialsOnOneWord(t *testing.T) {
	for _, in := range []string{
		"http://u:secret@proxy:3128",
		"u:secret@proxy:3128",
		`DOMAIN\user:\secret@proxy:8080`,
		"socks5h://u:p@h",
		"postgres://u:p@h1,h2/db",
		"https://registry.npmjs.org/@scope/pkg",
		"pkg:npm/lodash@4.17.21",
		"/usr/bin:/opt/x@1/bin",
	} {
		assert.Equal(t, URLCredentials(in), URLCredentialsInText(in), "input %q", in)
	}
}

// No input may panic, the output must be stable under a second pass, and it
// must name no host the input does not.
func FuzzURLCredentialsInText(f *testing.F) {
	for _, s := range []string{"HTTP_PROXY=http://u:p@h:1\n", `x="u:p@h:1";`, "a=b=c@d", "'", "=@", "\"@\"", "dG9rZW4=@proxy:3128", "k=http://@a?u:p@b:1", `{"p":"x://u:a\"<b/c@h:1","n":1}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		once := URLCredentialsInText(s)
		if twice := URLCredentialsInText(once); twice != once {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, once, twice)
		}
		if !strings.Contains(s, "@") && once != s {
			t.Fatalf("changed text with no at-sign: %q -> %q", s, once)
		}
		checkTextNamesNoOtherHost(t, s, once)
	})
}

// A line of output is chosen by whatever the command runs, so its shape can
// be adversarial. Each of these took seconds to tens of seconds at 192 KB
// when every separator rescanned the line to its end; linear work does it in
// milliseconds. The bound is loose enough for a loaded machine and far below
// what quadratic work takes at this size.
func TestURLCredentialsInTextIsLinearOnAdversarialLines(t *testing.T) {
	const n = 64000
	for name, in := range map[string]string{
		"separator and at-sign":         strings.Repeat("x://a@", n),
		"escaped separator and at-sign": strings.Repeat(`x:\/\/a@`, n),
		"at-signs then separators":      strings.Repeat("@", n) + strings.Repeat("x://y", n),
		"scheme-less userinfos":         strings.Repeat("u:p@", n) + "h",
		"many at-signs in one url":      "https://" + strings.Repeat("a@", n) + "h",
		"separators and spaces":         strings.Repeat("x://a@b ", n),
		// The only at-sign starts an image digest, so no separator has a
		// userinfo, and each one used to read the rest of the line to find
		// that out: to the end for a closing quote, and back from the
		// digest for an earlier at-sign.
		"separators then an image digest":         strings.Repeat("x://", n) + "h/img@sha256:" + strings.Repeat("a", 64),
		"escaped separators then an image digest": strings.Repeat(`x:\/\/`, n) + "h/img@sha256:" + strings.Repeat("a", 64),
		"separators then a quoted at-sign":        strings.Repeat("x://", n) + `"@`,
		"separators and quotes then an at-sign":   strings.Repeat(`x://"`, n) + "@",
		"alternating framings then an at-sign":    strings.Repeat("\"x://`x://<x://>x://", n/4) + "@",
		"escaped quotes then an at-sign":          `"x://` + strings.Repeat(`\"x://`, n) + "@",
		// An empty userinfo sends each URL on to Python's reading, which
		// runs to the next '/'.
		"empty userinfos then queries":        strings.Repeat("x://@?", n),
		"empty userinfos then query at-signs": strings.Repeat("x://@?a@", n),
		"keys then an at-sign":                strings.Repeat("a=", n) + "b@h:1",
		"keys and at-signs":                   strings.Repeat("a=b@h:1", n),
	} {
		start := time.Now()
		_ = URLCredentialsInText(in)
		_ = URLCredentials(in)
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("%s: %d bytes took %v", name, len(in), took)
		}
	}
}
