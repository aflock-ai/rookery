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
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDigest is a full-length sha256 image digest.
const testDigest = "0f6c5a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7"

// redactionCases is shared by TestRedactURLCredentials, which pins each
// output, and TestRedactedValueNamesNoOtherHost, which checks every output
// against the host property. Every row is a value a consumer of that variable
// can read as carrying a credential, or a value that must survive untouched.
// Where the parsers do not agree on one userinfo and one host, the value
// keeps no host at all rather than risk publishing a secret or naming a host
// the consumer did not use.
var redactionCases = []struct {
	name, in, want string
}{
	// The userinfo is the credential; scheme, host, port and path stay.
	{"user and password", "http://u:secret@proxy:3128", "http://******@proxy:3128"},
	{"token-only userinfo", "https://ghp_abcdefghij@github.com/o/r.git", "https://******@github.com/o/r.git"},
	{"token in the username slot", "https://ghs_abcdefghij:x-oauth-basic@github.com", "https://******@github.com"},
	{"ssh login is not told apart from a token", "ssh://git@github.com/o/r.git", "ssh://******@github.com/o/r.git"},
	{"upper-case scheme", "HTTP://U:SECRET@PROXY:8080", "HTTP://******@PROXY:8080"},
	{"ipv6 host", "http://u:secret@[::1]:3128", "http://******@[::1]:3128"},
	{"empty scheme", "://u:secret@proxy", "://******@proxy"},

	{"encoded at-sign in password", "http://u:p%40ss@proxy:3128", "http://******@proxy:3128"},

	// The host after the marker is the host every parser reads. Where
	// Go's net/url, Python, the WHATWG parser and curl do not all read
	// one userinfo and one host, the URL keeps only its scheme and
	// "******@", in which none of them finds a host, so the evidence
	// names no host at all rather than a host the tool did not use. The
	// password is still taken to the LAST at-sign, so no part of it
	// survives.
	//
	// Two at-signs in the authority: Go, Python and WHATWG read host
	// github.com, curl refuses the URL ("Bad hostname").
	{"two at-signs in the authority", "https://a@evil.example@github.com/x", "https://******@"},
	{"raw at-sign in password", "http://u:p@ss@proxy:3128", "http://******@"},
	{"empty user before a second at-sign", "https://@evil.example@github.com/x", "https://******@"},
	// The rest of the URL goes with the host.
	{"at-sign in the path after a redacted authority", "https://a@evil.example@github.com/x@y", "https://******@"},
	// A password holding '/', '?' or '#' ends the RFC 3986 authority
	// early: every parser reads host "alice" or refuses, none reads
	// github.com.
	{"slash in password", "https://alice:sec/ret@github.com/acme", "https://******@"},
	{"query byte in password", "https://alice:sec?ret@github.com", "https://******@"},
	{"fragment byte in password", "https://alice:sec#ret@github.com", "https://******@"},
	// WHATWG ends a special scheme's authority at '\', Python does not:
	// one reads evil.example, the other github.com.
	{"backslash before the at-sign", `https://evil.example\x@github.com/`, "https://******@"},
	// The review's repro: Go, WHATWG, curl and urlsplit connect to
	// evil.example with no userinfo, while Python's proxy parser reads
	// userinfo "evil.example/payload.sh" and host github.com.
	// "******@github.com" would name a host the tool never used, and
	// keeping the URL would keep what Python sends as a password, so no
	// host is named.
	{"at-sign in the path after a plain host", "https://evil.example/payload.sh@github.com/actions/runner", "https://******@"},
	{"at-sign in the query after a plain host", "https://evil.example?x@github.com", "https://******@"},
	{"at-sign in the fragment after a plain host", "https://evil.example#x@github.com", "https://******@"},
	{"at-sign in the path after a host and port", "https://evil.example:8443/p@github.com", "https://******@"},
	{"at-sign in the path after an ipv6 host", "https://[::1]:8443/p@github.com", "https://******@"},
	// A URL can start inside a plain authority; its userinfo goes with the
	// rest of the outer URL.
	{"url starting inside a plain authority", "http://0http://u:p1sec@h:3128", "http://******@"},
	{"escaped url starting inside a plain authority", `https://evil.example:\/\/u:p1sec@h`, "https://******@"},
	// The at-sign that ends a scheme-less userinfo for Go's http://
	// reading need not be the last one: ":0@0://#@" is user "", password
	// "0" and host "0:" there.
	{"scheme-less userinfo ended before the last at-sign", ":0@0://#@", "******@"},
	// A real userinfo followed by an at-sign in the path: the userinfo
	// ends at the authority's at-sign, not the path's.
	{"credential then an at-sign in the path", "https://u:p1sec@host/a/@scope/pkg", "https://******@host/a/@scope/pkg"},
	// Go, WHATWG and curl read host "alice", port 123; Python's proxy
	// parser sends password "123/ret" to host.
	{"numeric password holding a slash", "https://alice:123/ret@host", "https://******@"},
	// No byte ends a whole value's userinfo for Python's proxy parser, which
	// sends "sec<ret/part", a JSON field after the URL included.
	{"password holding a byte no url holds", "http://u:sec<ret/part@proxy:3128", "http://******@"},
	{"json after a url", `https://h.example/v1","author":"a@b.example`, "https://******@"},

	// A value that IS a URL is read whole by its consumer, which accepts
	// spaces in userinfo and strips tabs and newlines.
	{"space in password", "http://u:my secret@proxy:3128", "http://******@proxy:3128"},
	{"newline in password", "http://u:sec\nret@proxy:3128", "http://******@proxy:3128"},
	{"leading whitespace", "  http://u:secret@proxy:3128", "  http://******@proxy:3128"},
	{"space in password, compound scheme", "jdbc:postgresql://u:my secret@db/app", "******@"},
	{"space in a password holding a scheme separator", "u:ab://c d@proxy:3128", "******@"},

	// Lists and URLs inside text.
	{"comma list", "https://u:tok@corp.example,https://proxy.golang.org,direct", "https://******@corp.example,https://proxy.golang.org,direct"},
	{"url in text", "use http://u:secret@proxy:3128 for egress", "use http://******@proxy:3128 for egress"},
	{"two urls in text", "a http://u:s1@h1 b https://v:s2@h2 c", "a http://******@h1 b https://******@h2 c"},
	{"url in json", `{"proxy":"http://u:secret@h:1"}`, `{"proxy":"http://******@h:1"}`},
	{"url then email in text", "see https://example.com/x or mail a@b.example", "see https://example.com/x or mail a@b.example"},

	// curl and Go assume http:// for a proxy value that has no scheme.
	{"schemeless proxy", "u:secret@proxy.corp:3128", "******@proxy.corp:3128"},
	{"schemeless proxy with path", "u:secret@proxy:3128/", "******@proxy:3128/"},
	// Go and Python's urllib read host proxy, curl refuses: no host.
	{"schemeless at-sign in password", "u:p@ss@proxy:3128", "******@"},
	{"schemeless two at-signs, with a path", "u:a@evil.example@github.com/x", "******@"},
	{"schemeless trailing newline", "u:secret@proxy:3128\n", "******@proxy:3128\n"},
	{"schemeless ipv6", "u:secret@[::1]:3128", "******@[::1]:3128"},
	{"schemeless password holding a scheme separator", "u:ab://cd@proxy:3128", "******@"},
	{"single-slash scheme", "http:/u:secret@proxy:3128", "******@"},
	{"backslash scheme", `http:\\u:secret@proxy:3128`, "******@"},
	{"schemeless empty username", ":secret@proxy:3128", "******@proxy:3128"},
	{"schemeless slash in password", "u:sec/ret@proxy:3128", "******@"},
	{"single-slash scheme, slash in password", "http:/u:sec/ret@proxy:3128", "******@"},
	// Python's urllib reads a scheme-less `DOMAIN\user:pass@proxy` as
	// user `DOMAIN\user` and password "pass", and `http:\\DOMAIN\user:pass@h`
	// as user "http" and a password that holds "pass". A backslash in a
	// user name does not make it a path list.
	{"windows domain user, scheme-less", `DOMAIN\user:p1sec@proxy:8080`, "******@"},
	{"windows domain user after a backslash scheme", `http:\\DOMAIN\user:p1sec@proxy:8080`, "******@"},
	// With a scheme, WHATWG ends the authority at the '\' and reads
	// host DOMAIN, Python reads proxy, Go refuses: no host is named.
	{"windows domain user with a scheme", `http://DOMAIN\user:p1sec@proxy:8080`, "http://******@"},
	// A password that starts with '\' is not the next entry of a path list
	// when the user holds '\' and no ';': Python sends it as a password.
	{"windows domain user, password starting with a backslash", `DOMAIN\user:\p1sec@proxy:8080`, "******@"},
	{"windows domain user, password starting with two backslashes", `DOMAIN\user:\\p1sec@proxy:8080`, "******@"},

	// A reference that only looks like userinfo keeps its credential
	// reading when anything else is added to it. A second at-sign in
	// the userinfo is read to the last one by Go and Python and refused
	// by curl, so the host goes with it.
	{"credential after a purl in a list", "pkg:npm/x@1,u:p1sec@proxy:3128", "******@"},
	{"credential after a mailto in a list", "mailto:a@b.example,u:p1sec@proxy:3128", "******@"},
	// Python's urllib reads the whole value as one scheme-less userinfo, user
	// "pkg", up to the last at-sign, so all of it goes.
	{"credential after a purl in text", "pkg:npm/x@1 http://u:p1sec@proxy:3128", "******@"},
	{"user named pkg", "pkg:p1sec@proxy:3128", "******@proxy:3128"},
	{"user named npm", "npm:p1sec@proxy:3128", "******@proxy:3128"},
	{"user named docker", "docker:p1sec@proxy:3128", "******@proxy:3128"},
	{"user named mailto, proxy with a port", "mailto:p1sec@proxy:3128", "******@proxy:3128"},
	// The same without a port, so only the shape of the reference
	// keeps them redacted.
	{"credential after a purl in a list, no port", "pkg:npm/x@1,u:p1sec@proxy", "******@"},
	{"credential after a mailto in a list, no port", "mailto:a@b.example,u:p1sec@proxy", "******@"},
	{"user named pkg, no port", "pkg:p1sec@proxy", "******@proxy"},
	{"user named npm, no port", "npm:p1sec@proxy", "******@proxy"},
	{"user named docker, no port", "docker:p1sec@proxy", "******@proxy"},
	{"npm alias holding a password, no port", "npm:@scope/p1sec:x@proxy", "******@"},
	// Go's parseProxy retries these as http://mailto:u:p1sec@proxy, so the
	// ':' in the reference part gives the credential reading back.
	{"mailto holding a password, no port", "mailto:u:p1sec@proxy", "******@proxy"},
	{"purl holding a password, no port", "pkg:npm/u:p1sec@proxy", "******@"},
	{"purl-shaped password, proxy with a port", "pkg:npm/p1sec@proxy:3128", "******@"},
	{"credential before an image digest", "docker://u:p1sec@ghcr.io/o/img@sha256:" + testDigest, "docker://******@ghcr.io/o/img@sha256:" + testDigest},
	{"host named like a digest algorithm", "http://u:p1sec@sha256:8080", "http://******@sha256:8080"},

	// A colon-separated list of filesystem paths is not a URL, even when
	// a later entry holds an at-sign (Homebrew's versioned kegs, npm
	// scopes). A user name never holds a '/', and a password that begins
	// with '/' or '\' is the next entry of the list. A Windows list is
	// kept because no host[:port] follows its at-sign.
	{"PATH with a versioned keg", "/usr/local/bin:/opt/homebrew/opt/python@3.11/bin:/usr/bin", "/usr/local/bin:/opt/homebrew/opt/python@3.11/bin:/usr/bin"},
	{"PKG_CONFIG_PATH with two at-signs", "/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/icu4c@76/lib/pkgconfig", "/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/icu4c@76/lib/pkgconfig"},
	{"PATH with an npm scope", "/Users/a/.volta/bin:/Users/a/node_modules/@scope/cli/bin", "/Users/a/.volta/bin:/Users/a/node_modules/@scope/cli/bin"},
	{"relative first entry", ".:/opt/homebrew/opt/python@3.11/bin", ".:/opt/homebrew/opt/python@3.11/bin"},
	{"bare-word first entry", "bin:/opt/homebrew/opt/openjdk@17/bin:/usr/bin", "bin:/opt/homebrew/opt/openjdk@17/bin:/usr/bin"},
	{"empty first entry", ":/opt/homebrew/opt/postgresql@16/share/man", ":/opt/homebrew/opt/postgresql@16/share/man"},
	{"relative second entry", "lib/a.jar:lib/foo@1.2/b.jar", "lib/a.jar:lib/foo@1.2/b.jar"},
	{"drive-letter path list", "C:/tools/node@20/bin;C:/Windows", "C:/tools/node@20/bin;C:/Windows"},
	{"single-slash file scheme", "file:/opt/homebrew/opt/python@3.11/bin", "file:/opt/homebrew/opt/python@3.11/bin"},
	{"windows list, keg in first entry", `C:\tools\node@20\bin;C:\Windows`, `C:\tools\node@20\bin;C:\Windows`},
	{"windows list, keg in second entry", `C:\Windows;C:\tools\node@20\bin`, `C:\Windows;C:\tools\node@20\bin`},
	{"windows list, relative first entry", `bin\x;C:\tools\node@20`, `bin\x;C:\tools\node@20`},
	{"windows scoop path", `C:\Users\a\scoop\apps\python@3.11\current`, `C:\Users\a\scoop\apps\python@3.11\current`},
	{"windows list, dot entry", `.\bin;C:\tools\node@20\bin`, `.\bin;C:\tools\node@20\bin`},
	{"unix list, backslash in first entry", `odd\dir:/opt/homebrew/opt/python@3.11/bin`, `odd\dir:/opt/homebrew/opt/python@3.11/bin`},

	// Nothing here is a credential.
	{"no userinfo", "https://proxy.golang.org", "https://proxy.golang.org"},
	{"empty userinfo", "https://@github.com", "https://@github.com"},
	{"email", "alice@example.com", "alice@example.com"},
	{"named email", "Alice <alice@example.com>", "Alice <alice@example.com>"},
	// Python's urllib sends user "Contact" and password " help" to
	// example.com; no byte rule tells this from "u:my secret@proxy:3128".
	{"prose with a colon", "Contact: help@example.com", "******@example.com"},
	{"image digest", "node:20@sha256:0f6c5a1b2c3d4e5f", "node:20@sha256:0f6c5a1b2c3d4e5f"},
	{"registry image digest", "ghcr.io/o/img:v1@sha256:abc123def", "ghcr.io/o/img:v1@sha256:abc123def"},
	{"already obfuscated", "******", "******"},
	// Package and mailbox references: the at-sign ends a name, not a
	// userinfo, and a scheme-less proxy value never has one of these
	// schemes as its user.
	{"npm purl", "pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"},
	{"golang purl", "pkg:golang/github.com/foo/bar@v1.2.3", "pkg:golang/github.com/foo/bar@v1.2.3"},
	{"scoped npm purl", "pkg:npm/%40angular/core@17.0.0", "pkg:npm/%40angular/core@17.0.0"},
	{"npm alias", "npm:@scope/pkg@1.2.3", "npm:@scope/pkg@1.2.3"},
	{"mailto", "mailto:alice@example.com", "mailto:alice@example.com"},
	{"image digest with a scheme", "docker://ghcr.io/o/img@sha256:" + testDigest, "docker://ghcr.io/o/img@sha256:" + testDigest},
	{"image digest with a tag and a scheme", "docker://ghcr.io/o/img:v1@sha256:" + testDigest, "docker://ghcr.io/o/img:v1@sha256:" + testDigest},
	{"empty", "", ""},

	// An at-sign after a plain host is in the path for Go, WHATWG and
	// curl, and ends a userinfo for Python's proxy parser. Shape cannot
	// tell a path from a password, so the URL keeps no host.
	{"at-sign in path", "https://registry.npmjs.org/@scope/pkg", "https://******@"},
	{"pip vcs ref", "git+https://github.com/org/repo@v1.2.3", "git+https://******@"},
	{"medium handle", "https://medium.com/@user/post", "https://******@"},
	{"space-separated list", "https://pypi.org/simple https://u:secret@corp/simple", "https://******@"},

	// Deliberate over-redaction: a value read whole runs its first URL
	// to the end of the value, so an at-sign past that URL's authority
	// takes the rest of the value with it.
	{"credential in a later list entry", "https://proxy.golang.org,https://u:tok@corp.example,direct", "https://******@"},
	{"compound scheme with a credential", "jdbc:postgresql://u:secret@db:5432/app", "******@"},
	// A path list with no separator before its at-sign is, byte for
	// byte, user:pass@host.
	{"slash-less path list reads as user:pass@host", ".:foo@1.2", "******@1.2"},
	// Only a full-length digest is not a userinfo end, so a truncated one
	// after a host is read like any other at-sign in a path. With a
	// userinfo whose password holds '/', the '@' of a full-length digest
	// still does not end the userinfo; the one before it does.
	{"truncated digest with a scheme", "docker://ghcr.io/o/img@sha256:abc123", "docker://******@"},
	{"credential with a slash before an image digest", "docker://u:p1/sec@ghcr.io/o/img@sha256:" + testDigest, "docker://******@"},

	// Scheme-less values whose password holds a byte that ends an RFC 3986
	// authority ('/', '?', '#', or '\', which WHATWG reads as '/'). Go and
	// curl read "http://" + value and dial the text before the colon;
	// WHATWG reads "http:evil.example/x@h" as host evil.example. Only
	// Python's proxy parser reads the host after the at-sign, so it is not
	// kept. The first has no credential at all.
	{"scheme-less host and port before a path at-sign", "evil.example:8080/payload.sh@github.com/actions/runner", "******@"},
	{"scheme-less query byte before the at-sign", "evil.example:80?@github.com", "******@"},
	{"scheme-less fragment byte before the at-sign", "evil.example:80#@github.com", "******@"},
	{"scheme-less backslash before the at-sign", `evil.example:80\@github.com`, "******@"},
	{"whatwg scheme without slashes, path at-sign", "http:evil.example/x@github.com", "******@"},
	{"whatwg backslash scheme, backslash path at-sign", `http:\\evil.example\x@github.com`, "******@"},
	{"go module version behind a proxy host", "goproxy.internal:8080/mod@v1.2.3", "******@"},
	{"forged host, scheme-less", "evil.example:8080/x@good.example", "******@"},
	{"forged host, scheme-less, numeric password", "u:12/34@good.example", "******@"},

	// Forged hosts with a scheme: each dials the host before the first
	// '/', '?', '#' or '\', and whoever sets it chooses the text after its
	// last at-sign.
	{"forged host after a path", "https://evil.example/x@proxy.golang.org", "https://******@"},
	{"forged host after a query", "https://evil.example/?a=@registry.npmjs.org", "https://******@"},
	{"forged host after a fragment", "https://evil.example#@pypi.org/simple", "https://******@"},
	{"forged loopback host", "http://127.0.0.2:9/x@127.0.0.3:9/", "http://******@"},
	{"forged host in text", "see https://evil.example/x@good.example ok", "see https://******@/ ok"},
	{"forged host, compound scheme", "jdbc:postgresql://evil/x@db", "******@"},
	// A real userinfo ends at the authority's at-sign, and every parser
	// reads the host after it; the later at-sign is in the query.
	{"real userinfo, at-sign in the query", "https://u:p1sec@evil.example/?a=@good.example", "https://******@evil.example/?a=@good.example"},
	// Python's proxy parser (CPython 3.9 to 3.14, urllib/request.py
	// _parse_proxy) ends the authority at the first '/' after the FIRST
	// at-sign, not at '?' or '#', and takes the userinfo to the last
	// at-sign before that '/'. With no '/' between them, a later at-sign
	// ends its userinfo: it sends password "first@proxy-a?p1sec-tail" to
	// proxy-b:3128, while Go, curl and WHATWG send "first" to proxy-a. No
	// host is kept and the tail goes.
	{"real userinfo, query then a later at-sign", "http://u:first@proxy-a?p1sec-tail@proxy-b:3128", "http://******@"},
	{"real userinfo, fragment then a later at-sign", "http://u:first@proxy-a#p1sec-tail@proxy-b:3128", "http://******@"},
	{"real userinfo, empty query then a later at-sign", "https://u:first@proxy-a?@proxy-b", "https://******@"},
	{"real userinfo, query then a later at-sign, quoted", `"http://u:first@proxy-a?p1sec-tail@proxy-b:3128"`, `"http://******@/"`},
	{"real userinfo, query then a later at-sign, scheme-relative", "//u:first@proxy-a?p1sec-tail@proxy-b:3128", "//******@"},
	{"real userinfo, query then a later at-sign, scheme-less", "u:first@proxy-a?p1sec-tail@proxy-b:3128", "******@"},
	{"real userinfo, path then a later at-sign, scheme-less", "u:first@proxy-a/p1sec-tail@proxy-b:3128", "******@"},
	// Deliberate over-redaction: a query holding an at-sign after a
	// credential ("?email=a@b") has the same shape.
	{"credential then an email in the query", "https://u:p1sec@host?email=a@b.example", "https://******@"},
	// A '/' after the userinfo's at-sign ends the authority for every one
	// of them, _parse_proxy included: Go, curl and Python all send "first"
	// to proxy-a (measured against a local listener), so "tail" is a path
	// and the host stays. A '?' before that '/' does not change it.
	{"real userinfo, path then a later at-sign", "http://u:first@proxy-a/tail@proxy-b:3128", "http://******@proxy-a/tail@proxy-b:3128"},
	{"real userinfo, query and path then a later at-sign", "http://u:first@proxy-a?q/tail@proxy-b:3128", "http://******@proxy-a?q/tail@proxy-b:3128"},
	// An empty userinfo is not the end of the search. Go, WHATWG and curl
	// read an empty user at proxy-a, but Python's proxy parser still runs
	// from the first at-sign to the first '/' after it, so it sends
	// password "p4sec" to proxy-b:3128.
	{"empty userinfo, query then a userinfo", "http://@proxy-a?user:p4sec@proxy-b:3128", "http://******@"},
	{"empty userinfo, fragment then a userinfo", "http://@proxy-a#user:p4sec@proxy-b:3128", "http://******@"},
	{"empty userinfo, query and fragment then a userinfo", "http://@proxy-a?q#user:p4sec@proxy-b:3128", "http://******@"},
	{"empty userinfo, several later at-signs", "http://@proxy-a?x@y#user:p4sec@proxy-b:3128", "http://******@"},
	{"empty userinfo and a port, query then a userinfo", "http://@proxy-a:8080?user:p4sec@proxy-b:3128", "http://******@"},
	{"empty userinfo, query then a token", "https://@proxy-a?ghp_p4token@proxy-b:3128", "https://******@"},
	{"empty userinfo, query then a padded token", "https://@proxy-a?cDRzZWNyZXQ=@proxy-b:3128", "https://******@"},
	{"empty userinfo, escaped slashes, in text", `see http:\/\/@proxy-a?user:p4sec@proxy-b:3128`, `see http:\/\/******@`},
	{"empty userinfo, quoted", `"http://@proxy-a?user:p4sec@proxy-b:3128"`, `"http://******@/"`},
	{"empty userinfo, in text", "use http://@proxy-a?user:p4sec@proxy-b:3128 now", "use http://******@/ now"},
	{"empty user and password, query then a userinfo", "http://:@proxy-a?user:p4sec@proxy-b:3128", "http://******@"},
	{"empty user with a password", "http://:p4sec@proxy:3128", "http://******@proxy:3128"},
	{"empty userinfo, scheme-relative, query then a userinfo", "//@proxy-a?user:p4sec@proxy-b:3128", "//******@"},
	{"empty userinfo, scheme-less, query then a userinfo", "@proxy-a?user:p4sec@proxy-b:3128", "******@"},
	// A '/' after the empty userinfo ends the authority for every parser,
	// Python's included: each reads an empty user at proxy-a, and the later
	// at-sign is in the path.
	{"empty userinfo, path then a later at-sign", "http://@proxy-a/tail@proxy-b:3128", "http://@proxy-a/tail@proxy-b:3128"},
	{"empty userinfo, query and path then a later at-sign", "http://@proxy-a?q/tail@proxy-b:3128", "http://@proxy-a?q/tail@proxy-b:3128"},
	// '=' is a byte of a credential: base64 pads with it, and RFC 3986
	// allows it in a userinfo.
	{"padded token in the username slot", "cDRzZWNyZXQ=@proxy:3128", "******@proxy:3128"},
	{"double-padded token in the username slot", "cDRzZWNyZQ==@proxy:3128", "******@proxy:3128"},
	{"padded token with a scheme", "http://cDRzZWNyZXQ=@proxy:3128", "http://******@proxy:3128"},
	{"equals inside a password", "u:q16a=q16b@proxy:3128", "******@proxy:3128"},

	// docker --env-file and some .env loaders keep the quotes, and
	// Python's urllib still reads the password inside them.
	{"double-quoted scheme-less proxy", `"u:p1sec@proxy:3128"`, `"******@proxy:3128"`},
	{"single-quoted scheme-less proxy", `'u:p1sec@proxy:3128'`, `'******@proxy:3128'`},
	{"quoted scheme-less forged host", `"evil.example:8080/x@good.example"`, `"******@/"`},
	{"single-quoted scheme-less forged host", `'evil.example:8080/x@good.example'`, `'******@/'`},
	{"quoted email", `"alice@example.com"`, `"alice@example.com"`},
	{"quoted path list", `"/usr/local/bin:/opt/homebrew/opt/python@3.11/bin"`, `"/usr/local/bin:/opt/homebrew/opt/python@3.11/bin"`},
	// The quotes are looked through for a value with a scheme too, so its
	// userinfo is not cut at a space the way a URL inside text is.
	{"quoted proxy, space in password", `"http://u:my secret@proxy:3128"`, `"http://******@proxy:3128"`},
	{"quoted forged host with a scheme", `"https://evil.example/x@good.example"`, `"https://******@/"`},

	// A network-path reference ("//authority", RFC 3986 section 4.2) is an
	// authority with no scheme, and Python's urllib reads a proxy value of
	// that shape: it sends "secret" for "//u:secret@proxy:3128". It is the
	// value's own URL, so its userinfo runs to the last at-sign, spaces
	// included, and goes whole, whatever the path-list reading would say.
	{"scheme-relative proxy", "//u:secret@proxy:3128", "//******@proxy:3128"},
	{"scheme-relative token-only userinfo", "//ghp_abcdefghij@github.com/o/r.git", "//******@github.com/o/r.git"},
	{"scheme-relative, space in password", "//u:my secret@proxy:3128", "//******@proxy:3128"},
	{"scheme-relative, surrounding whitespace", "  //u:secret@proxy:3128\n", "  //******@proxy:3128\n"},
	{"scheme-relative, quoted", `"//u:secret@proxy:3128"`, `"//******@proxy:3128"`},
	{"scheme-relative, third slash", "///u:secret@proxy:3128", "//******@"},
	{"scheme-relative, slash in user", "//u/x:secret@proxy:3128", "//******@"},
	// Python dials the host after the at-sign, Go and WHATWG the one
	// before the '/', so neither is kept.
	{"scheme-relative forged host", "//evil.example/x@proxy.golang.org", "//******@"},
	// A closing quote after "******@" would read as the host.
	{"scheme-relative forged host, quoted", `"//evil.example/x@proxy.golang.org"`, `"//******@/"`},
	// Python reads user "server/share/bin" and password "/opt/python".
	{"scheme-relative network path list", "//server/share/bin:/opt/homebrew/opt/python@3.11/bin", "//******@"},
	{"scheme-relative, empty userinfo", "//@proxy:3128", "//@proxy:3128"},
	{"scheme-relative image digest", "//ghcr.io/o/img@sha256:" + testDigest, "//ghcr.io/o/img@sha256:" + testDigest},

	// WHATWG removes every tab, LF and CR from its input before it parses,
	// so these are http://u:p1sec@h to Node. The value is read as WHATWG
	// reads it, and one that holds a credential only in that reading
	// keeps nothing.
	{"tab inside the scheme separator", "http:/\t/u:p1sec@h", "******@"},
	{"tab before the scheme separator", "http:\t//u:p1sec@h", "******@"},
	{"newline inside the scheme separator", "http:/\n/u:p1sec@h", "******@"},

	// Scheme-less userinfo is not checked byte by byte: Python's urllib
	// sends every one of these passwords (see redactSchemelessUserinfo).
	{"scheme-less, space in password", "u:my secret@proxy:3128", "******@proxy:3128"},
	{"scheme-less, tab in password", "u:my\tsecret@proxy:3128", "******@proxy:3128"},
	{"scheme-less, spaces in password", "u:my   secret@proxy:3128", "******@proxy:3128"},
	// A second at-sign: Go and Python read proxy, curl refuses, so no host
	// is named (the #9648 fix keeps proxy:3128 here; this package names no
	// host where the parsers disagree).
	{"scheme-less, at-sign and space in password", "u:my s@cret@proxy:3128", "******@"},
	{"scheme-less, colon and space in password", "u:my:s ecret@proxy:3128", "******@proxy:3128"},
	{"scheme-less, encoded space in password", "u:my%20secret@proxy:3128", "******@proxy:3128"},
	{"scheme-less, space in user", "my user:pw@proxy:3128", "******@proxy:3128"},
	{"scheme-less, space in password, no port", "u:my secret@proxy", "******@proxy"},
	{"scheme-less, quoted, space in password", `"u:my secret@proxy:3128"`, `"******@proxy:3128"`},
	{"scheme-less, space in password past the authority", "u:my secret/x@proxy:3128", "******@"},
	// Go and curl send the user of "user@host:port" with an empty password.
	{"scheme-less user, port", "ghp_usertoken@proxy:3128", "******@proxy:3128"},
	{"scheme-less user, ip literal and port", "ghp_usertoken@[::1]:3128", "******@[::1]:3128"},
	{"scheme-less user, port and path", "tok@proxy:3128/", "******@proxy:3128/"},
	// Without a port it is an email address; nothing tells the two apart.
	{"scheme-less user, no port", "ghp_usertoken@proxy", "ghp_usertoken@proxy"},
	{"scheme-less user, ip literal, no port", "ghp_usertoken@[::1]", "ghp_usertoken@[::1]"},
	{"scheme-less user, empty port", "alice@example.com:", "alice@example.com:"},
	{"plain value with spaces", "plain value with spaces", "plain value with spaces"},
	{"path list entry with a port-shaped version", "/opt/x@1:2", "/opt/x@1:2"},
	{"image with a tag and digest", "node@sha256:" + testDigest, "node@sha256:" + testDigest},
}

func TestRedactURLCredentials(t *testing.T) {
	for _, tc := range redactionCases {
		t.Run(tc.name, func(t *testing.T) {
			got := URLCredentials(tc.in)
			require.Equal(t, tc.want, got, "input %q", tc.in)
			assert.Equal(t, got, URLCredentials(got), "redaction must be idempotent")
		})
	}
}

// hostReadings returns the host that each reading of s names, "" where that
// reading finds none or fails. Index 0 and 1 are Go's url.Parse of the value
// and of "http://" + value, which is how net/http's ProxyFromEnvironment and
// curl read a proxy value with no scheme. Index 2 and 3 are the same two
// inputs read by authorityHost, the unvalidated RFC 3986 reading that WHATWG,
// Python's urlsplit and Go share. Index 4 is the host after the first "://"
// (schemeAuthorityHost), which is what the others read too unless s opens
// with "//". After those come the five readings of each field between C0
// controls and spaces, because a URL inside text ends there. Each reading is
// applied to every string and field, so an unchanged field names the same
// hosts before and after the redaction: "//://0" is a network path to
// authorityHost, and a redaction that drops a URL before it moves the first
// "://" of the line into it.
//
// Python's proxy parser is not one of the readings: it takes the host after
// the at-sign of "//evil.example/x@proxy.golang.org", where the others take
// the one before the '/', so a redaction that keeps a host where they
// disagree fails against one of them anyway.
func hostReadings(s string) []string {
	read := func(s string) []string {
		host := ""
		if u, err := url.Parse(s); err == nil {
			host = u.Host
		}
		prefixed := ""
		if u, err := url.Parse("http://" + s); err == nil {
			prefixed = u.Host
		}
		return []string{host, prefixed, authorityHost(s), authorityHost("http://" + s), schemeAuthorityHost(s)}
	}
	hosts := read(s)
	for _, field := range urlFields(s) {
		hosts = append(hosts, read(field)...)
	}
	return hosts
}

// authorityHost returns the host of the authority that s opens with "//" (a
// network-path reference), or else of its first "://": the authority runs to
// the first '/', '?', '#' or '\' (WHATWG ends a special scheme's authority at
// a backslash), and the host follows its last at-sign. The host is checked
// only for bytes no parser accepts in one (space, control bytes, quotes, '<',
// '>'), so that the text after a URL inside prose is not read as its host.
func authorityHost(s string) string {
	return plausibleHost(rawAuthorityHost(s))
}

// schemeAuthorityHost is authorityHost of the authority after the first
// "://" in s, whether or not s opens with "//".
func schemeAuthorityHost(s string) string {
	return plausibleHost(rawSchemeAuthorityHost(s))
}

// plausibleHost is host, or "" when it holds a byte no parser accepts in one.
func plausibleHost(host string) string {
	if strings.ContainsFunc(host, func(r rune) bool { return r <= ' ' || strings.ContainsRune(`"'<>`, r) }) {
		return ""
	}
	return host
}

// urlFields splits s where a URL inside text ends: at C0 controls and space.
func urlFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r <= ' ' })
}

// rawAuthorityHost is authorityHost without the check on the bytes of the
// host. The authority is the one s opens with "//" (a network-path
// reference), or else the one after its first "://".
func rawAuthorityHost(s string) string {
	if rest, ok := strings.CutPrefix(s, "//"); ok {
		return hostOfAuthority(rest)
	}
	return rawSchemeAuthorityHost(s)
}

// rawSchemeAuthorityHost is schemeAuthorityHost without the check on the
// bytes of the host.
func rawSchemeAuthorityHost(s string) string {
	_, rest, ok := strings.Cut(s, "://")
	if !ok {
		return ""
	}
	return hostOfAuthority(rest)
}

// hostOfAuthority returns the host of the authority rest opens with: it runs
// to the first '/', '?', '#' or '\', and the host follows its last at-sign.
func hostOfAuthority(rest string) string {
	if end := strings.IndexAny(rest, "/?#\\"); end >= 0 {
		rest = rest[:end]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	return rest
}

// unescaped is host with its percent-escapes decoded, as Go's url.Parse
// returns it.
func unescaped(host string) string {
	if u, err := url.PathUnescape(host); err == nil {
		return u
	}
	return host
}

// goHostEscapesFixed is the host url.Parse reads in s once each byte Go
// refuses anywhere and accepts escaped: a '%' that does not start an escape,
// a control byte, a space and DEL. The redaction may replace the only such
// byte of a value that Go refused for it.
func goHostEscapesFixed(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '%' && (i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2])),
			c <= ' ' || c == 0x7f:
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(s[i])
	}
	if u, err := url.Parse(b.String()); err == nil {
		return u.Host
	}
	return ""
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// checkNamesNoOtherHost fails when signed, the redacted form of real, names a
// host that real does not. The authority readings must name no host or the
// same one. Go's strict readings may also name the authority host of real,
// because Go refuses some values that WHATWG and Python dial
// ("http://u:my secret@proxy:3128"), or refuses them for a byte outside the
// authority. A field of the redacted value may name
// any host that some reading of the original names, because redaction may
// change the number of fields.
func checkNamesNoOtherHost(t *testing.T, real, signed string) {
	t.Helper()
	want, got := hostReadings(real), hostReadings(signed)
	for i, host := range got[:4] {
		allowed := []string{"", want[i]}
		if i < 2 {
			// Go may refuse the original for a byte outside its
			// authority (an invalid escape in the path) and accept the
			// redacted form, which then names the same authority.
			in := []string{real, "http://" + real}[i]
			raw := rawAuthorityHost(in)
			allowed = append(allowed, want[i+2], raw, unescaped(raw), goHostEscapesFixed(in))
		}
		if !slices.Contains(allowed, host) {
			t.Errorf("reading %d: %q names host %q, %q names %q", i, signed, host, real, allowed[1:])
		}
	}
	checkEachHostIsNamedBy(t, real, signed, got[4:])
}

// checkEachHostIsNamedBy fails when a host in got, read from signed, is not
// one that some reading of real, or of one of its fields, names.
func checkEachHostIsNamedBy(t *testing.T, real, signed string, got []string) {
	t.Helper()
	want := hostReadings(real)
	for _, field := range append([]string{real}, urlFields(real)...) {
		for _, in := range []string{field, "http://" + field} {
			raw, scheme := rawAuthorityHost(in), rawSchemeAuthorityHost(in)
			want = append(want, raw, unescaped(raw), scheme, unescaped(scheme), goHostEscapesFixed(in))
		}
	}
	for _, host := range got {
		if host != "" && !slices.Contains(want, host) {
			t.Errorf("%q names host %q, which no reading of %q names", signed, host, real)
		}
	}
}

// The redacted value must never name a host the original does not dial: the
// signed evidence would then hold a false fact, chosen by whoever set the
// variable. url.Parse(signed).Host must be the host of the original or
// empty, and so must every other reading.
func TestRedactedValueNamesNoOtherHost(t *testing.T) {
	for _, tc := range redactionCases {
		t.Run(tc.name, func(t *testing.T) {
			checkNamesNoOtherHost(t, tc.in, URLCredentials(tc.in))
		})
	}
}

// secretCases are values that carry a credential in at least one parser's
// reading, each with the substrings that reading sends as userinfo. The
// invariant is that no reading of any redaction path signs one of them, in
// any of the places a value turns up (see secretContexts).
var secretCases = []struct {
	in      string
	secrets []string
}{
	// An empty userinfo before a later one (Python's proxy parser).
	{"http://@proxy-a?user:p4sec1@proxy-b:3128", []string{"p4sec1"}},
	{"http://@proxy-a#user:p4sec2@proxy-b:3128", []string{"p4sec2"}},
	{"http://@proxy-a?q#user:p4sec3@proxy-b:3128", []string{"p4sec3"}},
	{"http://@proxy-a?x@y?user:p4sec4@proxy-b:3128", []string{"p4sec4"}},
	{"http://@proxy-a:8080?user:p4sec5@proxy-b:3128", []string{"p4sec5"}},
	{"http://:@proxy-a?user:p4sec6@proxy-b:3128", []string{"p4sec6"}},
	{`http:\/\/@proxy-a?user:p4sec7@proxy-b:3128`, []string{"p4sec7"}},
	{"//@proxy-a?user:p4sec8@proxy-b:3128", []string{"p4sec8"}},
	{"@proxy-a?user:p4sec9@proxy-b:3128", []string{"p4sec9"}},
	{"https://@proxy-a?cDRzZWNyZXQ=@proxy-b:3128", []string{"cDRzZWNyZXQ"}},
	// '=' inside a userinfo: base64 padding, and '=' in a user or a
	// password. A "KEY=" reading must not keep the part before the '='.
	{"cDRzZWNyZXQ=@proxy:3128", []string{"cDRzZWNyZXQ"}},
	{"cDRzZWNyZQ==@proxy:3128", []string{"cDRzZWNyZQ"}},
	{"cDRzZWNyZXQ=:p4sec12@proxy:3128", []string{"cDRzZWNyZXQ", "p4sec12"}},
	{"p4usr13=tail:p4sec13@proxy:3128", []string{"p4usr13", "p4sec13"}},
	{"p4tok14=tail@proxy:3128", []string{"p4tok14"}},
	{"u:p4sec15=@proxy:3128", []string{"p4sec15"}},
	{"u:q16a=q16b@proxy:3128", []string{"q16a", "q16b"}},
	{"http://cDRzZWNyZXQ=@proxy:3128", []string{"cDRzZWNyZXQ"}},
	// Read after its key first, the value drops its host ("p4usr26=******@"),
	// and the whole reading of that finds no userinfo left to take the key
	// with: the whole word must be read first.
	{"p4usr26=tail:p4/sec26@proxy:3128", []string{"p4usr26", "sec26"}},
	// Classes earlier rounds closed, held to the same property.
	{"http://u:p4sec20@proxy-a?p4tail20@proxy-b:3128", []string{"p4sec20", "p4tail20"}},
	{"https://evil.example/p4sec21@github.com", []string{"p4sec21"}},
	{"u:p4sec22@proxy:3128", []string{"p4sec22"}},
	{"p4tok23@proxy:3128", []string{"p4tok23"}},
	{`DOMAIN\p4usr24:p4sec24@proxy:8080`, []string{"p4usr24", "p4sec24"}},
	{"https://x-access-token:p4sec25@github.com/o/r.git", []string{"x-access-token", "p4sec25"}},
}

// secretContexts are the places a value is read: an environment value, a
// word of output alone, after a flag, after an assignment, in quotes, in
// JSON and in a sentence, and an argv element alone or as a flag value.
var secretContexts = []struct {
	name   string
	redact func(string) string
}{
	{"value", URLCredentials},
	{"text", URLCredentialsInText},
	{"text, after a flag", func(s string) string { return URLCredentialsInText("curl -x " + s + " https://example.com\n") }},
	{"text, assignment", func(s string) string { return URLCredentialsInText("HTTPS_PROXY=" + s + "\n") }},
	{"text, quoted", func(s string) string { return URLCredentialsInText(`export P="` + s + `";`) }},
	{"text, json", func(s string) string { return URLCredentialsInText(`{"proxy":"` + s + `"}`) }},
	{"arg", URLCredentialsInArg},
	{"arg, flag value", func(s string) string { return URLCredentialsInArg("--proxy=" + s) }},
}

// No substring that some parser reads as userinfo survives any redaction
// path, whatever surrounds the value.
func TestNoReadingSignsASecret(t *testing.T) {
	for _, tc := range secretCases {
		for _, ctx := range secretContexts {
			t.Run(ctx.name+"/"+tc.in, func(t *testing.T) {
				got := ctx.redact(tc.in)
				for _, secret := range tc.secrets {
					assert.NotContains(t, got, secret, "input %q", tc.in)
				}
			})
		}
	}
}

// Every value, not only the table: the redacted form names no host the
// original does not, and a second pass changes nothing.
func FuzzURLCredentialsNamesNoOtherHost(f *testing.F) {
	for _, tc := range redactionCases {
		f.Add(tc.in)
	}
	for _, tc := range secretCases {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, s string) {
		once := URLCredentials(s)
		if twice := URLCredentials(once); twice != once {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, once, twice)
		}
		checkNamesNoOtherHost(t, s, once)
	})
}
