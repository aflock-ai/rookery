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

// Package redact removes credentials from text before it is signed into
// evidence. It decides by the shape of a VALUE, so it runs where the name of
// the value says nothing: an environment variable, a line of command output,
// an argv element, or a CI server URL.
//
// The invariant: if any parser we know of (Go's net/url, Python's urllib
// proxy parser and urlsplit, WHATWG, curl, git) can read a substring as
// userinfo, in any reading of the value, that substring is redacted.
// Ambiguity resolves toward redacting. Where the readings disagree the
// redaction takes their union, and a host is kept only when every reading
// names the same one: over-redaction removes information from evidence,
// under-redaction signs a secret. The exceptions are shapes named below as
// not credentials, each held tight: an email address (user@host with no
// password and no port), a path list, a package or mailbox reference, and a
// full-length image digest.
package redact

import "strings"

// Marker is what a redacted credential becomes. The environment attestor's
// key-based obfuscation writes the same token, so a reader has one marker to
// look for.
const Marker = "******"

// URLCredentials replaces the userinfo of every URL in an environment
// value with Marker, keeping scheme, host, port and path.
//
// The key-based list decides by NAME, and a credential URL lives under names
// that match nothing: HTTP_PROXY=http://user:pass@proxy:3128 was signed
// verbatim while CLOUDSDK_PROXY_PASSWORD, holding the same password, was
// obfuscated. This decides by the VALUE, so it runs for every key, in every
// capture mode, whether or not the key list is enabled or the key is allowed:
// allowing a key by name corrects a false positive of the name heuristic, and
// this rule has no name to be wrong about.
//
// The whole userinfo goes, username included. "ghs_TOKEN:x-oauth-basic" puts
// the token in the username slot and "ghp_TOKEN@host" has no password at all,
// and neither can be told from "alice:pw" or "git@host" by its shape.
//
// The redaction never names a host the value's consumer would not dial. The
// marker keeps the at-sign and the host after it only when Go's net/url,
// Python, the WHATWG parser and curl read the same single userinfo and host.
// Where they do not, the URL keeps only its scheme and "******@", in which
// none of those parsers finds a host (see readAuthority):
//
//   - an authority with two at-signs ("https://a@evil.example@github.com/x"):
//     Go, Python and WHATWG read github.com, curl refuses the URL;
//   - a password holding an unencoded '/', '?' or '#', which ends the RFC 3986
//     authority early ("https://alice:sec/ret@github.com"): Go, WHATWG and
//     curl read host "alice" or refuse, none reads github.com;
//   - a '\' before the at-sign, where WHATWG ends a special scheme's authority
//     and Python does not;
//   - a later at-sign after a '?' or '#' with no '/' before it
//     ("http://u:first@proxy-a?tail@proxy-b:3128"): Python's proxy parser
//     does not end the authority at '?' or '#', and sends password
//     "first@proxy-a?tail" to proxy-b. The same holds after an empty
//     userinfo: "http://@proxy-a?u:secret@proxy-b:3128" sends "secret". A
//     '/' first ends the authority for every parser, Python's included, so
//     "https://u:p@host/o/r.git@v1" keeps its host and path;
//   - an at-sign past an authority that holds none
//     ("https://evil.example/x@proxy.golang.org"). Go, WHATWG, curl and
//     urlsplit dial evil.example, but Python's proxy parser reads userinfo
//     "evil.example/x" and dials proxy.golang.org. Keeping the host after the
//     at-sign would let whoever sets the value choose the host the evidence
//     names, and keeping the URL would keep what Python sends as a password
//     ("https://alice:123/ret@host"). The cost is that an at-sign in a path
//     ("https://registry.npmjs.org/@scope/pkg") takes the whole URL after its
//     scheme.
//
// The password is still taken to the LAST at-sign, so none of it survives. A
// secret in immutable evidence is an incident; a lost hostname is not; a
// wrong hostname is false evidence.
//
// WHATWG removes every tab, LF and CR from its input before it parses, so
// "http:/\t/u:p@h" is http://u:p@h to Node. The redacted value is also read
// with them removed, and one that still holds a credential in that reading
// becomes "******@".
//
// The rule runs to a fixpoint, so its output is its own fixpoint; the bound
// is a backstop.
func URLCredentials(value string) string {
	return urlCredentials(value, wholeValue)
}

// wholeValue is the opener of a value that is read whole (see
// redactAuthorityUserinfo).
const wholeValue = -1

// urlCredentials is URLCredentials for a whole value, and for a word of text
// when opener is the byte its quotes or brackets open with, or 0.
func urlCredentials(value string, opener int) string {
	redacted := urlCredentialsFixpoint(value, opener)
	if strings.ContainsAny(redacted, "\t\n\r") {
		// Checked on the output, so that a second pass finds it too.
		stripped := withoutTabOrNewline(redacted)
		if urlCredentialsFixpoint(stripped, opener) != stripped {
			return Marker + "@"
		}
	}
	return redacted
}

func urlCredentialsFixpoint(value string, opener int) string {
	for range strings.Count(value, "@") + 2 {
		next := redactURLCredentialsOnce(value, opener)
		if next == value {
			break
		}
		value = next
	}
	return value
}

func redactURLCredentialsOnce(value string, opener int) string {
	if !strings.Contains(value, "@") {
		return value // userinfo is delimited by an at-sign; there is none
	}
	if redacted, ok := redactSchemelessUserinfo(value); ok {
		return redacted
	}
	return redactAuthorityUserinfo(value, opener)
}

// redactAuthorityUserinfo handles every "://" in the value, and its JSON
// spelling ":\/\/" (see nextSchemeSeparator).
//
// A URL that IS the value is read whole by its consumer, and the WHATWG parser
// (Node, browsers) keeps spaces in userinfo and strips tabs and newlines, so
// its userinfo may run to the end of the value. A URL inside text ends at the
// first whitespace, where every tokenizer ends it; this is what keeps an email
// address later in a commit message from being read as the end of a userinfo.
// A URL inside one pair of matching quotes is still the value's own (see
// valueCore), so a space in its password does not end it.
//
// Python's proxy parser reads every byte before the at-sign as userinfo, so
// "http://u:sec<ret/part@proxy:3128" sends password "sec<ret/part". In a
// value read whole, no byte ends the search past an authority that holds no
// at-sign. In a word of text, a URL that a quote or bracket of framing opens
// ends at the unescaped byte that closes it: JSON escapes its quote inside a
// string and XML its '<', so what follows that byte is the next field
// ("\"https://h/v1\",\"author\":\"a@b\""), not a password. No other byte
// ends it, and in a word whose last at-sign is followed by host[:port] that
// one does not either: there a quote left unescaped inside the URL is the
// likelier reading.
func redactAuthorityUserinfo(value string, opener int) string {
	valueStart, core := valueCore(value)
	valueEnd := valueStart + len(core)
	lastAt := strings.LastIndexByte(value, '@')
	var out strings.Builder
	var seps separatorScanner
	written, pos, space := 0, 0, unknownIndex
	if isHostAndPort(value[lastAt+1:]) {
		opener = wholeValue
	}
	var past [len(framing) + 1]pastAuthorityScan // one per closer, and one for none
	for k := range past {
		past[k] = pastAuthorityScan{next: -1, limit: unknownIndex}
		if k < len(framing) {
			past[k].closer, past[k].next = closing[k], unknownIndex
		}
	}
	for {
		separator, n := seps.next(value, pos)
		start := separator + n
		if separator < 0 || start > lastAt {
			break // no at-sign after this separator, so no userinfo
		}
		end, from, compound := urlExtent(value, valueStart, valueEnd, separator, start, &space)
		at, keepHost := readAuthority(value, start, end, &past[framingOf(value, separator, opener)])
		if at < 0 {
			// No userinfo. A URL can start inside this one's authority
			// ("http://0http://u:p@h"), so the search goes on after the
			// separator.
			pos = start
			continue
		}
		out.WriteString(value[written:from])
		out.WriteString(Marker)
		if keepHost && !compound {
			written, pos = start+at, start+at+1
			continue
		}
		// No host is named. The compound form loses its scheme, so what
		// is left would read as a scheme-less proxy value naming the host;
		// Go reads "http://jdbc:postgresql://..." as having none. A '/'
		// ends the authority before any text after the URL, so a reader
		// that does not stop at whitespace does not read that as the host.
		out.WriteByte('@')
		if end < len(value) {
			out.WriteByte('/')
		}
		written, pos = end, end
	}
	if written == 0 {
		return value
	}
	out.WriteString(value[written:])
	return out.String()
}

// urlExtent returns where the URL whose scheme separator runs from separator
// to start ends, where its redaction begins, and whether its scheme is
// compound. valueStart and valueEnd bound the value's core (see valueCore). A
// URL that IS the value runs to the end of the core; one inside text ends at
// the next space, or at the end of the core. space holds that index between
// calls, found once and reused until the scan passes it, so a word of many
// URLs is not rescanned to its end for each one.
func urlExtent(value string, valueStart, valueEnd, separator, start int, space *int) (end, from int, compound bool) {
	scheme := urlStart(value, separator)
	if scheme == valueStart {
		// A compound scheme is also a scheme-less userinfo; see
		// redactSchemelessUserinfo.
		if strings.Contains(value[scheme:separator], ":") {
			return valueEnd, scheme, true
		}
		return valueEnd, start, false
	}
	if *space != -1 && *space < start {
		*space = indexFrom(value, start, func(s string) int { return strings.IndexAny(s, " \t\n\r\f\v") })
	}
	if *space >= 0 && *space < valueEnd {
		return *space, start, false
	}
	return valueEnd, start, false
}

// schemeSeparators are the spellings of "://" a URL is found by. ":\/\/" is
// the same URL in JSON whose encoder escapes '/', PHP's json_encode default.
var schemeSeparators = [...]string{"://", `:\/\/`}

// nextSchemeSeparator returns the index and length of the first scheme
// separator in s, or -1.
func nextSchemeSeparator(s string) (index, length int) {
	index = -1
	for _, sep := range schemeSeparators {
		if i := strings.Index(s, sep); i >= 0 && (index < 0 || i < index) {
			index, length = i, len(sep)
		}
	}
	return index, length
}

// unknownIndex marks an index not searched for yet. It is below every real
// index and is not -1, which means "none".
const unknownIndex = -2

// indexFrom returns find(value[from:]) as an index into value, or -1.
func indexFrom(value string, from int, find func(string) int) int {
	if i := find(value[from:]); i >= 0 {
		return from + i
	}
	return -1
}

// separatorScanner finds each scheme separator of one value in order. It
// keeps the next index of each spelling and searches again only when the
// scan passes it, so a value holding many separators is read once per
// spelling, not once per separator: a line of adversarial output
// ("x://a@x://a@...") cannot make the redaction quadratic.
type separatorScanner struct {
	found   [len(schemeSeparators)]int
	started bool
}

// next returns the index and length of the first separator at or after pos,
// or -1.
func (s *separatorScanner) next(value string, pos int) (index, length int) {
	if !s.started {
		s.started = true
		for k := range s.found {
			s.found[k] = unknownIndex
		}
	}
	index = -1
	for k, sep := range schemeSeparators {
		if s.found[k] != -1 && s.found[k] < pos {
			s.found[k] = indexFrom(value, pos, func(rest string) int { return strings.Index(rest, sep) })
		}
		if i := s.found[k]; i >= 0 && (index < 0 || i < index) {
			index, length = i, len(sep)
		}
	}
	return index, length
}

// authorityEnd is the bytes that end an RFC 3986 authority. WHATWG adds '\'
// for a special scheme.
const authorityEnd = "/?#"

// readAuthority reads value[start:end], the URL after a "://", and returns
// the index in it of an at-sign that ends a userinfo in some parser's
// reading, or -1 when no parser reads one. keepHost says every parser reads
// the same userinfo and the same host after it, so only the userinfo goes.
// Otherwise the caller drops the whole URL after its scheme, so the at-sign
// returned only says that there is one.
//
// The parsers end a userinfo at different at-signs, and each one counts:
//
//   - Go's net/url, WHATWG, urlsplit, curl and git read the RFC 3986
//     authority, up to the first '/', '?' or '#', and end its userinfo at its
//     last at-sign. WHATWG also ends a special scheme's authority at '\', and
//     curl refuses a second at-sign, so either byte before that at-sign
//     means they disagree;
//   - Python's proxy parser ends the userinfo at the last at-sign before the
//     first '/' after the URL's FIRST at-sign (pythonProxyUserinfoAt), so it
//     reads past a '?' or '#', and past an authority that holds no at-sign
//     at all (pastAuthorityScan).
//
// An empty userinfo in one reading is not an answer for the others:
// "http://@proxy-a?u:secret@proxy-b:3128" is an empty user at proxy-a to Go,
// curl and WHATWG, and password "secret" at proxy-b to Python. The URL has no
// userinfo only when every reading finds none or an empty one.
func readAuthority(value string, start, end int, past *pastAuthorityScan) (at int, keepHost bool) {
	url := value[start:end]
	authority := url[:indexAnyOrLen(url, authorityEnd)]
	rfcAt := strings.LastIndexByte(authority, '@')
	if rfcAt < 0 {
		return past.userinfoAt(value, start, end), false
	}
	pythonAt := pythonProxyUserinfoAt(url, strings.IndexByte(authority, '@'))
	if pythonAt == 0 {
		return -1, false // an empty userinfo in every reading
	}
	return pythonAt, pythonAt == rfcAt && !strings.ContainsAny(authority[:rfcAt], "@\\")
}

// pythonProxyUserinfoAt returns the index in url, the text after a "://", of
// the at-sign that ends the userinfo for Python's proxy parser, given first,
// the index of the first at-sign in url. urllib.request._parse_proxy (CPython
// 3.9 to 3.14) ends the authority at the first '/' after the FIRST at-sign,
// not at '?' or '#' as RFC 3986 does, and _splituser takes the userinfo to the
// last at-sign before that end. So "u:first@proxy-a?tail@proxy-b:3128" sends
// password "first@proxy-a?tail" to proxy-b:3128, where Go, curl and WHATWG
// send "first" to proxy-a. The result is first itself when no later at-sign
// comes before that end.
//
// The search ends at the first '/' after first, and the separators a URL is
// found by both hold one, so it reads no byte that the next URL's search
// reads: a line of adversarial output stays linear.
func pythonProxyUserinfoAt(url string, first int) int {
	end := first + indexAnyOrLen(url[first:], "/")
	return strings.LastIndexByte(url[:end], '@')
}

// pastAuthorityScan answers, for the URLs of one value that share a closer, in
// the order the scan meets them, the search readAuthority makes past an
// authority that holds no at-sign: lastUserinfoAt of the URL up to its limit,
// the closer (see redactAuthorityUserinfo) or the end of the URL.
//
// That search reads the rest of the URL, and a URL whose authority holds no
// at-sign is followed by the next one inside it, so reading it again for each
// would be quadratic: "x://x://...h/img@sha256:<hex>" read to the digest, and
// back from it for an earlier at-sign, once per separator. The next closer is
// kept until the scan passes it, as the next space is (see urlExtent). The
// answer is kept for its limit too: every URL that starts between two limits
// shares the later one, and the at-sign found from the first of them is the
// answer for each that starts at or before it, and none for the rest. The
// limits only grow after the first URL, so each byte is read by one search of
// each scan.
type pastAuthorityScan struct {
	closer byte
	next   int // next closer at or after the last start, -1 for none
	limit  int // the limit found is for
	from   int // the start found was searched from
	found  int // index in value of the at-sign lastUserinfoAt returns, or -1
}

// userinfoAt returns lastUserinfoAt of value[start:limit] as an index into
// value[start:end], or -1, where limit is the first unescaped closer at or
// after start, or end.
func (s *pastAuthorityScan) userinfoAt(value string, start, end int) int {
	if s.next != -1 && s.next < start {
		s.next = indexFrom(value, start, func(rest string) int { return indexUnescaped(rest, s.closer) })
	}
	limit := end
	if s.next >= 0 && s.next < end {
		limit = s.next
	}
	if limit != s.limit || start < s.from {
		s.limit, s.from, s.found = limit, start, -1
		if at := lastUserinfoAt(value[start:limit]); at >= 0 {
			s.found = start + at
		}
	}
	if s.found < start {
		return -1
	}
	return s.found - start
}

// framing is the bytes RFC 3986 allows nowhere in a URI, and that WHATWG
// percent-encodes or refuses, which text puts around a URL; closing is the
// byte that closes each.
const framing, closing = "\"`<>", "\"`><"

// framingOf returns the index in framing of the byte that opens the URL whose
// scheme separator is at value[separator]: the byte before its scheme, or
// opener when the scheme starts the value. It is len(framing) for none, and
// for a value read whole.
func framingOf(value string, separator, opener int) int {
	if opener == wholeValue {
		return len(framing)
	}
	if scheme := urlStart(value, separator); scheme > 0 {
		opener = int(value[scheme-1])
	}
	for k := range len(framing) {
		if int(framing[k]) == opener {
			return k
		}
	}
	return len(framing)
}

// indexUnescaped returns the index of the first c in s that no '\' comes
// right before, or -1.
func indexUnescaped(s string, c byte) int {
	for i := 0; ; {
		j := strings.IndexByte(s[i:], c)
		if j < 0 {
			return -1
		}
		if i+j == 0 || s[i+j-1] != '\\' {
			return i + j
		}
		i += j + 1
	}
}

func indexAnyOrLen(s, chars string) int {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return i
	}
	return len(s)
}

// lastUserinfoAt returns the index of the last at-sign in url, the text after
// a "://", unless that one starts an image digest that ends the URL
// ("docker://ghcr.io/o/img@sha256:<hex>"), in which case it is the one before
// it. Only a full-length digest counts. A short hex run after "@sha256:" is
// also a host named sha256 and a port, and "http://u:p@sha256:8080" is a
// credential.
func lastUserinfoAt(url string) int {
	at := strings.LastIndexByte(url, '@')
	if at >= 0 && isImageDigest(url[at+1:]) {
		return strings.LastIndexByte(url[:at], '@')
	}
	return at
}

// isImageDigest reports whether s is an OCI digest, "algorithm:hex", with
// the full hex length of its algorithm, optionally followed by URL space.
func isImageDigest(s string) bool {
	algorithm, encoded, ok := strings.Cut(trimURLSpace(s, strings.TrimRightFunc), ":")
	if !ok {
		return false
	}
	want := map[string]int{"sha256": 64, "sha384": 96, "sha512": 128}[algorithm]
	if want == 0 || len(encoded) != want {
		return false
	}
	for i := 0; i < len(encoded); i++ {
		if !(encoded[i] >= '0' && encoded[i] <= '9' || encoded[i] >= 'a' && encoded[i] <= 'f') {
			return false
		}
	}
	return true
}

// urlStart returns where the scheme ending at value[separator] begins. A colon
// counts as part of it, so a compound "jdbc:postgresql://" is read as the
// value's own URL rather than as a URL inside text.
func urlStart(value string, separator int) int {
	i := separator
	for i > 0 && isSchemeByte(value[i-1]) {
		i--
	}
	return i
}

func isSchemeByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '+' || b == '-' || b == '.' || b == ':'
}

// redactSchemelessUserinfo handles a value that is "user:pass@host[:port]"
// whose first colon is not a "://". curl and Go's ProxyFromEnvironment both
// read a scheme-less proxy value as http://, so this is a working credentialed
// proxy; it also covers the WHATWG spellings "http:/u:p@h" and "http:\\u:p@h".
// One pair of matching quotes around the value is looked through (see
// valueCore), and a value that opens with "//" is a network-path reference
// (see redactNetworkPathUserinfo).
//
// As with a scheme (see URLCredentials), the host is kept only when every
// parser reads it. A userinfo that runs past the RFC 3986 authority keeps no
// host (see pastAuthority): "evil.example:8080/x@good.example" is dialed at
// evil.example:8080 by Go and curl, "http:evil.example/x@good.example" at
// evil.example by WHATWG, and "DOMAIN\user:p@proxy:8080" at domain by
// WHATWG, and each becomes "******@". So does a userinfo holding a second
// at-sign, where curl refuses the host that Go and Python read.
//
// The userinfo runs to the LAST at-sign and is not checked byte by byte,
// because Python's urllib does not check it: _parse_proxy takes everything
// before the last at-sign as userinfo and everything after the first colon of
// that as the password, spaces, tabs, at-signs and colons included, so
// "u:my secret@proxy:3128" sends "my secret". Go and curl refuse that value,
// and a reader that refuses a value is not a reason to sign it. Prose shaped
// "Contact: help@example.com" is redacted for the same reason: Python sends
// "Contact" and " help" to example.com.
//
// Without a colon the value is "user@host". Go and curl send its user, with
// an empty password, so "ghp_TOKEN@proxy:3128" is a credential. It is
// redacted only when the host has a port (see hasPort), because
// "alice@example.com" has the same shape and is an email address; no reading
// tells a token from a mailbox, and a port is what an email address never
// carries. Requiring host[:port] after the at-sign keeps an image digest
// ("node:20@sha256:...") out. A compound scheme ("jdbc:postgresql://u:p@h") lands here too and loses
// its scheme: it cannot be told from "u:ab://cd@h", a scheme-less password
// holding "://", and only this reading redacts both. A path list is kept out
// by isPathListHead.
func redactSchemelessUserinfo(value string) (string, bool) {
	lead, core := valueCore(value)
	if strings.HasPrefix(core, "//") {
		return redactNetworkPathUserinfo(value, lead, core)
	}
	at := schemelessUserinfoEnd(core)
	if at < 0 {
		return "", false
	}
	if userinfo := core[:at]; pastAuthority(userinfo) || strings.Contains(userinfo, "@") ||
		at != strings.LastIndexByte(core, '@') {
		rest := value[lead+len(core):]
		if rest != "" {
			// A closing quote after "******@" would read as the host.
			rest = "/" + rest
		}
		return value[:lead] + Marker + "@" + rest, true
	}
	return value[:lead] + Marker + value[lead+at:], true
}

// schemelessUserinfoEnd returns the index of the at-sign that ends the
// userinfo of core, a scheme-less value, or -1 when it holds no credential.
// That is the last at-sign, as Go and Python read it. When the text after
// that one is not host[:port], it is the last at-sign of Go's http://
// authority, the text before the first '/', '?', '#' or '\': Go reads
// ":0@0://#@" as password "0" at host "0:". No byte of the userinfo is
// refused, whitespace included (see redactSchemelessUserinfo); a userinfo
// with no colon counts only before a host with a port.
func schemelessUserinfoEnd(core string) int {
	at := strings.LastIndexByte(core, '@')
	if at >= 0 && !isHostAndPort(core[at+1:]) {
		at = strings.LastIndexByte(core[:indexAnyOrLen(core, `/?#\`)], '@')
	}
	if at <= 0 {
		return -1 // no userinfo, or an empty one
	}
	userinfo, host := core[:at], core[at+1:]
	if !isHostAndPort(host) {
		return -1
	}
	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 && !hasPort(host) || colon >= 0 && strings.HasPrefix(core[colon:], "://") {
		return -1
	}
	if isPathListHead(userinfo) || isNonCredentialReference(userinfo, host) {
		return -1
	}
	return at
}

// pastAuthority reports whether userinfo, the text from the start of an
// authority to the at-sign chosen to end its userinfo, runs past the RFC 3986
// authority: whether it holds a '/', '?' or '#', or a '\', which WHATWG reads
// as '/'. If it does, the host after that at-sign is not the one Go, WHATWG
// and curl dial.
func pastAuthority(userinfo string) bool {
	return strings.ContainsAny(userinfo, `/?#\`)
}

// redactNetworkPathUserinfo handles a value whose core (see valueCore) is a
// network-path reference, "//[userinfo@]host[:port]" (RFC 3986 section 4.2):
// an authority with no scheme. Python's urllib reads a proxy value of that
// shape and sends the password of "//u:pass@proxy:3128", and to the path-list
// reading its user "//u" holds a '/'. It is the value's own URL, so it is held
// to the rules of one with a scheme (see URLCredentials): the userinfo
// runs to the last at-sign, spaces included, and goes whole, colon or not; a
// userinfo that runs past the authority keeps no host; and a full-length image
// digest ends the URL. A path list whose first entry is a network path
// ("//server/share/bin:/opt/x@1/bin") is redacted with it, because Python
// reads that value as a user and a password too.
func redactNetworkPathUserinfo(value string, lead int, core string) (string, bool) {
	authority := core[len("//"):]
	at := lastUserinfoAt(authority)
	if at <= 0 {
		return "", false // no userinfo, or an empty one; a "://" later is still read
	}
	start := lead + len("//")
	if pastAuthority(authority[:at]) {
		rest := value[lead+len(core):]
		if rest != "" {
			// A closing quote after "******@" would read as the host.
			rest = "/" + rest
		}
		return value[:start] + Marker + "@" + rest, true
	}
	return value[:start] + Marker + value[start+at:], true
}

// valueCore returns the value without the URL space around it and without one
// pair of matching quotes around what is left, and the index where that core
// starts. docker --env-file and some .env loaders keep the quotes, and
// Python's urllib still reads the credential inside them.
func valueCore(value string) (int, string) {
	lead := len(value) - len(trimURLSpace(value, strings.TrimLeftFunc))
	core := trimURLSpace(value[lead:], strings.TrimRightFunc)
	if len(core) >= 2 && (core[0] == '"' || core[0] == '\'') && core[len(core)-1] == core[0] {
		lead++
		core = core[1 : len(core)-1]
	}
	return lead, core
}

// isPathListHead reports whether a scheme-less userinfo candidate is really
// the start of a colon-separated list of filesystem paths whose later entry
// holds an at-sign: PATH=/usr/bin:/opt/homebrew/opt/python@3.11/bin reads,
// byte for byte, as user "/usr/bin", password "/opt/homebrew/opt/python" and
// host "3.11". Nothing but the shape says a scheme-less value is a URL, and
// two shapes say it is a path list instead:
//
//   - the user holds '/'. This is a guess, not a parser rule: WHATWG and Go
//     end the authority at '/', but Python's urllib reads "u/x:pass@proxy:8080"
//     as user "u/x" and password "pass". Such a user is kept, because a
//     relative path list ("lib/a.jar:lib/foo@1.2/b.jar") has the same shape
//     and a proxy user name with '/' in it is rare;
//   - the password starts with '/' or '\', which is the next absolute entry
//     of the list. Two users are exceptions. A user that is an RFC 3986
//     scheme is WHATWG's "http:/u:p@h" or "http:\\u:p@h", where the slashes
//     belong to the scheme, and the user after them is held to the first
//     rule. A Windows domain user (isDomainUser) with a password that starts
//     with '\' is Python's "DOMAIN\user:\pass@proxy:8080", a credential.
//
// A backslash in the user does NOT mark a path list. WHATWG and Go stop at
// it, but Python's urllib does not: it reads "DOMAIN\user:pass@proxy:8080"
// as user "DOMAIN\user" and password "pass", and "http:\\DOMAIN\user:pass@h"
// as user "http" and a password that holds "pass". A Windows path list is
// still kept by its host ("C:\tools\node@20\bin;C:\Windows" has no
// host[:port] after its at-sign) or by the ';' that separates its entries
// ("bin\x;C:\tools\node@20").
//
// A password is not held to the first rule: "u:sec/ret@proxy" is still
// redacted, as a password holding '/' is in a URL with a scheme.
func isPathListHead(userinfo string) bool {
	user, password, _ := strings.Cut(userinfo, ":")
	if strings.Contains(user, "/") {
		return true
	}
	afterSlashes := strings.TrimLeft(password, `/\`)
	if len(afterSlashes) == len(password) {
		return false
	}
	if isScheme(user) {
		user, _, _ = strings.Cut(afterSlashes, ":")
		return strings.Contains(user, "/")
	}
	return !isDomainUser(user) || strings.HasPrefix(password, "/")
}

// isDomainUser reports whether a scheme-less user is a Windows
// "DOMAIN\user" name: it holds '\' and no ';'. The ';' is what separates
// the entries of a Windows path list, so "bin\x;C" (from
// "bin\x;C:\tools\node@20") is not a domain user. A password that starts
// with '/' after such a user is still read as a path list: Python refuses
// "DOMAIN\user:/pass@proxy" ("proxy URL with no authority"), and a Unix
// list whose first entry holds '\' ("odd\dir:/opt/x@1/bin") has that shape.
func isDomainUser(user string) bool {
	return strings.Contains(user, `\`) && !strings.Contains(user, ";")
}

// isNonCredentialReference reports whether a scheme-less "user:pass@host"
// candidate is a reference whose at-sign ends a name, not a userinfo:
//
//   - a package URL, "pkg:type/namespace/name@version";
//   - an npm alias to a scoped package, "npm:@scope/name@version";
//   - a mailbox, "mailto:local@domain".
//
// Each shape is held tight, so that adding anything to it gives the
// credential reading back. The part before the at-sign must hold no '@', ':'
// or ',' beyond the shape's own, so "pkg:npm/x@1,u:p@proxy:3128" is still
// redacted, and the host must have no port, so "pkg:npm/p@proxy:3128" and
// "mailto:p@proxy:3128" are too. What is left open is a proxy user named
// pkg, npm or mailto, whose password has the shape of the rest of a
// reference, on a proxy with no port.
func isNonCredentialReference(userinfo, host string) bool {
	if strings.Contains(host, ":") {
		return false
	}
	scheme, rest, _ := strings.Cut(userinfo, ":")
	switch strings.ToLower(scheme) {
	case "pkg":
		typ, path, ok := strings.Cut(rest, "/")
		return ok && isScheme(typ) && path != "" && allBytes(path, isPURLPathByte)
	case "npm":
		scope, name, ok := strings.Cut(rest, "/")
		return ok && len(scope) > 1 && scope[0] == '@' && allBytes(scope[1:], isNPMNameByte) &&
			name != "" && allBytes(name, isNPMNameByte)
	case "mailto":
		return rest != "" && allBytes(rest, isMailboxByte)
	}
	return false
}

func allBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isAlphaNum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// isPURLPathByte admits the namespace and name of a package URL: unreserved
// bytes, '%' for its percent-encoding, '+' and '/'.
func isPURLPathByte(b byte) bool {
	return isAlphaNum(b) || b == '.' || b == '-' || b == '_' || b == '~' || b == '%' || b == '+' || b == '/'
}

func isNPMNameByte(b byte) bool {
	return isAlphaNum(b) || b == '.' || b == '-' || b == '_' || b == '~'
}

func isMailboxByte(b byte) bool {
	return isAlphaNum(b) || b == '.' || b == '-' || b == '_' || b == '+' || b == '%'
}

// isScheme reports whether s is an RFC 3986 scheme:
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
func isScheme(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] == ':' || !isSchemeByte(s[i]) {
			return false
		}
	}
	return true
}

// trimURLSpace trims what the WHATWG URL parser strips from either end of its
// input: C0 controls and space.
func trimURLSpace(s string, trim func(string, func(rune) bool) string) string {
	return trim(s, func(r rune) bool { return r <= ' ' })
}

// isHostAndPort reports whether s is host[:port], optionally followed by a
// path, query or fragment. The port may be empty, as Go's parser allows. An
// IP literal is not parsed at all: no digest begins with '[', so treating any
// bracket as a host only ever redacts more.
func isHostAndPort(s string) bool {
	if strings.HasPrefix(s, "[") {
		return true
	}
	i := 0
	for i < len(s) && isHostByte(s[i]) {
		i++
	}
	if i == 0 {
		return false
	}
	if i < len(s) && s[i] == ':' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	return i == len(s) || s[i] == '/' || s[i] == '?' || s[i] == '#'
}

// hasPort reports whether s, which isHostAndPort accepts, names a port: its
// host, or its bracketed IP literal, is followed by ':' and a digit.
func hasPort(s string) bool {
	i := 0
	if strings.HasPrefix(s, "[") {
		i = strings.IndexByte(s, ']') + 1
		if i == 0 {
			return false
		}
	}
	for i < len(s) && isHostByte(s[i]) {
		i++
	}
	return i+1 < len(s) && s[i] == ':' && s[i+1] >= '0' && s[i+1] <= '9'
}

func isHostByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '.' || b == '-' || b == '_' || b == '~' || b == '%' || b >= 0x80
}
