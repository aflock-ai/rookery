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

import "strings"

// URLCredentialsInText applies URLCredentials to free text, such as a
// command's stdout, stderr or command line. It changes the userinfo of the
// URLs in it, and a URL whose host the parsers do not agree on keeps only its
// scheme and "******@/", the '/' ending its authority before the text that
// follows. Every other byte, separators included, is kept.
//
// URLCredentials reads its input as ONE value: a proxy variable holds one URL,
// so a value that starts with a URL is read to its last at-sign. Text holds
// many values. A log that opens with a URL and shows an email address three
// lines later is not one URL, and the whole-value reading would sign
// "https://******@example.com>" for it. So the text is cut into words at URL
// space (C0 controls and space, where every tokenizer ends a URL), and each
// word is one value.
//
// Two shapes around a word are taken off before it is read, so that the
// scheme-less rule, which wants the value to end at host[:port], still sees
// one:
//
//   - a key, "KEY=value", "--proxy=value" or a JSON or Python key
//     ("\"proxy\":value", "'http':value"), which holds no ':', '@' or '/'.
//     A quoted key is taken off on trust. A key that ends in '=' is not:
//     '=' is a byte of a credential (base64 pads with it), so
//     "dG9rZW4=@proxy:3128" is a token and a proxy, not a key and an empty
//     userinfo. Such a word is read whole as well as after its key (see
//     valueStarts), and where the whole reading finds a userinfo, the key
//     goes with it: "HTTPS_PROXY=u:p@proxy:3128" becomes "******@proxy:3128";
//   - quotes and brackets around the value, and a ';', ',', '.' or ':' after
//     it, as a shell script, JSON line or sentence puts them
//     ("\"u:p@proxy:3128\";", "[u:p@proxy:3128]", "via u:p@proxy:3128.").
//
// What this cannot see: a password that holds URL space ("http://u:my
// pw@proxy") is two words and neither is a URL (of "u:my pw@proxy:3128" only
// the second word, "user@host:port", is redacted, and "u:my" is signed), and
// a scheme-less credential with more text glued to it
// ("u:p@proxy:3128,localhost", "proxy=u:p@proxy:3128&x=1") has no
// host[:port] end. Both are the boundaries URLCredentials documents for a URL
// inside text.
func URLCredentialsInText(text string) string {
	if !strings.Contains(text, "@") {
		return text // userinfo is delimited by an at-sign; there is none
	}
	var out strings.Builder
	written := 0
	for i := 0; i < len(text); {
		if isURLSpace(text[i]) {
			i++
			continue
		}
		j := i
		for j < len(text) && !isURLSpace(text[j]) {
			j++
		}
		if word := text[i:j]; strings.Contains(word, "@") {
			if redacted := urlCredentialsInWord(word); redacted != word {
				out.WriteString(text[written:i])
				out.WriteString(redacted)
				if j < len(text) && strings.HasSuffix(redacted, Marker+"@") {
					// The redaction named no host. A '/' ends the
					// authority there, so the next word is not read as
					// one by a WHATWG parser, which keeps spaces in a
					// userinfo.
					out.WriteByte('/')
				}
				written = j
			}
		}
		i = j
	}
	if written == 0 {
		return text
	}
	out.WriteString(text[written:])
	return out.String()
}

// URLCredentialsInArg redacts one argv element. An element that is a URL,
// or a flag whose value is one ("--proxy=http://...", a key with no space in
// it), is read whole first,
// as URLCredentials reads an environment value: its consumer keeps a space in
// a userinfo ("http://u:my pw@proxy:3128" is a credential to Node's WHATWG
// parser), and read as text it is two words, neither of them a URL. So is an
// element, or a flag value, that is a scheme-less proxy value
// ("HTTP_PROXY=u:my pw@proxy:3128" after env): Python's urllib sends a
// password holding a space (see redactSchemelessUserinfo). That reading
// takes a whole element that ends at host[:port] with a colon or a port
// before it, prose and scripts included ("Reported: a@host:22" becomes
// "******@host:22"): an argv element is one value, and shape cannot tell
// which consumer reads it. Both are recognised in the element as WHATWG reads
// it too, with its tabs and newlines removed (see withoutTabOrNewline). Any
// element is then read as text, so a script loses the userinfo of every URL
// in it.
//
// An element that opens with "KEY=" is read whole first and then after its
// key, as a word of text is (see valueStarts): "dG9rZW4=@proxy:3128" is a
// positional proxy value whose token ends in base64 padding.
func URLCredentialsInArg(arg string) string {
	lead := len(arg) - len(trimURLSpace(arg, strings.TrimLeftFunc))
	arg = arg[:lead] + eachValueReading(arg[lead:], func(value string) string {
		if isOneValue(value) || isOneValue(withoutTabOrNewline(value)) {
			return URLCredentials(value)
		}
		return value
	})
	return URLCredentialsInText(arg)
}

// eachValueReading applies redact to each reading of s as a value, in the
// order valueStarts gives, each to the output of the one before: the whole
// of s, then s after its key. A whole reading that takes the key off leaves
// no key for the next, and its userinfo holds everything the next would
// take; one that leaves the key (a URL after it) is read again after it.
func eachValueReading(s string, redact func(string) string) string {
	for _, whole := range valueStarts(s) {
		k := 0
		if !whole {
			if k = keyEnd(s); k == 0 {
				break
			}
		}
		s = s[:k] + redact(s[k:])
	}
	return s
}

// valueStarts returns the readings of s as a value: true for the whole of s,
// false for s after its key (see keyEnd), whole first. A key that ends in '='
// is not taken on trust: '=' is a byte of a credential, base64 padding and a
// byte RFC 3986 allows in a userinfo, so the whole of "dG9rZW4=@proxy:3128"
// is a token and a proxy, and the whole of "HTTPS_PROXY=u:p@proxy:3128" is a
// user "HTTPS_PROXY=u" to Go, curl and Python. A quoted key ("\"proxy\":",
// "'http':") is taken off on trust: a credential holds no quote, and Go
// refuses one in a userinfo.
func valueStarts(s string) []bool {
	switch k := keyEnd(s); {
	case k == 0:
		return []bool{true}
	case s[k-1] == '=':
		return []bool{true, false}
	default:
		return []bool{false}
	}
}

// isOneValue reports whether an argv element, its flag or key taken off, is
// read whole: it is a URL, or a scheme-less proxy value.
func isOneValue(value string) bool {
	if i, _ := nextSchemeSeparator(value); i > 0 && urlStart(value, i) == 0 {
		return true
	}
	_, ok := redactSchemelessUserinfo(value)
	return ok
}

// withoutTabOrNewline is s as the WHATWG URL parser reads it: it removes
// every tab, LF and CR before it parses, so "http:/<TAB>/u:p@h" is
// http://u:p@h to Node. Read as text, that element splits at the tab and
// "/u:p@h" reads as a path, so an element is recognised in this reading
// too, and URLCredentials, which reads it the same way, redacts it.
func withoutTabOrNewline(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

// urlCredentialsInWord redacts one word of text; see URLCredentialsInText.
// Like URLCredentials it runs to a fixpoint: the narrower trailing set is
// tried only when the wider one changes nothing, so a pass can leave a
// credential that only the narrower reading of its output shows.
func urlCredentialsInWord(word string) string {
	for range strings.Count(word, "@") + 2 {
		next := urlCredentialsInWordOnce(word)
		if next == word {
			break
		}
		word = next
	}
	return word
}

func urlCredentialsInWordOnce(word string) string {
	return eachValueReading(word, redactWordValue)
}

// redactWordValue applies URLCredentials to value, a word or what follows
// its key, with the quotes and brackets around it and the punctuation after
// it taken off.
func redactWordValue(value string) string {
	core := strings.TrimLeft(value, "\"'`([{<")
	lead := value[:len(value)-len(core)]
	// The wider trailing set ends a sentence or a bracket; the narrower one
	// is tried when it finds nothing, because a '.' or ':' it takes off can
	// be all the host there is ("u:p@.").
	for _, trailing := range [...]string{"\"'`;,.:)]}>", "\"'`;,)"} {
		body := strings.TrimRight(core, trailing)
		if redacted := URLCredentials(body); redacted != body {
			if suffix := core[len(body):]; suffix != "" && strings.HasSuffix(redacted, Marker+"@") {
				// The redaction named no host. A '/' ends the authority
				// there, so the '.' or ',' taken off the end is not read as
				// one ("http://******@.").
				redacted += "/"
			}
			return lead + redacted + core[len(body):]
		}
	}
	return value
}

// keyEnd returns the length of the key at the start of s, through its
// separator: "KEY=", "\"key\":" or "'key':". It returns 0 when there is none,
// and when what would be the key holds a ':', '@' or '/', which put it inside
// a URL or a userinfo, or URL space, which an argv element can hold.
func keyEnd(s string) int {
	end := -1
	for _, sep := range [...]string{"=", `":`, `':`} {
		if i := strings.Index(s, sep); i >= 0 && (end < 0 || i+len(sep) < end) {
			end = i + len(sep)
		}
	}
	if end < 0 || strings.ContainsAny(s[:end-1], ":@/") || strings.ContainsFunc(s[:end], func(r rune) bool { return r <= ' ' }) {
		return 0
	}
	return end
}

func isURLSpace(b byte) bool {
	return b <= ' '
}
