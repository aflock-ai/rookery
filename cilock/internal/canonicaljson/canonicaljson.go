// Package canonicaljson re-emits JSON in the byte-stable form a Pushgate
// assignment approval's subject digest is computed over: objects sorted by
// key at every depth, arrays in place, no whitespace. It is a port of
// judge-api/pkg/canonicaljson, the package the platform uses to recompute
// that digest before it signs, and must produce the same bytes for every
// document the platform signs. cilock cannot import it: judge-api is a
// separate module and rookery is a published subtree.
//
// Number literals pass through verbatim (json.Number). Strings are escaped as
// JSON.stringify escapes them (see writeString), not as encoding/json does;
// the two differ on `<>&`, U+2028 and U+2029.
//
// It refuses more than the platform's package does. A string holding invalid
// UTF-8 or an unpaired surrogate escape is refused (RejectAmbiguous), because
// encoding/json silently rewrites both to U+FFFD. No platform-signed payload
// holds either: the platform re-serialises what it signs as valid UTF-8.
package canonicaljson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrDuplicateKey is returned for a document that names the same key twice
// in one object. See RejectDuplicateKeys.
var ErrDuplicateKey = errors.New("duplicate object key")

// ErrAmbiguousString is returned for a document holding a string that
// encoding/json would decode to a value other than the one it spells.
var ErrAmbiguousString = errors.New("string does not decode to a single value")

// RejectAmbiguous reports an error if raw is not a well-formed JSON token
// stream, names the same key twice in one object, or holds a string
// encoding/json would silently rewrite. A signature over such bytes vouches
// for a document that different readers resolve to different values. It does
// not require exactly one value; Canonical does.
func RejectAmbiguous(raw []byte) error {
	if err := RejectDuplicateKeys(raw); err != nil {
		return err
	}
	return rejectRewrittenStrings(raw)
}

// RejectDuplicateKeys reports an error if raw names the same key twice within
// a single object, at any depth.
//
// THIS IS A SIGNING CONTROL, NOT A STYLE RULE. Decoding a duplicate key is
// undefined across implementations: Go's decoder and JSON.stringify's parser
// both keep the LAST occurrence, others keep the first, and some report an
// error. A signer that validates and digests the DECODED value while signing
// the ORIGINAL bytes therefore vouches for a document that a different reader
// resolves to different values — the caller chooses what each verifier sees.
// The only safe answer is to refuse the document rather than pick a winner,
// so no digest is ever computed for a document that means two things. Keys
// are compared decoded, so `"a"` and `"\u0061"` are the same key.
//
// The same NAME at different DEPTHS is not a duplicate: each object opens its
// own key namespace ("signed" is a key of both before_modes and after_modes
// on every real approval).
func RejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack keyStack
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		delim, isDelim := tok.(json.Delim)
		if f := stack.awaitingKey(isDelim); f != nil {
			key, ok := tok.(string)
			if !ok {
				return fmt.Errorf("object key is not a string: %v", tok)
			}
			if err := f.note(key); err != nil {
				return err
			}
			continue
		}
		switch {
		case isDelim && (delim == '{' || delim == '['):
			stack.consumedValue()
			stack = stack.push(delim == '{')
		case isDelim:
			if len(stack) == 0 {
				return errors.New("unbalanced JSON")
			}
			stack = stack[:len(stack)-1]
		default:
			stack.consumedValue()
		}
	}
}

// keyFrame tracks one open object or array while walking a JSON token stream.
// Inside an object the tokens alternate key, value, key, value; expectKey says
// which of the two the next non-delimiter token is.
type keyFrame struct {
	object    bool
	expectKey bool
	seen      map[string]struct{}
}

// note records a key, or reports that this object already named it.
func (f *keyFrame) note(key string) error {
	if _, dup := f.seen[key]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateKey, key)
	}
	f.seen[key] = struct{}{}
	f.expectKey = false
	return nil
}

type keyStack []*keyFrame

func (s keyStack) top() *keyFrame {
	if len(s) == 0 {
		return nil
	}
	return s[len(s)-1]
}

func (s keyStack) push(object bool) keyStack {
	return append(s, &keyFrame{object: object, expectKey: object, seen: map[string]struct{}{}})
}

// awaitingKey returns the innermost frame when the token just read is that
// object's next KEY rather than a value, and nil otherwise. Returning the
// frame rather than a bool hands the caller the non-nil pointer it would
// otherwise have to re-derive from top().
func (s keyStack) awaitingKey(isDelim bool) *keyFrame {
	f := s.top()
	if f == nil || !f.object || !f.expectKey || isDelim {
		return nil
	}
	return f
}

// consumedValue advances the enclosing object past a value it just read, so
// the next string it sees is read as a key again.
func (s keyStack) consumedValue() {
	if f := s.top(); f != nil && f.object {
		f.expectKey = true
	}
}

// rejectRewrittenStrings refuses invalid UTF-8 and any \u escape naming an
// unpaired surrogate. raw must already be valid JSON: a backslash then occurs
// only inside a string and always starts exactly one escape sequence, so the
// walk needs no string-boundary tracking.
func rejectRewrittenStrings(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%w: invalid UTF-8", ErrAmbiguousString)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i < len(raw) && raw[i] == 'u' {
			end, err := unicodeEscapeEnd(raw, i+1)
			if err != nil {
				return err
			}
			i = end
		}
	}
	return nil
}

// unicodeEscapeEnd reads the four hex digits of a \u escape starting at at,
// and for a high surrogate the \u escape that must pair with it. It returns
// the index of the last hex digit consumed.
func unicodeEscapeEnd(raw []byte, at int) (int, error) {
	r, ok := hex4(raw, at)
	if !ok {
		return 0, fmt.Errorf("%w: malformed \\u escape", ErrAmbiguousString)
	}
	last := at + 3
	if !utf16.IsSurrogate(r) {
		return last, nil
	}
	if last+2 < len(raw) && raw[last+1] == '\\' && raw[last+2] == 'u' {
		if low, ok := hex4(raw, last+3); ok && utf16.DecodeRune(r, low) != utf8.RuneError {
			return last + 6, nil
		}
	}
	return 0, fmt.Errorf("%w: unpaired surrogate \\u%04x", ErrAmbiguousString, r)
}

func hex4(raw []byte, at int) (rune, bool) {
	if at < 0 || at+4 > len(raw) {
		return 0, false
	}
	var r rune
	for _, c := range raw[at : at+4] {
		var d byte
		switch {
		case '0' <= c && c <= '9':
			d = c - '0'
		case 'a' <= c && c <= 'f':
			d = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(d)
	}
	return r, true
}

// Canonical returns the canonical bytes of one JSON value. A document
// RejectAmbiguous refuses is refused here rather than silently collapsed.
func Canonical(raw []byte) ([]byte, error) {
	if err := RejectAmbiguous(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	var out bytes.Buffer
	if err := write(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Digest returns the lowercase hex sha256 of Canonical(raw).
func Digest(raw []byte) (string, error) {
	canonical, err := Canonical(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func write(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case map[string]any:
		return writeObject(out, v)
	case []any:
		return writeArray(out, v)
	case json.Number:
		out.WriteString(v.String())
		return nil
	case string:
		writeString(out, v)
		return nil
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
		return nil
	case nil:
		out.WriteString("null")
		return nil
	default:
		return errors.New("unsupported JSON value")
	}
}

// writeString escapes exactly as JSON.stringify does: `"` and `\` with a
// backslash, \b \f \n \r \t by name, every other control character below
// 0x20 as \u00xx with lowercase hex, and EVERYTHING ELSE raw, including `/`,
// U+007F, non-ASCII, and U+2028/U+2029, which encoding/json would escape.
func writeString(out *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			out.WriteString(`\"`)
		case c == '\\':
			out.WriteString(`\\`)
		case c == '\b':
			out.WriteString(`\b`)
		case c == '\f':
			out.WriteString(`\f`)
		case c == '\n':
			out.WriteString(`\n`)
		case c == '\r':
			out.WriteString(`\r`)
		case c == '\t':
			out.WriteString(`\t`)
		case c < 0x20:
			out.WriteString(`\u00`)
			out.WriteByte(hexDigits[c>>4])
			out.WriteByte(hexDigits[c&0xf])
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
}

func writeObject(out *bytes.Buffer, v map[string]any) error {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := write(out, k); err != nil {
			return err
		}
		out.WriteByte(':')
		if err := write(out, v[k]); err != nil {
			return err
		}
	}
	out.WriteByte('}')
	return nil
}

func writeArray(out *bytes.Buffer, v []any) error {
	out.WriteByte('[')
	for i, item := range v {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := write(out, item); err != nil {
			return err
		}
	}
	out.WriteByte(']')
	return nil
}
