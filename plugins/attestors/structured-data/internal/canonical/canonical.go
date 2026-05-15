// Package canonical implements RFC 8785 JSON Canonicalization Scheme (JCS).
// The structured-data attestor uses JCS to produce a deterministic digest of
// the collected data, so two attestor runs against the same input produce
// byte-identical envelopes regardless of map iteration order or whitespace.
//
// JCS rules implemented here:
//   - Object keys are sorted lexicographically by their UTF-16 code unit
//     sequence (the IETF spec defers to ECMAScript-262 §22.1.3.30 sort, which
//     compares UTF-16 code units). For pure ASCII keys this matches Go's
//     default string ordering; for non-ASCII keys we sort on the actual
//     UTF-16 encoding so we match RFC 8785 §3.2.3.
//   - Strings are encoded with the minimal escape set from RFC 8785 §3.2.2
//     (only the seven mandatory escapes plus non-ASCII as \uXXXX surrogates).
//   - Numbers are encoded via the Number Serialization rules of
//     ECMAScript-262 §6.1.6.1.20 (ToString abstract op). The structured-data
//     attestor only feeds in JSON it has already unmarshalled, so every number
//     is a float64 — we emit it via strconv.FormatFloat with the shortest
//     representation that round-trips.
//   - Arrays, booleans, and null are emitted as-is.
//
// JCS is much smaller than a full JSON parser would be — we operate on the
// already-parsed any tree (map[string]any / []any / string / float64 /
// bool / nil) that the attestor gets from json.Unmarshal.
package canonical

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Marshal returns the RFC 8785 canonical encoding of v. v must be of types
// json.Unmarshal produces (map[string]any, []any, string, float64, bool,
// nil) — any other type is rejected.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case float64:
		return writeNumber(buf, x)
	case string:
		writeString(buf, x)
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		buf.WriteByte('{')
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
}

// writeNumber follows ECMAScript-262's ToString abstract operation for
// Numbers — the shortest decimal that uniquely round-trips, with no trailing
// zeros after the decimal point, no leading `+`, etc. strconv's 'g' verb
// with precision -1 produces the shortest round-trip representation; that's
// the V8/SpiderMonkey behavior JCS depends on for cross-implementation
// reproducibility.
func writeNumber(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("canonical: NaN and Inf are not representable in JSON")
	}
	if f == 0 {
		buf.WriteByte('0')
		return nil
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	// FormatFloat may emit `1e+09`; ECMAScript spec uses `1e+9` (no leading
	// zero in exponent). Strip a single leading zero from the exponent.
	if i := bytes.IndexAny([]byte(s), "eE"); i >= 0 {
		expSign := s[i+1]
		exp := s[i+2:]
		// Drop leading zeros in the exponent magnitude.
		j := 0
		for j < len(exp)-1 && exp[j] == '0' {
			j++
		}
		s = s[:i+1] + string(expSign) + exp[j:]
	}
	buf.WriteString(s)
	return nil
}

// writeString emits a JSON string with the RFC 8785 §3.2.2 escape set:
// only `"` `\` and U+0000..U+001F get escaped; everything else (including
// non-ASCII) is emitted verbatim. Control characters use \uXXXX form.
// (Go's default json.Marshal escapes additional code points like U+2028 —
// we deliberately do NOT, per the JCS spec.)
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// utf16Less compares two strings by their UTF-16 code unit sequence, which
// is what RFC 8785 §3.2.3 requires for object key ordering. Pure ASCII
// keys compare identically to byte order; this only matters when keys
// contain code points outside the BMP (surrogate pairs).
func utf16Less(a, b string) bool {
	if a == b {
		return false
	}
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
