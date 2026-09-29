// Copyright 2026 The Rookery Contributors
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package platformauth

import (
	"testing"
	"unicode"
)

// asciiLookalikes is every non-ASCII rune that Unicode lower-casing, upper-
// casing or simple case folding maps to or from an ASCII letter: the runes a
// Unicode-aware comparison (strings.ToLower, strings.EqualFold) treats as that
// letter while the HTTP transport's IDNA mapping sends them to a different
// host. U+0130 (İ -> i) and U+212A (Kelvin sign -> k) and U+017F (ſ -> s) are
// among them. The set is computed, not listed, so a Unicode table change that
// adds one is covered.
func asciiLookalikes() map[rune]rune {
	out := map[rune]rune{}
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		cands := []rune{unicode.ToLower(r), unicode.ToUpper(r)}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			cands = append(cands, f)
		}
		for _, c := range cands {
			if c < 0x80 && unicode.IsLetter(c) {
				out[r] = c
				break
			}
		}
	}
	return out
}

func TestSameSchemeHostRefusesEveryUnicodeLookalike(t *testing.T) {
	look := asciiLookalikes()
	if len(look) < 3 {
		t.Fatalf("lookalike set suspiciously small: %d", len(look))
	}
	for r, ascii := range look {
		spoof := "c" + string(r) + ".example"
		real := "c" + string(ascii) + ".example"
		if SameSchemeHost("https", spoof, "https", real) || SameSchemeHost("https", real, "https", spoof) {
			t.Errorf("host %q (U+%04X) compares equal to %q", spoof, r, real)
		}
		if SameSchemeHost("https", spoof, "https", spoof) {
			t.Errorf("a non-ASCII host %q matches even itself; a host must be ASCII (punycode) to match", spoof)
		}
	}
}

func TestSameSchemeHostIsASCIICaseInsensitive(t *testing.T) {
	for _, c := range []struct {
		s1, h1, s2, h2 string
		want           bool
	}{
		{"https", "Platform.Example:8443", "HTTPS", "platform.example:8443", true},
		{"https", "xn--bcher-kva.example", "https", "XN--BCHER-KVA.EXAMPLE", true},
		{"https", "platform.example", "http", "platform.example", false},
		{"https", "platform.example", "https", "platform.example:443", false},
		{"https", "platform.example", "https", "platform.example.evil", false},
		{"https", "", "https", "", false},
		{"https", "platform.example", "https", "platform.examplE", true},
	} {
		if got := SameSchemeHost(c.s1, c.h1, c.s2, c.h2); got != c.want {
			t.Errorf("SameSchemeHost(%q,%q,%q,%q) = %v, want %v", c.s1, c.h1, c.s2, c.h2, got, c.want)
		}
	}
}
