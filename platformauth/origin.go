// Copyright 2026 The Rookery Contributors
// SPDX-License-Identifier: Apache-2.0

package platformauth

// SameSchemeHost reports whether two URL origins, each a scheme and a host
// (host[:port], as url.URL.Host holds it), are the same origin: equal byte for
// byte up to ASCII case. A host carrying any non-ASCII byte never matches,
// itself included. strings.EqualFold and strings.ToLower fold Unicode, so
// "cİ.example" (U+0130) or a Kelvin sign would compare equal to an ASCII
// host, while Go's HTTP transport maps them through IDNA to a different
// punycode host: a bearer checked against one origin would be sent to
// another. An internationalized platform host is given in punycode (xn--).
// An empty host never matches.
func SameSchemeHost(scheme1, host1, scheme2, host2 string) bool {
	return host1 != "" && asciiEqualFold(scheme1, scheme2) && asciiEqualFold(host1, host2)
}

// IsASCII reports whether s holds only ASCII bytes.
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) || !IsASCII(a) || !IsASCII(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
