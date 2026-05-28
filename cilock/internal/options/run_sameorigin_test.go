package options

import "testing"

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "https://platform.testifysec.com/archivista", "https://platform.testifysec.com/archivista", true},
		{"same origin different path", "https://platform.testifysec.com/upload", "https://platform.testifysec.com/archivista", true},
		{"scheme case-insensitive", "HTTPS://platform.testifysec.com/x", "https://platform.testifysec.com/archivista", true},
		{"host case-insensitive", "https://Platform.TestifySec.com/x", "https://platform.testifysec.com/archivista", true},
		{"different host", "https://evil.example/archivista", "https://platform.testifysec.com/archivista", false},
		{"different scheme", "http://platform.testifysec.com/archivista", "https://platform.testifysec.com/archivista", false},
		{"different port", "https://platform.testifysec.com:8443/archivista", "https://platform.testifysec.com/archivista", false},
		{"empty target host", "", "https://platform.testifysec.com/archivista", false},
		{"empty platform host", "https://platform.testifysec.com/archivista", "", false},
		{"garbage target", "://not a url", "https://platform.testifysec.com/archivista", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameOrigin(tc.a, tc.b); got != tc.want {
				t.Errorf("sameOrigin(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
