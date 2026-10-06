// jade:ring local

package auth

import (
	"bytes"
	"html"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestFirstRunCallbackGuidanceMatchesModel holds the loopback page `cilock
// login` shows after the platform posts the credential to the guidance edges
// formal/pushgate-ux gives it (PushgateUx/FirstRun.lean, data in
// firstrun_formal_data_test.go). Only the text a person reads counts: tags,
// the stylesheet and the script are dropped before the needles are applied.
func TestFirstRunCallbackGuidanceMatchesModel(t *testing.T) {
	var out bytes.Buffer
	writeCallbackPage(&out, "acme", "https://pushgate.dev")
	page := out.String()
	if !strings.Contains(page, "Cilock authorized") || !strings.Contains(page, "<strong>acme</strong>") {
		t.Fatalf("writeCallbackPage did not render the login receipt:\n%s", page)
	}
	got := firstRunTargets(visibleText(page))
	want := slices.Clone(firstRunGuides)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("callback page guides to %v, the model says %v; update FirstRun.lean and regenerate", got, want)
	}
}

var (
	firstRunHidden = regexp.MustCompile(`(?is)<(style|script|title)[^>]*>.*?</(style|script|title)>`)
	firstRunTag    = regexp.MustCompile(`<[^>]*>`)
)

func visibleText(page string) string {
	return html.UnescapeString(firstRunTag.ReplaceAllString(firstRunHidden.ReplaceAllString(page, " "), " "))
}

func firstRunTargets(text string) []string {
	lower := strings.ToLower(text)
	var got []string
	for _, n := range firstRunNeedles {
		if strings.Contains(lower, n[0]) && !slices.Contains(got, n[1]) {
			got = append(got, n[1])
		}
	}
	sort.Strings(got)
	return got
}
