// Slim fork of upstream gitleaks/v8/report/finding.go for the
// TestifySec rookery secretscan attestor. Trimmed to the Finding +
// RequiredFinding types and the Redact helper. The
// sources.Fragment-typed Fragment field is replaced with an opaque
// `any` so we don't pull github.com/zricethezav/gitleaks/v8/sources
// (which transitively brings mholt/archives + the compression zoo).
// PrintRequiredFindings (the lipgloss-using terminal pretty-printer)
// is removed — we never invoke it from the library use case.
package report

import (
	"math"
	"strings"
)

// Finding contains a whole bunch of information about a secret finding.
type Finding struct {
	RuleID      string
	Description string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string `json:"-"`

	Match string

	// Captured secret
	Secret string

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string
	Link        string `json:",omitempty"`

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// unique identifier
	Fingerprint string

	// Fragment was *sources.Fragment in upstream — opaque here to keep
	// the slim fork detached from the deleted sources/ package. The
	// secretscan attestor never reads this field.
	Fragment any `json:",omitempty"`

	requiredFindings []*RequiredFinding
}

type RequiredFinding struct {
	RuleID      string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Line        string `json:"-"`
	Match       string
	Secret      string
}

func (f *Finding) AddRequiredFindings(afs []*RequiredFinding) {
	if f.requiredFindings == nil {
		f.requiredFindings = make([]*RequiredFinding, 0)
	}
	f.requiredFindings = append(f.requiredFindings, afs...)
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secret := maskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.Secret = secret
}

func maskSecret(secret string, percent uint) string {
	if percent > 100 {
		percent = 100
	}
	length := float64(len(secret))
	if length <= 0 {
		return secret
	}
	prc := float64(100 - percent)
	lth := int64(math.RoundToEven(length * prc / float64(100)))

	return secret[:lth] + "..."
}

// PrintRequiredFindings was a lipgloss-using terminal pretty-printer in
// upstream; removed here since the slim fork is library-only. Callers
// in the deleted detect/utils.go invoked this for CLI output.
func (f *Finding) PrintRequiredFindings() {
	// no-op in the slim fork
}
