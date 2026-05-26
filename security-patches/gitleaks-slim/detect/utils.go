// Slim fork of upstream detect/utils.go for the rookery secretscan
// attestor. Trimmed to shannonEntropy + filter + a stub createScmLink.
// printFinding (lipgloss + sources) and the full SCM-URL switch
// (sources.RemoteInfo and friends) are removed since this fork has no
// CLI / git-scan surface — secretscan only calls DetectBytes on
// in-memory content.
package detect

import (
	"math"
	"strings"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

// createScmLink is a stub in the slim fork. In upstream gitleaks it built a
// platform-specific URL (GitHub blob, GitLab blob, Azure DevOps commit,
// Gitea src, Bitbucket src) from a sources.RemoteInfo + finding. The
// secretscan attestor never invokes the git-scan path that populates
// CommitInfo, so this is always called with no remote and returns "".
func createScmLink(_ any, _ report.Finding) string {
	return ""
}

// shannonEntropy calculates the entropy of data.
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// filter will dedupe and redact findings
func filter(findings []report.Finding, redact uint) []report.Finding {
	var retFindings []report.Finding
	for _, f := range findings {
		include := true
		if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
				if f.StartLine == fPrime.StartLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
					betterMatch := strings.ReplaceAll(fPrime.Match, fPrime.Secret, "REDACTED")
					logging.Trace().Msgf("skipping %s finding (%s), %s rule takes precedence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if redact > 0 {
			f.Redact(redact)
		}
		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

// printFinding is a no-op in the slim fork; upstream's lipgloss-using
// terminal pretty-printer is removed since this fork has no CLI surface.
func printFinding(_ report.Finding, _ bool) {}
