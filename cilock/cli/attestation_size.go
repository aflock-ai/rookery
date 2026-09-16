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

package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/spf13/cobra"
)

// Attestation size limit: the CLI half.
//
// The measurement and the refusal live in attestation/workflow
// (StatementTooLargeError); this file resolves the operator's limit
// (flag > env > 4 MiB default, see internal/options) and turns the refusal
// into a message that says what filled the statement and what to do about
// each contributor. See attestation/archivista/size_advice.go for the
// upload-time cousin of this message; the facts about which attestor has
// which lever are kept identical between the two.

// resolveMaxAttestationBytes applies flag > env > default for a command that
// registered the flag, announcing an explicit 0 on stderr.
//
// os.Getenv is passed in rather than called, which is what makes the
// precedence testable without mutating the process environment. It is NOT a
// Viper violation: the "all configuration goes through Viper" rule is
// judge-api's, enforced by forbidigo in judge-api/.golangci.yml, and cilock is
// a separately distributed CLI that imports Viper nowhere (0 files) and reads
// its environment through os.Getenv in 36 places, including its own resolver
// at internal/options/resolve.go. Adding a Viper dependency and a config
// surface to a customer-facing binary for one integer would import judge-api's
// convention into a subtree it does not govern.
func resolveMaxAttestationBytes(cmd *cobra.Command, flagValue options.ByteSize) (int, error) {
	return options.ResolveMaxAttestationBytes(cmd, flagValue, os.Getenv, os.Stderr)
}

// checkAttestationSize refuses data that is over limit bytes, rendering the
// refusal for an operator. It is the one entry point the CLI uses, so a
// caller cannot check the size and then forget to explain the failure.
// A limit of zero or less is unlimited.
func checkAttestationSize(data []byte, predicateType string, limit int) error {
	err := workflow.CheckStatementSize(data, predicateType, limit)
	var tooLarge *workflow.StatementTooLargeError
	if errors.As(err, &tooLarge) {
		return formatStatementTooLarge(tooLarge)
	}
	return err
}

// remedyShare is the fraction of the statement a contributor must hold before
// its remedy is worth printing.
//
// Every contributor's SIZE is printed — that is the measurement, and dropping
// it would hide which attestor is which. But a remedy is an instruction, and
// telling someone to narrow their product globs to save 144 bytes out of
// 47 MB is worse than saying nothing: it is a plausible-looking path that
// cannot work, and they will follow it before they read the line above. The
// largest contributor always gets its remedy, however small, so the message is
// never a list of sizes with nothing to do about any of them.
const remedyShare = 0.10

// secondsPerMB is the platform's measured evaluate-release parse cost
// (2026-09-15): downloads + JSON-parses every envelope matching the commit,
// three times, uncached above 512 KiB.
const secondsPerMB = 0.4

// formatStatementTooLarge renders a workflow refusal for an operator: the
// total, the limit and how to change it, why the limit exists, and the
// largest contributors, each with a remedy cilock can vouch for where the
// contributor is big enough for a remedy to be worth acting on.
func formatStatementTooLarge(e *workflow.StatementTooLargeError) error {
	var b strings.Builder
	fmt.Fprintf(&b, "attestation too large: the %s statement is %s (%s bytes), over the %s limit "+
		"(--%s, or %s). Refusing to sign, write or upload it: the platform parses every envelope "+
		"matching a commit on each push evaluation at ~%.1f s/MB against a 25 s budget",
		shortPredicateName(e.PredicateType), humanByteCount(e.Bytes), commaBytes(e.Bytes),
		options.FormatByteSize(int64(e.Limit)), options.MaxAttestationBytesFlag, options.MaxAttestationBytesEnv,
		secondsPerMB)
	// Only quote the per-push cost when it is a number worth quoting. Rounding
	// 0.11 s to "about 0 s per push" reads as "this costs nothing", which
	// argues against the very limit the sentence is explaining.
	if cost := float64(e.Bytes) / 1e6 * secondsPerMB; cost >= 1 {
		fmt.Fprintf(&b, ", so one envelope this size would cost about %.0f s per push", cost)
	}
	b.WriteString(".")
	if len(e.Contributors) > 0 {
		b.WriteString("\n  largest contributors:")
	}
	for i, c := range e.Contributors {
		fmt.Fprintf(&b, "\n    %10s  %s", humanByteCount(c.Bytes), shortPredicateName(c.Type))
		if i == 0 || e.Bytes <= 0 || float64(c.Bytes)/float64(e.Bytes) >= remedyShare {
			fmt.Fprintf(&b, "\n      %s", remedyFor(c.Type))
		}
	}
	return fmt.Errorf("%s", b.String())
}

// remedyFor is the one line cilock can say about shrinking a given
// attestor, keyed on the attestor's predicate type. Every flag it names is
// checked against the real `cilock run` flag set by
// TestStatementTooLargeRemediesNameRealRunFlags.
func remedyFor(typeURI string) string {
	switch attestorFamily(typeURI) {
	case commandrun.Name:
		return "command-run records the wrapped command's stdout and stderr verbatim; redirect the noisy stream " +
			"to a file under the working directory (e.g. -- sh -c 'go test -json ./... > test-output.json') so it " +
			"is attested as a product digest instead of inline"
	case product.Name:
		return "narrow the product set with ONE --" + registry.AttestorFlagName(product.Name, "exclude-glob") +
			" (the flag is last-one-wins, so put every tree in a single brace alternation, e.g. " +
			"'{**/,}{node_modules,.venv}/**'); exclude dependencies, never build output"
	case material.Name:
		return "the material attestor walks the whole working directory and has no include/exclude glob; remove " +
			"untracked dependency trees from the working directory (`git ls-files <dir>` prints nothing for those), " +
			"or use --material-manifest so per-file details live in a detached inventory that this limit does not apply to"
	default:
		return "drop the attestor from -a if its evidence is not needed here, or raise --" + options.MaxAttestationBytesFlag +
			" if the evidence store can take it (0 disables the limit)"
	}
}

// attestorFamily reduces a predicate type URI to the attestor name it was
// registered under: https://aflock.ai/attestations/command-run/v0.2 ->
// command-run. Legacy witness.dev URIs have the same shape.
func attestorFamily(typeURI string) string {
	segs := strings.Split(strings.TrimRight(typeURI, "/"), "/")
	if len(segs) < 2 {
		return typeURI
	}
	return segs[len(segs)-2]
}

// shortPredicateName is the operator-facing form of a predicate type:
// https://aflock.ai/attestations/material/v0.3 -> material/v0.3.
func shortPredicateName(typeURI string) string {
	if typeURI == "" {
		return "(unnamed)"
	}
	segs := strings.Split(strings.TrimRight(typeURI, "/"), "/")
	if len(segs) >= 2 {
		return segs[len(segs)-2] + "/" + segs[len(segs)-1]
	}
	return segs[len(segs)-1]
}

// humanByteCount renders a byte count the way an operator reads one.
func humanByteCount(n int) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := int64(n) / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}

// commaBytes renders an exact byte count with thousands separators, so the
// exact number and the rounded one can sit side by side without confusing
// each other.
func commaBytes(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	return strings.Join(append([]string{s}, parts...), ",")
}
