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
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// EVIDENCE LOSS — a signed attestation that failed to store.
//
// Signing happens before upload, so a store failure leaves an envelope that
// exists, is valid, and is nowhere the platform can see it. The run produced no
// platform evidence, which is the one thing the product exists to guarantee.
//
// Observed 2026-08-28 (maintenance.yml run 33142366506): two Archivista 503s
// inside a bounded window, the scan itself fine, only the evidence lost. The
// durable defect was not the 503 — it was that NOTHING NOTICED. The only signal
// was a red job conclusion, inside a workflow whose top-level conclusion had
// been red for 80 consecutive retained runs across two months. A new
// evidence-loss event was indistinguishable at a glance from the accumulated
// unrelated redness, and the reason lived only in step logs, which age out.
//
// So the signal below is deliberately NOT another log line. A GitHub Actions
// error annotation is surfaced by the Checks API as its own record, attached to
// the run and retained independently of log retention, which is what makes the
// gap auditable after the fact instead of reconstructable only from logs.

// evidenceLossTitle is the annotation title. Stable, greppable, and distinct
// from any other failure this binary can emit: an alerting rule keys on it.
const evidenceLossTitle = "cilock: attestation signed but NOT stored"

// storeTarget is the subset of the Archivista client the upload paths use. An
// interface so the loss signal can be tested without a server.
type storeTarget interface {
	Store(ctx context.Context, env dsse.Envelope) (string, error)
}

// evidenceRef names one piece of evidence that was lost, for the annotation.
// Subjects are the correlation anchors a verifier would have searched for, so
// naming them is what lets a reader establish WHAT went missing rather than
// merely that something did.
type evidenceRef struct {
	// Step is the cilock step the evidence belonged to.
	Step string
	// Subjects are the collection's subject names, already resolved.
	Subjects []string
	// Outfile, when set, is where the signed envelope was written locally. It
	// is not a recovery path — an attestation is evidence of an execution and
	// uploading a held bundle later would detach it from the act that produced
	// it — but it tells an auditor the bytes existed and where they were.
	Outfile string
}

// evidenceLossOut is where the loss annotation is written. A variable so a
// test can capture what the wrapper emits rather than calling the reporter
// directly — which is what lets the test fail if the wrapper stops reporting.
var evidenceLossOut io.Writer = os.Stderr

// storeEvidence is THE upload choke point. Every path that signs an envelope
// and then stores it goes through here, so the loss signal cannot be forgotten
// by a path added later — TestNoDirectStoreCallsOutsideChokePoint enforces that
// there is no second way in.
func storeEvidence(ctx context.Context, target storeTarget, env dsse.Envelope, ref evidenceRef) (string, error) {
	gitoid, err := target.Store(ctx, env)
	if err == nil && gitoid == "" {
		err = fmt.Errorf("upload response has no gitoid")
	}
	if err != nil {
		reportEvidenceLoss(evidenceLossOut, ref, err)
		return "", err
	}
	return gitoid, nil
}

// inGitHubActions reports whether this process is running under the Actions
// runner, which sets GITHUB_ACTIONS to the literal string "true" on every job.
// The variable is read at call time, so a test that sets it with t.Setenv is
// observed.
func inGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == envTrue
}

// reportEvidenceLoss writes the annotation. Takes its writer so a test can read
// what an operator would see.
//
// Outside GitHub Actions this is a no-op: the ::error:: syntax is meaningless in
// a plain terminal, the caller already returns a described error, and printing
// workflow-command syntax to a developer's console would be noise. The signal
// exists to survive in CI, which is where the evidence was lost.
func reportEvidenceLoss(w io.Writer, ref evidenceRef, cause error) {
	if !inGitHubActions() {
		return
	}
	// A write failure here has nowhere better to go: the caller is already on
	// the error path with a described error, and there is no second channel
	// to report that the report itself could not be written.
	_, _ = fmt.Fprintf(w, "::error title=%s::%s\n", evidenceLossTitle, evidenceLossMessage(ref, cause))
}

// evidenceLossMessage builds the one-line annotation body.
//
// One line because a workflow command is newline-terminated: a literal newline
// would end the annotation and leave the remainder as bare stdout, silently
// truncating the very record this exists to preserve.
//
// The message is assembled as plain text — raw newlines between sections, the
// subjects, outfile and cause pasted in verbatim — and encoded exactly once at
// the end. Encoding once is what keeps the output a faithful transcript of the
// input: a section break and a newline inside a server response body both
// become %0A and both render as line breaks, while a "%" or a literal "%0A"
// that arrived in the input is escaped so the runner shows the text that was
// actually there. Encoding a piece before pasting it in would escape it twice
// and render a stray "%25" where the input had "%".
func evidenceLossMessage(ref evidenceRef, cause error) string {
	var b strings.Builder
	b.WriteString("step ")
	b.WriteString(orUnnamed(ref.Step))
	b.WriteString(": the attestation was signed but NOT stored, so this run produced no platform evidence.")

	if len(ref.Subjects) > 0 {
		b.WriteString("\nlost evidence for ")
		fmt.Fprintf(&b, "%d subject(s): ", len(ref.Subjects))
		b.WriteString(strings.Join(ref.Subjects, ", "))
	}
	if ref.Outfile != "" {
		b.WriteString("\nsigned envelope was written to ")
		b.WriteString(ref.Outfile)
		b.WriteString(" (local copy only — re-run to regenerate the evidence; a held bundle uploaded later is detached from the run that produced it)")
	}
	if cause != nil {
		b.WriteString("\ncause: ")
		b.WriteString(cause.Error())
	}
	return encodeAnnotationData(b.String())
}

// encodeAnnotationData escapes the characters that would terminate or corrupt a
// workflow command, in the order the runner's decoder expects: percent first,
// so that the %0D and %0A produced by the two later steps cannot be mistaken
// for a percent that was in the input. Called once, on the fully assembled
// message; nothing is pre-encoded before it and nothing is un-escaped after.
func encodeAnnotationData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func orUnnamed(s string) string {
	if s == "" {
		return "(unnamed)"
	}
	return s
}

// lostSubjectNames flattens the summary's subjects to their names. Names only:
// the digests are already in the signed envelope and in the run summary, and an
// annotation that reprinted them would push the readable part of the message
// past where anyone looks.
func lostSubjectNames(subjects []options.RunSubject) []string {
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, s.Name)
	}
	return out
}
