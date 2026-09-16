// jade:ring local
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
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/stretchr/testify/require"
)

// A multi-line error must reach the terminal with real line breaks.
//
// cilock's failures are structured on purpose — the attestation-size refusal
// lists the five largest attestors and a remedy for each, and a dozen other
// errors (upload rejection, trust registration, subject candidates) end with
// an indented "here is what to do" block. Handing all of that to logrus as one
// message renders it as a single quoted line with literal \n in it, which is
// exactly the format no operator can read. The breakdown is the whole value of
// the message; if it arrives escaped, the feature does not work.
//
// So the first line goes through the logger (keeping the level=error prefix
// every other cilock failure has) and the remaining lines are written raw.
func TestMultiLineErrorsRenderWithRealNewlines(t *testing.T) {
	err := formatStatementTooLarge(&workflow.StatementTooLargeError{
		PredicateType: "https://aflock.ai/attestations/collection/v0.1",
		Bytes:         49_380_120,
		Limit:         4 << 20,
		Contributors:  []workflow.StatementContributor{{Type: commandrun.Type, Bytes: 49_300_000}},
	})

	var logged, raw bytes.Buffer
	reportCommandError(err, func(line string) { logged.WriteString(line + "\n") }, &raw)

	require.Equal(t, 1, strings.Count(logged.String(), "\n"), "exactly one line goes through the logger")
	require.Contains(t, logged.String(), "attestation too large")
	require.NotContains(t, logged.String(), `\n`, "the logged line must not carry escaped newlines")

	require.NotContains(t, raw.String(), `\n`, "the breakdown must not be escaped")
	require.Contains(t, raw.String(), "largest contributors:")
	require.Contains(t, raw.String(), "command-run/v0.2")
	require.Contains(t, raw.String(), "redirect")
	require.Greater(t, strings.Count(raw.String(), "\n"), 2, "the breakdown is several real lines")

	// Every line of the original error is accounted for, in order, with nothing
	// invented: a renderer that drops or reorders detail is worse than one that
	// escapes it, because the loss is silent.
	require.Equal(t, strings.Split(err.Error(), "\n"),
		strings.Split(strings.TrimSuffix(logged.String()+raw.String(), "\n"), "\n"))
}

// A single-line error keeps the behaviour every other cilock failure has: one
// logger call, nothing written raw.
func TestSingleLineErrorsStillGoOnlyThroughTheLogger(t *testing.T) {
	var logged, raw bytes.Buffer
	reportCommandError(errors.New("failed to load signer: failed to load any signers"),
		func(line string) { logged.WriteString(line + "\n") }, &raw)
	require.Equal(t, "failed to load signer: failed to load any signers\n", logged.String())
	require.Empty(t, raw.String())
}
