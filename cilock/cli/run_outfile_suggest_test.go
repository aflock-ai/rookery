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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Onboarding simulator (fullblind45, fullblind56, mx-python-click-l3): the
// agent re-ran a step with the same -o after deleting good.json, and was
// refused on "good.json-material-inventory.json", a companion file it had
// never named. The refusal said "select a new --outfile" and nothing else, so
// it did not say the path was a companion, that every mint needs a fresh
// outfile, or what to pass.

func TestTakenEvidencePathNamesTheCompanionAndAFreshOutfile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "good.json")
	companion := out + "-material-inventory.json"
	require.NoError(t, os.WriteFile(companion, []byte("earlier"), 0o600))

	err := refuseTakenEvidencePaths(out, true)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "refuse existing or inaccessible evidence path", "the prefix the metrics and older tests key on stays")
	require.Contains(t, msg, companion)
	require.Contains(t, msg, `the material inventory written beside --outfile "`+out+`"`)
	require.Contains(t, msg, "cilock never overwrites evidence, so every run, a re-run of the same step included, needs a fresh --outfile")
	require.Contains(t, msg, "Next: rerun with --outfile '"+filepath.Join(dir, "good-2.json")+"'")
}

func TestTakenEvidencePathSuggestionSkipsTakenNames(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "good.json")
	require.NoError(t, os.WriteFile(out, []byte("earlier"), 0o600))
	// good-2.json is free but its companion is not, so it is not free.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "good-2.json-product-inventory.json"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "good-3.json"), []byte("x"), 0o600))

	err := refuseTakenEvidencePaths(out, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "(the --outfile itself)")
	require.Contains(t, err.Error(), "--outfile '"+filepath.Join(dir, "good-4.json")+"'")
}

func TestFreshOutfileSuggestionHandlesNoExtensionAndQuotes(t *testing.T) {
	dir := t.TempDir()
	require.Equal(t, filepath.Join(dir, "evidence-2"), suggestFreshOutfile(filepath.Join(dir, "evidence")))
	// A name a shell would act on is single-quoted by the caller, never
	// interpolated raw; an unprintable one gets no suggestion at all.
	require.Empty(t, suggestFreshOutfile(filepath.Join(dir, "bad\x1bname.json")))
	msg := takenEvidencePathError(filepath.Join(dir, "it's.json"), filepath.Join(dir, "it's.json")).Error()
	require.True(t, strings.Contains(msg, `'\''`), "the suggestion is shell-quoted: %s", msg)
}
