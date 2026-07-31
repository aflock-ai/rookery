// Copyright 2026 The Archivista Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package source

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
)

// TestRetentionAmplificationAgainstRealCorpus measures heap RETAINED per stored
// byte when the verify path decodes a real collection envelope and holds the
// result — the shape verifySteps keeps in StepResult.Passed across the depth
// loop. It reproduces the prod-observed ~4.7x amplification (17.8 MiB heap per
// 3.76 MiB stored) so a fix can be measured against it.
//
// Faithful to CURRENT main: envelopeToCollectionEnvelope decodes, then
// releaseEnvelopeBytes drops the raw Envelope.Payload/Signatures from the
// retained copy (already live). What remains retained is Statement (including
// its ~3.5 MiB Predicate json.RawMessage) plus the parsed Collection (whose
// material member is ~5 MiB). Those two are what this task targets.
//
// Skipped unless CORPUS_DIR points at the flat gitoid-keyed report bucket dump.
//
//	Run: CORPUS_DIR=/path/to/reports-corpus go test ./attestation/source/ \
//	       -run TestRetentionAmplificationAgainstRealCorpus -v -count=1
func TestRetentionAmplificationAgainstRealCorpus(t *testing.T) {
	dir := os.Getenv("CORPUS_DIR")
	if dir == "" {
		t.Skip("set CORPUS_DIR to the real report-bucket dump to run this measurement")
	}
	prefixFile := os.Getenv("CORPUS_PREFIXES") // optional: limit to the verified set

	files := corpusFiles(t, dir, prefixFile)
	if len(files) == 0 {
		t.Fatal("no corpus files resolved")
	}

	var storedBytes int64
	retained := make([]CollectionVerificationResult, 0, len(files))

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		storedBytes += int64(len(raw))

		var env dsse.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue // not a DSSE envelope
		}
		ce, err := envelopeToCollectionEnvelope(filepath.Base(f), env)
		if err != nil {
			continue
		}
		// Match the retained shape after verification on current main.
		releaseEnvelopeBytes(&ce)
		retained = append(retained, CollectionVerificationResult{CollectionEnvelope: ce})
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	// Keep the slice alive across the measurement.
	if len(retained) == 0 {
		t.Fatal("nothing retained")
	}

	heapDelta := int64(after.HeapInuse) - int64(before.HeapInuse)
	storedMiB := float64(storedBytes) / (1 << 20)
	heapMiB := float64(heapDelta) / (1 << 20)
	amp := heapMiB / storedMiB

	t.Logf("decoded+retained %d/%d envelopes", len(retained), len(files))
	t.Logf("stored:   %.1f MiB", storedMiB)
	t.Logf("retained: %.1f MiB heap", heapMiB)
	t.Logf("AMPLIFICATION: %.2fx heap-retained per stored byte", amp)

	runtime.KeepAlive(retained)
}

func corpusFiles(t *testing.T, dir, prefixFile string) []string {
	t.Helper()
	if prefixFile != "" {
		return corpusFilesByPrefix(t, dir, prefixFile)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// corpusFilesByPrefix resolves the hot-set prefix list (12-hex-char gitoid
// prefixes, one per line) against the flat corpus directory.
func corpusFilesByPrefix(t *testing.T, dir, prefixFile string) []string {
	t.Helper()
	data, err := os.ReadFile(prefixFile)
	if err != nil {
		t.Fatalf("read prefixes %s: %v", prefixFile, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	byPrefix := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if len(name) >= 12 {
			byPrefix[name[:12]] = filepath.Join(dir, name)
		}
	}
	var out []string
	for _, line := range splitNonEmpty(string(data)) {
		if f, ok := byPrefix[line]; ok {
			out = append(out, f)
		}
	}
	return out
}

func splitNonEmpty(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
