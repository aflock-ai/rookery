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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
)

// PEAK driver. The durable-retention measurement (retention_bench_test.go)
// reports ~1.5x; prod's aborted unparks showed ~4.7x PEAK HeapInuse per stored
// byte. Those are different quantities, and only the peak one is the number the
// fix has to move. This samples HeapInuse on a tight ticker WHILE the verify
// path decodes the real hot set, and reports the max.
//
// It also emits a VERDICT FINGERPRINT — a stable hash over each envelope's
// decode outcome (reference, collection name, attestation types, subject
// digests). No candidate fix counts unless this fingerprint is byte-identical
// to the baseline committed alongside it.
//
// FIDELITY, stated plainly: this drives the real corpus through the real
// decode + release path (envelopeToCollectionEnvelope + releaseEnvelopeBytes),
// which is where the transient allocation lives. It does NOT run
// Policy.Verify with the prod policy's Fulcio functionaries — the prod policy
// envelope is not in hand. So it reproduces the DECODE-side peak, not the
// signature-verification-side peak. If the number lands well below prod's
// 17.8 MiB/envelope, the gap is attributable to what this omits, and that is
// itself the finding.
//
// Run:
//
//	CORPUS_DIR=... CORPUS_PREFIXES=/tmp/prefixes.txt \
//	  go test ./attestation/source/ -run TestPeak -v -count=1
type peakSampler struct {
	stop chan struct{}
	done chan struct{}
	max  uint64
	mu   sync.Mutex
}

func startPeakSampler() *peakSampler {
	p := &peakSampler{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		var ms runtime.MemStats
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				runtime.ReadMemStats(&ms)
				p.mu.Lock()
				if ms.HeapInuse > p.max {
					p.max = ms.HeapInuse
				}
				p.mu.Unlock()
			}
		}
	}()
	return p
}

func (p *peakSampler) finish() uint64 {
	close(p.stop)
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.max
}

// decodeTurn performs one verify-shaped pass over the corpus: read, decode,
// release raw bytes, retain the compact result — exactly what one
// VerifyWorkflow turn holds for its step results.
func decodeTurn(t *testing.T, files []string) ([]CollectionVerificationResult, int64, []string) {
	t.Helper()
	out := make([]CollectionVerificationResult, 0, len(files))
	var stored int64
	fingerprints := make([]string, 0, len(files))

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		stored += int64(len(raw))

		var env dsse.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		ce, err := envelopeToCollectionEnvelope(filepath.Base(f), env)
		if err != nil {
			continue
		}
		fingerprints = append(fingerprints, fingerprintOne(ce))
		releaseEnvelopeBytes(&ce)
		out = append(out, CollectionVerificationResult{CollectionEnvelope: ce})
	}
	return out, stored, fingerprints
}

// fingerprintOne captures the decode OUTCOME that verification depends on:
// reference, collection name, ordered attestation types, ordered subject
// digests. Deliberately excludes byte counts so a memory fix that preserves
// semantics leaves it unchanged.
func fingerprintOne(ce CollectionEnvelope) string {
	types := make([]string, 0, len(ce.Collection.Attestations))
	for _, a := range ce.Collection.Attestations {
		types = append(types, a.Type)
	}
	sort.Strings(types)

	digests := make([]string, 0)
	for _, s := range ce.Statement.Subject {
		for alg, d := range s.Digest {
			digests = append(digests, alg+":"+d)
		}
	}
	sort.Strings(digests)

	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|", ce.Reference, ce.Collection.Name)
	for _, x := range types {
		fmt.Fprintf(h, "t=%s;", x)
	}
	for _, x := range digests {
		fmt.Fprintf(h, "d=%s;", x)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func corpusFingerprint(parts []string) string {
	sort.Strings(parts)
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%s\n", p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestPeakOneTurn(t *testing.T) {
	files := peakCorpus(t)
	runtime.GC()

	s := startPeakSampler()
	retained, stored, fps := decodeTurn(t, files)
	peak := s.finish()
	runtime.KeepAlive(retained)

	reportPeak(t, "1-turn", peak, stored, len(retained))
	t.Logf("VERDICT FINGERPRINT: %s", corpusFingerprint(fps))
}

func TestPeakTwoConcurrentTurns(t *testing.T) {
	files := peakCorpus(t)
	runtime.GC()

	s := startPeakSampler()
	var wg sync.WaitGroup
	results := make([][]CollectionVerificationResult, 2)
	stored := make([]int64, 2)
	fps := make([][]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], stored[i], fps[i] = decodeTurn(t, files)
		}(i)
	}
	wg.Wait()
	peak := s.finish()
	runtime.KeepAlive(results)

	reportPeak(t, "2-turn", peak, stored[0], len(results[0]))
	if a, b := corpusFingerprint(fps[0]), corpusFingerprint(fps[1]); a != b {
		t.Errorf("concurrent turns disagree on decode outcome: %s vs %s", a, b)
	}
}

func reportPeak(t *testing.T, label string, peak uint64, stored int64, n int) {
	t.Helper()
	storedMiB := float64(stored) / (1 << 20)
	peakMiB := float64(peak) / (1 << 20)
	t.Logf("[%s] envelopes:      %d", label, n)
	t.Logf("[%s] stored:         %.1f MiB", label, storedMiB)
	t.Logf("[%s] PEAK HeapInuse: %.1f MiB", label, peakMiB)
	if n > 0 {
		t.Logf("[%s] peak per envelope: %.2f MiB (prod observed 17.8)", label, peakMiB/float64(n))
	}
	if storedMiB > 0 {
		t.Logf("[%s] PEAK AMPLIFICATION: %.2fx (prod observed 4.7)", label, peakMiB/storedMiB)
	}
}

func peakCorpus(t *testing.T) []string {
	t.Helper()
	dir := os.Getenv("CORPUS_DIR")
	if dir == "" {
		t.Skip("set CORPUS_DIR to the real report-bucket dump")
	}
	files := corpusFiles(t, dir, os.Getenv("CORPUS_PREFIXES"))
	if len(files) == 0 {
		t.Fatal("no corpus files resolved")
	}
	return files
}
