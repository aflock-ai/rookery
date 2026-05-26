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

// Package bundle implements the cilock attestation bundle format: a tar.gz
// archive containing newline-delimited DSSE envelopes plus a manifest. See
// https://github.com/aflock-ai/rookery/issues/120 for the design rationale.
//
// A bundle is a portable evidence package: one file that carries the DSSE
// envelopes needed to satisfy a policy's step graph. It is intentionally
// distinct from the Sigstore protobuf bundle (which is per-artifact) — a
// cilock bundle is per-policy-evaluation and stays JSONL so it is streamable
// and grep-friendly.
//
// Layout:
//
//	release.bundle.tar.gz
//	├── bundle.json          // manifest: subjects, source, created_at, envelopes
//	└── attestations.jsonl   // one DSSE envelope per line
//
// The bundle itself is unsigned — the envelopes inside are individually
// signed and that is what carries cryptographic weight. The manifest records
// a sha256 per envelope so a verifier can detect post-hoc tampering of the
// JSONL.
package bundle

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
)

const (
	SchemaVersion = "https://aflock.ai/bundle/v0.1"

	ManifestFilename  = "bundle.json"
	EnvelopesFilename = "attestations.jsonl"

	// MaxBundleBytes caps the total decompressed bytes the Reader will accept.
	// Defends against gzip-bomb input. Practical bundles in the documented use
	// cases (one release's worth of attestations) are well under this.
	MaxBundleBytes = 512 << 20 // 512 MiB

	// MaxEnvelopes caps the number of envelopes the Reader will accept.
	MaxEnvelopes = 100000

	// MaxLineBytes caps a single JSONL line. DSSE envelopes carrying large
	// SBOMs can be several MB; 32 MiB gives generous headroom while still
	// bounding per-line memory.
	MaxLineBytes = 32 << 20

	SourceArchivista   = "archivista"
	SourceFile         = "file"
	SourceVerifyExport = "verify-export"
)

// Manifest is the bundle.json descriptor packed alongside attestations.jsonl.
//
// The manifest is **not** cryptographic evidence — it is convenience metadata
// for tooling (inspect, dedup, integrity checks). The envelopes inside the
// JSONL carry their own signatures and that is what verifies.
type Manifest struct {
	SchemaVersion string             `json:"schemaVersion"`
	CreatedAt     time.Time          `json:"createdAt"`
	Source        string             `json:"source,omitempty"`
	SourceURL     string             `json:"sourceURL,omitempty"`
	Subjects      []string           `json:"subjects,omitempty"`
	Count         int                `json:"count"`
	Envelopes     []EnvelopeManifest `json:"envelopes,omitempty"`
}

// EnvelopeManifest is the per-envelope record in Manifest.Envelopes. Sha256
// is computed over the canonical JSON bytes of the envelope as written to
// the JSONL — verifying it against the actual line content catches tampering.
type EnvelopeManifest struct {
	Sha256       string   `json:"sha256"`
	PayloadType  string   `json:"payloadType,omitempty"`
	SignerKeyIDs []string `json:"signerKeyIDs,omitempty"`
}

// Writer accumulates DSSE envelopes and produces a tar.gz bundle on Close.
// Duplicate envelopes (same sha256 of the marshalled JSON) are silently
// dropped — bundles are evidence sets, not ordered logs.
type Writer struct {
	out      io.Writer
	manifest Manifest
	jsonl    bytes.Buffer
	seen     map[string]struct{}
	closed   bool
}

func NewWriter(out io.Writer) *Writer {
	return &Writer{
		out: out,
		manifest: Manifest{
			SchemaVersion: SchemaVersion,
			CreatedAt:     time.Now().UTC(),
		},
		seen: make(map[string]struct{}),
	}
}

func (w *Writer) SetSource(source, sourceURL string) {
	w.manifest.Source = source
	w.manifest.SourceURL = sourceURL
}

func (w *Writer) SetSubjects(subjects []string) {
	dedup := make(map[string]struct{}, len(subjects))
	for _, s := range subjects {
		dedup[s] = struct{}{}
	}
	out := make([]string, 0, len(dedup))
	for s := range dedup {
		out = append(out, s)
	}
	sort.Strings(out)
	w.manifest.Subjects = out
}

// SetCreatedAt overrides the default createdAt timestamp (UTC now). Mostly
// useful for deterministic tests.
func (w *Writer) SetCreatedAt(t time.Time) {
	w.manifest.CreatedAt = t.UTC()
}

// Add appends a DSSE envelope to the bundle. Returns an error if the envelope
// cannot be marshalled.
func (w *Writer) Add(env dsse.Envelope) error {
	if w.closed {
		return errors.New("bundle writer is closed")
	}

	line, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	sum := sha256.Sum256(line)
	digest := hex.EncodeToString(sum[:])
	if _, dup := w.seen[digest]; dup {
		return nil
	}
	w.seen[digest] = struct{}{}

	w.jsonl.Write(line)
	w.jsonl.WriteByte('\n')

	keyIDs := make([]string, 0, len(env.Signatures))
	for _, sig := range env.Signatures {
		if sig.KeyID != "" {
			keyIDs = append(keyIDs, sig.KeyID)
		}
	}

	w.manifest.Envelopes = append(w.manifest.Envelopes, EnvelopeManifest{
		Sha256:       digest,
		PayloadType:  env.PayloadType,
		SignerKeyIDs: keyIDs,
	})
	w.manifest.Count++
	return nil
}

func (w *Writer) Count() int { return w.manifest.Count }

// Close finalizes the bundle: writes bundle.json then attestations.jsonl
// into a tar.gz stream on the underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	manifestBytes, err := json.MarshalIndent(w.manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	gz := gzip.NewWriter(w.out)
	tw := tar.NewWriter(gz)

	if err := writeTarEntry(tw, ManifestFilename, manifestBytes, w.manifest.CreatedAt); err != nil {
		return fmt.Errorf("write manifest entry: %w", err)
	}

	if err := writeTarEntry(tw, EnvelopesFilename, w.jsonl.Bytes(), w.manifest.CreatedAt); err != nil {
		return fmt.Errorf("write envelopes entry: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}
	return nil
}

func writeTarEntry(tw *tar.Writer, name string, body []byte, modTime time.Time) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(body)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

// Reader reads a tar.gz bundle, exposing the manifest and an iterator over
// the contained DSSE envelopes.
type Reader struct {
	manifest      Manifest
	jsonl         []byte
	manifestBytes []byte
}

// Read parses a tar.gz bundle from r. The full bundle (manifest + JSONL) is
// buffered in memory — bundles are sized for a single release, not a log
// firehose, so streaming is not worth the API complexity.
func Read(r io.Reader) (*Reader, error) { //nolint:gocognit // tar entry loop with per-entry caps stays clearer inline than split into helpers
	limited := &countingReader{r: io.LimitReader(r, MaxBundleBytes+1)}
	gz, err := gzip.NewReader(limited)
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)

	var (
		manifestBytes []byte
		jsonlBytes    []byte
	)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}

		if hdr.Size > MaxBundleBytes {
			return nil, fmt.Errorf("bundle entry %q exceeds max size %d", hdr.Name, MaxBundleBytes)
		}

		switch hdr.Name {
		case ManifestFilename:
			buf, err := io.ReadAll(io.LimitReader(tr, MaxBundleBytes+1))
			if err != nil {
				return nil, fmt.Errorf("read manifest: %w", err)
			}
			manifestBytes = buf
		case EnvelopesFilename:
			buf, err := io.ReadAll(io.LimitReader(tr, MaxBundleBytes+1))
			if err != nil {
				return nil, fmt.Errorf("read envelopes: %w", err)
			}
			jsonlBytes = buf
		default:
			// Unknown entries are tolerated for forward-compat but not loaded.
		}

		if limited.n > MaxBundleBytes {
			return nil, fmt.Errorf("bundle exceeds max decompressed size %d (likely zip-bomb)", MaxBundleBytes)
		}
	}

	if manifestBytes == nil {
		return nil, fmt.Errorf("bundle missing %s entry", ManifestFilename)
	}
	if jsonlBytes == nil {
		return nil, fmt.Errorf("bundle missing %s entry", EnvelopesFilename)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}

	return &Reader{
		manifest:      manifest,
		jsonl:         jsonlBytes,
		manifestBytes: manifestBytes,
	}, nil
}

func (r *Reader) Manifest() Manifest {
	out := r.manifest
	if len(r.manifest.Subjects) > 0 {
		out.Subjects = append([]string(nil), r.manifest.Subjects...)
	}
	if len(r.manifest.Envelopes) > 0 {
		out.Envelopes = append([]EnvelopeManifest(nil), r.manifest.Envelopes...)
	}
	return out
}

// Envelopes decodes each JSONL line into a dsse.Envelope. Lines whose sha256
// disagrees with the manifest's matching entry produce an error — that signals
// tampering of attestations.jsonl after the manifest was written.
//
// When the manifest has zero EnvelopeManifest entries (older or hand-built
// bundles), digest cross-checking is skipped and the JSONL is the sole source
// of truth. Envelope signatures inside still verify on their own.
func (r *Reader) Envelopes() ([]dsse.Envelope, error) {
	scanner := bufio.NewScanner(bytes.NewReader(r.jsonl))
	scanner.Buffer(make([]byte, 64*1024), MaxLineBytes)

	var (
		envelopes []dsse.Envelope
		idx       int
	)

	manifestByIdx := r.manifest.Envelopes
	checkDigests := len(manifestByIdx) == r.manifest.Count && r.manifest.Count > 0

	for scanner.Scan() {
		if idx >= MaxEnvelopes {
			return nil, fmt.Errorf("bundle envelope count exceeds limit %d", MaxEnvelopes)
		}
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		if checkDigests {
			sum := sha256.Sum256(line)
			digest := hex.EncodeToString(sum[:])
			if idx >= len(manifestByIdx) {
				return nil, fmt.Errorf("bundle has more envelopes than manifest records (line %d)", idx+1)
			}
			if manifestByIdx[idx].Sha256 != digest {
				return nil, fmt.Errorf("bundle envelope %d digest mismatch: manifest %s, line %s", idx, manifestByIdx[idx].Sha256, digest)
			}
		}

		var env dsse.Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, fmt.Errorf("decode envelope %d: %w", idx, err)
		}
		envelopes = append(envelopes, env)
		idx++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan envelopes: %w", err)
	}

	if checkDigests && idx != len(manifestByIdx) {
		return nil, fmt.Errorf("bundle has fewer envelopes (%d) than manifest records (%d)", idx, len(manifestByIdx))
	}

	return envelopes, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
