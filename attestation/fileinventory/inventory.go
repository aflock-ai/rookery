// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package fileinventory binds complete path inventories to v0.3 content trees.
package fileinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aflock-ai/rookery/attestation/merkle"
)

const (
	Type              = "https://aflock.ai/attestations/file-inventory/v0.1"
	MaxBytes          = 64 << 20
	MaxEntries        = 1000000
	StateOmitted      = "omitted"
	StateDetached     = "detached"
	fieldBytes        = "bytes"
	fieldKind         = "kind"
	fieldCaptureMode  = "captureMode"
	fieldCaptureScope = "captureScope"
	fieldState        = "state"
	fieldDigest       = "digest"
)

type Reference struct {
	Schema       string `json:"schema" jsonschema:"enum=https://aflock.ai/attestations/file-inventory/v0.1"`
	Kind         string `json:"kind" jsonschema:"enum=material,enum=product"`
	State        string `json:"state" jsonschema:"enum=detached,enum=omitted"`
	FileCount    int    `json:"fileCount" jsonschema:"minimum=1,maximum=1000000"`
	CaptureMode  string `json:"captureMode" jsonschema:"enum=walk,enum=trace,enum=unknown"`
	CaptureScope string `json:"captureScope" jsonschema:"enum=working-directory,enum=trace-provider,enum=unspecified"`
	Digest       string `json:"digest,omitempty" jsonschema:"pattern=^[0-9a-f]{64}$"`
	Bytes        int    `json:"bytes,omitempty" jsonschema:"minimum=1,maximum=67108864"`
}

type Entry struct {
	Path       string `json:"path" jsonschema:"minLength=1"`
	FileDigest string `json:"fileDigest" jsonschema:"pattern=^[0-9a-f]{64}$"`
	MIMEType   string `json:"mimeType,omitempty"`
	Kind       string `json:"kind,omitempty"`
}

type Payload struct {
	Schema  string  `json:"schema" jsonschema:"enum=https://aflock.ai/attestations/file-inventory/v0.1"`
	Kind    string  `json:"kind" jsonschema:"enum=material,enum=product"`
	Entries []Entry `json:"entries" jsonschema:"minItems=1,maxItems=1000000"`
}

func captureScope(mode string) string {
	switch mode {
	case "walk":
		return "working-directory"
	case "trace":
		return "trace-provider"
	case "unknown":
		return "unspecified"
	default:
		return ""
	}
}

func validDigest(d string) bool {
	if len(d) != 64 {
		return false
	}
	for _, c := range d {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validKind(kind string) bool {
	return kind == "material" || kind == "product"
}

func (r *Reference) Validate(kind string) error {
	if r == nil || r.Schema != Type || !validKind(kind) || r.Kind != kind {
		return fmt.Errorf("file inventory: invalid schema or kind")
	}
	if r.FileCount < 1 || r.FileCount > MaxEntries {
		return fmt.Errorf("file inventory: fileCount must be between 1 and %d", MaxEntries)
	}
	if scope := captureScope(r.CaptureMode); scope == "" || scope != r.CaptureScope {
		return fmt.Errorf("file inventory: invalid capture mode or scope")
	}
	return r.validateState()
}

func (r *Reference) validateState() error {
	switch r.State {
	case StateOmitted:
		if r.Digest != "" || r.Bytes != 0 {
			return fmt.Errorf("file inventory: omitted details cannot carry digest or bytes")
		}
	case StateDetached:
		if !validDigest(r.Digest) || r.Bytes < 1 || r.Bytes > MaxBytes {
			return fmt.Errorf("file inventory: invalid digest or byte count")
		}
	default:
		return fmt.Errorf("file inventory: invalid state %q", r.State)
	}
	return nil
}

// object checks exact keys and duplicates before decoding into Go structs, whose
// default decoder accepts case aliases, duplicate keys and null scalar fields.
func object(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	if !validUnicodeJSON(data) {
		return nil, fmt.Errorf("file inventory: invalid Unicode")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("file inventory: expected object")
	}
	allowed := slices.Concat(required, optional)
	fields := make(map[string]json.RawMessage, len(allowed))
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok || !slices.Contains(allowed, key) {
			return nil, fmt.Errorf("file inventory: unknown field %q", key)
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("file inventory: duplicate field %q", key)
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		if bytes.Equal(raw, []byte("null")) {
			return nil, fmt.Errorf("file inventory: null field %q", key)
		}
		fields[key] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("file inventory: trailing data")
	}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return nil, fmt.Errorf("file inventory: missing field %q", k)
		}
	}
	return fields, nil
}

// encoding/json replaces invalid UTF-8 and unpaired UTF-16 escapes with U+FFFD.
// Refuse that lossy projection rather than authenticate a different path string.
func validUnicodeJSON(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i == len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		v, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v < 0xd800 || v > 0xdbff {
			continue
		}
		if !lowSurrogateEscape(data[i+1:]) {
			return false
		}
		i += 6
	}
	return true
}

func lowSurrogateEscape(data []byte) bool {
	if len(data) < 6 || data[0] != '\\' || data[1] != 'u' {
		return false
	}
	low, err := strconv.ParseUint(string(data[2:6]), 16, 16)
	return err == nil && low >= 0xdc00 && low <= 0xdfff
}

func (r *Reference) UnmarshalJSON(data []byte) error {
	fields, err := object(data, []string{"schema", fieldKind, fieldState, "fileCount", fieldCaptureMode, fieldCaptureScope}, []string{fieldDigest, fieldBytes})
	if err != nil {
		return err
	}
	type plain Reference
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	ref := Reference(decoded)
	if err := ref.Validate(ref.Kind); err != nil {
		return err
	}
	if ref.State == StateOmitted && (fields[fieldDigest] != nil || fields[fieldBytes] != nil) {
		return fmt.Errorf("file inventory: omitted details cannot carry digest or bytes")
	}
	*r = ref
	return nil
}

func (e *Entry) UnmarshalJSON(data []byte) error {
	if _, err := object(data, []string{"path", "fileDigest"}, []string{"mimeType", fieldKind}); err != nil {
		return err
	}
	type plain Entry
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*e = Entry(decoded)
	return nil
}

func validateEntries(entries []Entry) error {
	if len(entries) < 1 || len(entries) > MaxEntries {
		return fmt.Errorf("file inventory: entry count must be between 1 and %d", MaxEntries)
	}
	for i, e := range entries {
		if e.Path == "" || strings.ContainsRune(e.Path, 0) || !utf8.ValidString(e.Path) || !validDigest(e.FileDigest) || !utf8.ValidString(e.MIMEType) || !utf8.ValidString(e.Kind) {
			return fmt.Errorf("file inventory: invalid entry at index %d", i)
		}
		if i > 0 && entries[i-1].Path >= e.Path {
			return fmt.Errorf("file inventory: paths must be unique and sorted")
		}
	}
	return nil
}

func NewOmitted(kind, mode string, count int) *Reference {
	return &Reference{Schema: Type, Kind: kind, State: StateOmitted, FileCount: count, CaptureMode: mode, CaptureScope: captureScope(mode)}
}

func Encode(kind, mode string, entries []Entry) (*Reference, []byte, error) {
	if len(entries) > MaxEntries {
		return nil, nil, fmt.Errorf("file inventory: too many entries")
	}
	entries = append([]Entry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if err := validateEntries(entries); err != nil {
		return nil, nil, err
	}
	body, err := json.Marshal(Payload{Schema: Type, Kind: kind, Entries: entries})
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(body)
	ref := NewOmitted(kind, mode, len(entries))
	ref.State, ref.Digest, ref.Bytes = StateDetached, hex.EncodeToString(sum[:]), len(body)
	if err := ref.Validate(kind); err != nil {
		return nil, nil, err
	}
	return ref, body, nil
}

// Decode validates a standalone payload's shape, not its binding to a parent.
// Call Verify before using entries in a decision about materials or products.
func Decode(body []byte, kind string) ([]Entry, error) {
	if len(body) > MaxBytes {
		return nil, fmt.Errorf("file inventory: payload exceeds %d bytes", MaxBytes)
	}
	fields, err := object(body, []string{"schema", fieldKind, "entries"}, nil)
	if err != nil {
		return nil, err
	}
	var schema, role string
	if err := json.Unmarshal(fields["schema"], &schema); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(fields[fieldKind], &role); err != nil {
		return nil, err
	}
	if schema != Type || role != kind || !validKind(kind) {
		return nil, fmt.Errorf("file inventory: invalid schema or kind")
	}
	d := json.NewDecoder(bytes.NewReader(fields["entries"]))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('[') {
		return nil, fmt.Errorf("file inventory: expected entries array")
	}
	entries := []Entry{}
	for d.More() {
		if len(entries) == MaxEntries {
			return nil, fmt.Errorf("file inventory: too many entries")
		}
		var e Entry
		if err := d.Decode(&e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if err := validateEntries(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func Verify(ref *Reference, body []byte, kind, root string, treeSize uint64) ([]Entry, error) {
	if err := ref.Validate(kind); err != nil {
		return nil, err
	}
	if ref.State != StateDetached {
		return nil, fmt.Errorf("file inventory: details were omitted")
	}
	if len(body) != ref.Bytes {
		return nil, fmt.Errorf("file inventory: payload byte count mismatch")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != ref.Digest {
		return nil, fmt.Errorf("file inventory: payload digest mismatch")
	}
	entries, err := Decode(body, kind)
	if err != nil {
		return nil, err
	}
	if len(entries) != ref.FileCount {
		return nil, fmt.Errorf("file inventory: fileCount mismatch")
	}
	distinct := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		distinct[e.FileDigest] = struct{}{}
	}
	digests := make([]string, 0, len(distinct))
	for d := range distinct {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	leaves := make([][]byte, 0, len(digests))
	for _, d := range digests {
		raw, _ := hex.DecodeString(d) // validated by Decode
		prehash := sha256.Sum256(raw)
		leaves = append(leaves, prehash[:])
	}
	tree, err := merkle.NewTree(leaves)
	if err != nil {
		return nil, err
	}
	if tree.Size() != treeSize || hex.EncodeToString(tree.Root()) != root {
		return nil, fmt.Errorf("file inventory: signed root or treeSize mismatch")
	}
	return entries, nil
}

// DecodeParent preserves legacy decoding but makes the new representation closed
// and unambiguous. dst must be the material or product predicate, not its attestor.
func DecodeParent(data []byte, kind string, dst any) error {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	modern := false
	for key := range keys {
		modern = modern || strings.EqualFold(key, "inventory")
	}
	if !modern {
		return json.Unmarshal(data, dst)
	}
	fields, err := object(data, []string{"merkleRoot", "treeSize", "hashAlgorithm", "construction", "inventory"}, nil)
	if err != nil {
		return err
	}
	var p struct {
		MerkleRoot    string `json:"merkleRoot"`
		TreeSize      uint64 `json:"treeSize"`
		HashAlgorithm string `json:"hashAlgorithm"`
		Construction  string `json:"construction"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	var ref Reference
	if err := json.Unmarshal(fields["inventory"], &ref); err != nil {
		return err
	}
	if err := ref.Validate(kind); err != nil {
		return err
	}
	if p.TreeSize > MaxEntries {
		return fmt.Errorf("file inventory: invalid parent commitment")
	}
	if !validDigest(p.MerkleRoot) || p.TreeSize == 0 || int(p.TreeSize) > ref.FileCount || p.HashAlgorithm != "sha256" || p.Construction != "RFC6962" {
		return fmt.Errorf("file inventory: invalid parent commitment")
	}
	return json.Unmarshal(data, dst)
}
