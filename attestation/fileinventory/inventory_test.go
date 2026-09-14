// jade:ring local

package fileinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/stretchr/testify/require"
)

func inventoryFixture(t *testing.T) (*Reference, []byte, string) {
	t.Helper()
	digest := sha256.Sum256([]byte("same content"))
	prehash := sha256.Sum256(digest[:])
	tree, err := merkle.NewTree([][]byte{prehash[:]})
	require.NoError(t, err)
	ref, body, err := Encode("product", "walk", []Entry{
		{Path: "z", FileDigest: hex.EncodeToString(digest[:]), MIMEType: "text/plain", Kind: "binary"},
		{Path: "a", FileDigest: hex.EncodeToString(digest[:])},
	})
	require.NoError(t, err)
	return ref, body, hex.EncodeToString(tree.Root())
}

func TestInventoryExactBytesAndDistinctContentRoot(t *testing.T) {
	ref, body, root := inventoryFixture(t)
	require.Equal(t, "https://aflock.ai/attestations/file-inventory/v0.1", Type)
	require.Equal(t, 64<<20, MaxBytes)
	require.Equal(t, 2, ref.FileCount)
	require.Equal(t, len(body), ref.Bytes)
	sum := sha256.Sum256(body)
	require.Equal(t, hex.EncodeToString(sum[:]), ref.Digest)
	entries, err := Verify(ref, body, "product", root, 1)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "z"}, []string{entries[0].Path, entries[1].Path})
	require.Equal(t, "text/plain", entries[1].MIMEType)
	require.Equal(t, "binary", entries[1].Kind)
	for _, mutated := range [][]byte{
		bytes.Replace(body, []byte(`"path":"z"`), []byte(`"path":"b"`), 1),
		bytes.Replace(body, []byte("text/plain"), []byte("text/other"), 1),
		bytes.Replace(body, []byte("binary"), []byte("source"), 1),
		append(append([]byte{}, body...), '\n'),
	} {
		_, err := Verify(ref, mutated, "product", root, 1)
		require.Error(t, err, "a content root does not bind metadata or alternate encodings")
	}
	_, err = Verify(ref, body, "material", root, 1)
	require.Error(t, err)
	_, err = Verify(ref, body, "product", strings.Repeat("0", 64), 1)
	require.Error(t, err)
	_, err = Verify(ref, body, "product", root, 2)
	require.Error(t, err)
}

func TestInventoryRejectsMalformedPayload(t *testing.T) {
	ref, body, root := inventoryFixture(t)
	for name, malformed := range map[string][]byte{
		"duplicate":       bytes.Replace(body, []byte(`"kind":"product"`), []byte(`"kind":"product","kind":"product"`), 1),
		"case alias":      bytes.Replace(body, []byte(`"kind":"product"`), []byte(`"Kind":"product"`), 1),
		"unknown":         bytes.Replace(body, []byte(`"entries":`), []byte(`"extra":1,"entries":`), 1),
		"version":         bytes.Replace(body, []byte("v0.1"), []byte("v9.9"), 1),
		"role":            bytes.Replace(body, []byte(`"kind":"product"`), []byte(`"kind":"material"`), 1),
		"entry alias":     bytes.Replace(body, []byte(`"path":"a"`), []byte(`"Path":"a"`), 1),
		"entry duplicate": bytes.Replace(body, []byte(`"path":"a"`), []byte(`"path":"a","path":"a"`), 1),
		"entry unknown":   bytes.Replace(body, []byte(`"path":"a"`), []byte(`"path":"a","leafHash":"bad"`), 1),
		"duplicate path":  bytes.Replace(body, []byte(`"path":"z"`), []byte(`"path":"a"`), 1),
		"empty path":      bytes.Replace(body, []byte(`"path":"a"`), []byte(`"path":""`), 1),
		"nul path":        bytes.Replace(body, []byte(`"path":"a"`), []byte(`"path":"\u0000"`), 1),
		"invalid utf8":    bytes.Replace(body, []byte(`"path":"a"`), []byte{'"', 'p', 'a', 't', 'h', '"', ':', '"', 0xff, '"'}, 1),
		"null metadata":   bytes.Replace(body, []byte(`"kind":"binary"`), []byte(`"kind":null`), 1),
		"trailing":        append(append([]byte{}, body...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			bound := *ref
			sum := sha256.Sum256(malformed)
			bound.Digest, bound.Bytes = hex.EncodeToString(sum[:]), len(malformed)
			_, err := Verify(&bound, malformed, "product", root, 1)
			require.Error(t, err)
		})
	}
}

func TestInventoryReferenceValidation(t *testing.T) {
	ref, body, root := inventoryFixture(t)
	for name, mutate := range map[string]func(*Reference){
		"schema":         func(r *Reference) { r.Schema += "x" },
		"kind":           func(r *Reference) { r.Kind = "material" },
		"state":          func(r *Reference) { r.State = "inline" },
		"empty count":    func(r *Reference) { r.FileCount = 0 },
		"negative count": func(r *Reference) { r.FileCount = -1 },
		"large count":    func(r *Reference) { r.FileCount = 1000001 },
		"digest":         func(r *Reference) { r.Digest = strings.ToUpper(r.Digest) },
		"empty digest":   func(r *Reference) { r.Digest = "" },
		"zero bytes":     func(r *Reference) { r.Bytes = 0 },
		"large bytes":    func(r *Reference) { r.Bytes = MaxBytes + 1 },
		"scope":          func(r *Reference) { r.CaptureScope = "trace-provider" },
		"mode":           func(r *Reference) { r.CaptureMode = "auto" },
	} {
		t.Run(name, func(t *testing.T) {
			r := *ref
			mutate(&r)
			require.Error(t, r.Validate("product"))
		})
	}
	r := *ref
	r.FileCount++
	_, err := Verify(&r, body, "product", root, 1)
	require.Error(t, err)
	raw, err := json.Marshal(ref)
	require.NoError(t, err)
	for _, malformed := range []string{
		strings.Replace(string(raw), `"schema":`, `"Schema":`, 1),
		strings.Replace(string(raw), `"bytes":`, `"extra":1,"bytes":`, 1),
		strings.Replace(string(raw), `"kind":"product"`, `"kind":"product","kind":"product"`, 1),
		strings.Replace(string(raw), `"bytes":`, `"Bytes":`, 1),
		"null",
	} {
		var parsed Reference
		require.Error(t, json.Unmarshal([]byte(malformed), &parsed))
	}
}

func TestInventoryOmittedEmptyAndOpaquePaths(t *testing.T) {
	for mode, scope := range map[string]string{"walk": "working-directory", "trace": "trace-provider", "unknown": "unspecified"} {
		ref := NewOmitted("material", mode, 3)
		require.NoError(t, ref.Validate("material"))
		require.Equal(t, scope, ref.CaptureScope)
		raw, err := json.Marshal(ref)
		require.NoError(t, err)
		require.NotContains(t, string(raw), `"digest"`)
		require.NotContains(t, string(raw), `"bytes"`)
		_, err = Verify(ref, nil, "material", "", 1)
		require.Error(t, err)
		ref.Digest = strings.Repeat("0", 64)
		require.Error(t, ref.Validate("material"))
	}
	_, _, err := Encode("product", "walk", nil)
	require.Error(t, err, "captured empty sets use existing empty parent encoding")
	for _, path := range []string{"", "a\x00b", string([]byte{0xff})} {
		_, _, err := Encode("material", "walk", []Entry{{Path: path, FileDigest: strings.Repeat("0", 64)}})
		require.Error(t, err)
	}
	entries := make([]Entry, 0, 6)
	for _, path := range []string{"../a", "/a", `a\b`, "a/b", "A", "a"} {
		entries = append(entries, Entry{Path: path, FileDigest: strings.Repeat("0", 64)})
	}
	ref, body, err := Encode("material", "trace", entries)
	require.NoError(t, err)
	require.Equal(t, len(entries), ref.FileCount)
	require.Contains(t, string(body), `a\\b`)
	_, _, err = Encode("material", "walk", append(entries, entries[0]))
	require.Error(t, err)
}
