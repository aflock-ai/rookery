package gitoid

import (
	"bytes"
	"strings"
	"testing"
)

// Ground-truth vectors captured from github.com/edwarnicke/gitoid
// @v0.0.0-20220710194850-1be5bfda1f9d (the module this package replaces).
// The empty-blob sha1 value is also the canonical `git hash-object` empty
// blob, anchoring the algorithm to git itself. If any of these change, the
// inline implementation has diverged and persisted/signed gitoids would break.
var inputs = map[string][]byte{
	"empty":     {},
	"hello":     []byte("hello"),
	"newline":   []byte("blob test\nwith newline\n"),
	"binary":    {0, 1, 2, 3, 255, 254, 0, 0, 10},
	"dsse_like": []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJ4IjoxfQ=="}`),
	"large":     bytes.Repeat([]byte("A"), 100000),
}

var wantStr256 = map[string]string{
	"empty":     "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
	"hello":     "8aec4e4876f854f688d0ebfc8f37598f38e5fd6903cccc850ca36591175aeb60",
	"newline":   "18a74a81e5463f6fa56f81e60ce38c483872f56f457582d488e42e75ff09c474",
	"binary":    "3249b2fc0d52beaba1d0d1b203cfe76cb3c376478e61bdb9d0d0b6d72142a15a",
	"dsse_like": "8034bd09c3f1fb283e47cdf47745ef680c25d06d4a1ba7663e072a6c85c8468b",
	"large":     "855e95232cb49c8c2f3de1624c5c2a2f196988a1a56ca421ec237e391fa0c942",
}

var wantURI1 = map[string]string{
	"empty":     "gitoid:blob:sha1:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
	"hello":     "gitoid:blob:sha1:b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0",
	"newline":   "gitoid:blob:sha1:9af7235be21cd2b64cd8f44883f427cc5f2e138f",
	"binary":    "gitoid:blob:sha1:cb6ebd924f5138cb8112316006126365889d0a81",
	"dsse_like": "gitoid:blob:sha1:5c0bc1077e0961a4195b079df9ca3f3a1df029f5",
	"large":     "gitoid:blob:sha1:7ca7a468ab26a9e915d8a0127d83aa6155442d54",
}

// TestString256_ContentLengthPath covers the archivista server upload path:
// New(reader, WithContentLength(n), WithSha256()).String() — the value stored
// as the object key and returned to clients.
func TestString256_ContentLengthPath(t *testing.T) {
	for name, data := range inputs {
		g, err := New(bytes.NewReader(data), WithContentLength(int64(len(data))), WithSha256())
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		if got := g.String(); got != wantStr256[name] {
			t.Errorf("%s: String()=%s want %s", name, got, wantStr256[name])
		}
	}
}

// TestURI256_BufferedPath covers the rookery cryptoutil path:
// New(reader, WithSha256()).URI() with no declared content length (buffered).
func TestURI256_BufferedPath(t *testing.T) {
	for name, data := range inputs {
		g, err := New(bytes.NewReader(data), WithSha256())
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		want := "gitoid:blob:sha256:" + wantStr256[name]
		if got := g.URI(); got != want {
			t.Errorf("%s: URI()=%s want %s", name, got, want)
		}
	}
}

// TestURI1_Default covers the sha1 default path (used by rookery when the hash
// is not sha256). Anchored to git hash-object for the empty blob.
func TestURI1_Default(t *testing.T) {
	for name, data := range inputs {
		g, err := New(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		if got := g.URI(); got != wantURI1[name] {
			t.Errorf("%s: URI()=%s want %s", name, got, wantURI1[name])
		}
	}
}

// TestContentLengthVsBuffered: the two code paths (declared length vs buffered)
// must produce identical hashes for the same content.
func TestContentLengthVsBuffered(t *testing.T) {
	for name, data := range inputs {
		withLen, _ := New(bytes.NewReader(data), WithContentLength(int64(len(data))), WithSha256())
		buffered, _ := New(bytes.NewReader(data), WithSha256())
		if withLen.String() != buffered.String() {
			t.Errorf("%s: content-length path %s != buffered path %s", name, withLen.String(), buffered.String())
		}
	}
}

// TestHeader pins the exact git object header framing.
func TestHeader(t *testing.T) {
	if got := string(Header(BLOB, 5)); got != "blob 5\x00" {
		t.Errorf("Header(BLOB,5)=%q want %q", got, "blob 5\x00")
	}
}

// TestContentLengthTruncates: WithContentLength only hashes the first N bytes.
func TestContentLengthTruncates(t *testing.T) {
	full := []byte("hello world")
	short, _ := New(bytes.NewReader(full), WithContentLength(5), WithSha256())
	exact, _ := New(strings.NewReader("hello"), WithContentLength(5), WithSha256())
	if short.String() != exact.String() {
		t.Errorf("truncated read %s != %s", short.String(), exact.String())
	}
	if short.String() != wantStr256["hello"] {
		t.Errorf("truncated hello = %s want %s", short.String(), wantStr256["hello"])
	}
}

// TestContentLengthExceedsData errors when the declared length can't be read.
func TestContentLengthExceedsData(t *testing.T) {
	if _, err := New(bytes.NewReader([]byte("hi")), WithContentLength(100), WithSha256()); err == nil {
		t.Error("expected error when contentLength exceeds available data")
	}
}

func TestNilReader(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("expected error for nil reader")
	}
}
