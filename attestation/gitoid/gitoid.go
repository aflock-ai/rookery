// Package gitoid is a minimal implementation of the git object ID (gitoid)
// algorithm: the SHA over the header "blob <len>\0" followed by the content,
// i.e. the content-addressable identifier git uses for blobs.
//
// It replaces the external github.com/edwarnicke/gitoid dependency (a
// single-maintainer module) with the small subset rookery actually uses:
// computing blob gitoids for attestation digest sets (cryptoutil) and
// rendering them as `gitoid:blob:<hash>:<hex>` URIs. Output is byte-identical
// to that library and to `git hash-object`; see gitoid_test.go for the
// equivalence vectors.
//
// Derived from github.com/edwarnicke/gitoid (Apache-2.0, (c) 2022 Cisco
// and/or its affiliates) — API and behavior preserved for the methods used.
package gitoid

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- gitoid sha1 mode is content-addressing, not security
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// GitObjectType is the type of git object. Only BLOB is used here.
type GitObjectType string

const BLOB GitObjectType = "blob"

// GitOID is a computed git object identifier.
type GitOID struct {
	gitObjectType GitObjectType
	hashName      string
	hashValue     []byte
}

type option struct {
	gitObjectType GitObjectType
	h             hash.Hash
	hashName      string
	contentLength int64
}

// Option configures GitOID computation.
type Option func(o *option)

// WithSha256 uses sha256 instead of the default sha1.
func WithSha256() Option {
	return func(o *option) {
		o.hashName = "sha256"
		o.h = sha256.New()
	}
}

// WithContentLength asserts the content length to read from the reader; only
// the first contentLength bytes are read. When unset, the whole reader is
// buffered to determine the length.
func WithContentLength(contentLength int64) Option {
	return func(o *option) {
		o.contentLength = contentLength
	}
}

// WithGitObjectType sets the object type (default BLOB).
func WithGitObjectType(t GitObjectType) Option {
	return func(o *option) {
		o.gitObjectType = t
	}
}

// Header returns the git object header: "<type> <len>\0".
func Header(gitObjectType GitObjectType, contentLength int64) []byte {
	return []byte(fmt.Sprintf("%s %d\000", gitObjectType, contentLength))
}

// New computes a GitOID over reader. Default type is BLOB, default hash sha1.
func New(reader io.Reader, opts ...Option) (*GitOID, error) {
	if reader == nil {
		return nil, fmt.Errorf("reader in gitoid.New may not be nil")
	}

	o := &option{
		gitObjectType: BLOB,
		h:             sha1.New(), // #nosec G401 -- see package note
		hashName:      "sha1",
		contentLength: 0,
	}
	for _, opt := range opts {
		opt(o)
	}

	// No declared content length: buffer the whole reader to measure it.
	if o.contentLength == 0 {
		buf := bytes.NewBuffer(nil)
		contentLength, err := io.Copy(buf, reader)
		if err != nil {
			return nil, fmt.Errorf("error copying reader to buffer in gitoid.New: %w", err)
		}
		reader = buf
		o.contentLength = contentLength
	}

	o.h.Write(Header(o.gitObjectType, o.contentLength))

	n, err := io.Copy(o.h, io.LimitReader(reader, o.contentLength))
	if err != nil {
		return nil, fmt.Errorf("error copying reader to hash in gitoid.New: %w", err)
	}
	if n < o.contentLength {
		return nil, fmt.Errorf("expected contentLength (%d) exceeds actual (%d) in gitoid.New: %w", o.contentLength, n, io.ErrUnexpectedEOF)
	}

	return &GitOID{
		gitObjectType: o.gitObjectType,
		hashName:      o.hashName,
		hashValue:     o.h.Sum(nil),
	}, nil
}

// String returns the gitoid hash in lowercase hex.
func (g *GitOID) String() string {
	return fmt.Sprintf("%x", g.hashValue)
}

// URI returns the gitoid URI: "gitoid:<type>:<hashName>:<hex>".
func (g *GitOID) URI() string {
	return fmt.Sprintf("gitoid:%s:%s:%s", g.gitObjectType, g.hashName, g)
}
