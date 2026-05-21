// Copyright 2025 The Aflock Authors
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

// Package ociref parses OCI image references and resolves them to digests
// against a registry's /v2 API.
//
// It exists to keep the k8smanifest attestor from pulling in cosign/v2 and
// go-containerregistry for what amounts to a parser + a HEAD request. Only
// the small surface DigestForRef needs is implemented.
package ociref

import (
	"errors"
	"fmt"
	"strings"
)

// DefaultRegistry is the implicit registry for unqualified references like
// "nginx" or "library/nginx" — matching docker pull / go-containerregistry
// behavior.
const DefaultRegistry = "registry-1.docker.io"

// defaultRegistryAliases are the unqualified-name → DefaultRegistry hosts that
// users sometimes type explicitly. They behave the same as a bare reference.
var defaultRegistryAliases = map[string]bool{
	"docker.io":            true,
	"index.docker.io":      true,
	DefaultRegistry:        true,
}

// Reference is a parsed OCI image reference: registry host, repository path,
// and exactly one of Tag (if pulled by tag) or Digest (if pinned by digest).
type Reference struct {
	Host   string
	Repo   string
	Tag    string
	Digest string
}

// Identifier returns the registry-side identifier used to fetch a manifest —
// the digest if the reference is pinned, otherwise the tag.
func (r Reference) Identifier() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// Parse splits an image reference into its registry-host, repository, and
// tag/digest. It mirrors the subset of `name.ParseReference` that
// k8smanifest's DigestForRef actually depends on.
func Parse(input string) (Reference, error) {
	if input == "" {
		return Reference{}, errors.New("empty reference")
	}

	// Pull off the digest first if present — it dominates any tag.
	var dgst string
	if i := strings.Index(input, "@"); i >= 0 {
		if i == 0 {
			return Reference{}, errors.New("reference starts with '@'")
		}
		dgst = input[i+1:]
		input = input[:i]
		if err := validateDigest(dgst); err != nil {
			return Reference{}, err
		}
	}

	// Split host vs path. The first segment is the host iff it contains a
	// '.' or ':' OR is "localhost". Everything else inherits DefaultRegistry.
	host := DefaultRegistry
	path := input
	if first, rest, ok := strings.Cut(input, "/"); ok {
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			host = first
			path = rest
		}
	}
	if defaultRegistryAliases[host] {
		host = DefaultRegistry
	}

	// Pull off the tag from the LAST path segment. The colon-before-last-slash
	// is the registry port and was already consumed in the host split.
	tag := ""
	if last := strings.LastIndex(path, ":"); last >= 0 {
		// Reject `repo:` and `:tag` shapes.
		tag = path[last+1:]
		path = path[:last]
		if tag == "" {
			return Reference{}, errors.New("empty tag after ':'")
		}
		if path == "" {
			return Reference{}, errors.New("empty repository before ':'")
		}
	}

	// Docker-hub-style: single-segment repos default to library/<name>.
	if host == DefaultRegistry && !strings.Contains(path, "/") {
		path = "library/" + path
	}

	if path == "" {
		return Reference{}, errors.New("empty repository")
	}

	// Tag defaults to "latest" only when there's no digest. The convention
	// matches docker pull.
	if tag == "" && dgst == "" {
		tag = "latest"
	}

	return Reference{
		Host:   host,
		Repo:   path,
		Tag:    tag,
		Digest: dgst,
	}, nil
}

// validateDigest enforces the rough shape of an OCI content digest. We don't
// implement every registered algorithm — just check the structure so a typo
// fails fast instead of producing a malformed URL.
func validateDigest(d string) error {
	algo, hex, ok := strings.Cut(d, ":")
	if !ok || algo == "" || hex == "" {
		return fmt.Errorf("digest %q has no algorithm:hex separator", d)
	}
	switch algo {
	case "sha256":
		if len(hex) != 64 {
			return fmt.Errorf("sha256 digest must be 64 hex chars, got %d", len(hex))
		}
	case "sha512":
		if len(hex) != 128 {
			return fmt.Errorf("sha512 digest must be 128 hex chars, got %d", len(hex))
		}
	default:
		return fmt.Errorf("unsupported digest algorithm %q", algo)
	}
	for _, r := range hex {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return fmt.Errorf("digest contains non-hex character %q", r)
		}
	}
	return nil
}
