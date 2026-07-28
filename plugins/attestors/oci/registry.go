// Copyright 2022 The Witness Contributors
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

package oci

import (
	"crypto"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
)

// RegistryDigest ties a registry manifest digest to the image reference the
// pushing command reported it for.
//
// This is deliberately NOT the same thing as Attestor.ManifestDigest. That
// field is a SHA256 the attestor computes locally over the raw manifest.json
// bytes inside a `docker save` tarball, and it does not equal any value the
// registry knows about. The registry manifest digest is what the registry
// itself assigned on push — the value Kubernetes surfaces as a container's
// `imageID`, the value a `repo@sha256:...` pinned reference names, and the
// value a human pastes when asking "what do you know about this image?".
type RegistryDigest struct {
	// Reference is the image reference the digest was reported for, in
	// pinned form where the source output gave us one (e.g.
	// "ghcr.io/acme/api:v1.2.3"). Never empty: a digest we cannot tie to a
	// reference is discarded rather than emitted as an orphan.
	Reference string `json:"reference"`

	// Digest is the registry-assigned manifest digest. The sha256 value is
	// taken verbatim from the observed output; it is not recomputed.
	Digest cryptoutil.DigestSet `json:"digest"`
}

// Observed push/copy output grammars. Every pattern below was derived from
// real command output captured against a live registry; see
// registry_test.go's testdata for the verbatim samples.
var (
	// `docker push` prints a repository banner once, then one line per tag.
	// The banner is the only place the repository appears, so it has to be
	// carried forward to attribute the bare tags that follow.
	//
	//   The push refers to repository [localhost:5959/regdigest-demo]
	pushRepoBannerRE = regexp.MustCompile(`^The push refers to repository \[([^\]]+)\]`)

	// Shared by `docker push` and `crane push`/`crane copy`. docker emits a
	// bare tag before the colon; crane emits a fully qualified reference and
	// prefixes the line with its own log timestamp.
	//
	//   v1.0: digest: sha256:b217... size: 523
	//   2026/07/28 10:01:13 localhost:5959/regdigest-copy:c1: digest: sha256:b217... size: 523
	//
	// This is the ONLY grammar accepted, deliberately. An earlier revision
	// also scraped bare pinned references (`repo/name@sha256:<hex>`) out of
	// any line, to pick up `crane push`'s stdout and BuildKit's "pushing
	// manifest for" report. That pattern was dropped: `<path>@sha256:<hex>`
	// is not unique to registry references — nix store paths, containerd
	// logs and content-addressed artifact tooling all print it — so it could
	// mint an IMAGE_DIGEST for something that is not an image. These subjects
	// are signed, and a wrong digest is undetectable downstream because it
	// looks exactly like a correct one, whereas a missing one merely costs a
	// query. The recall given up is close to nil: `crane push` reports the
	// same push on stderr in this grammar anyway (see
	// TestParseRegistryDigests_RealCranePushCoveredByStderr).
	pushDigestLineRE = regexp.MustCompile(`(?:^|\s)(\S+): digest: sha256:([0-9a-f]{64}) size: \d+\s*$`)
)

// collectRegistryDigests pulls the registry manifest digests out of the
// command output cilock already captured for this run.
//
// Nothing here reaches the network. The digests are read out of bytes the
// commandrun attestor observed and attested, so the oci attestor's
// determinism guarantee is preserved: identical observed output yields an
// identical, identically ordered result.
//
// Parsing is bound to the originating command, not just the line shape: only
// output from a successful (exit 0, no attestor error) direct invocation of a
// known push command is considered. Any wrapped command can PRINT a line that
// matches the push grammar — a Makefile echo, a test suite replaying fixtures
// — and these values become signed registrydigest: subjects, so shape alone
// must never be sufficient to mint one.
func collectRegistryDigests(ctx *attestation.AttestationContext) []RegistryDigest {
	var found []RegistryDigest
	for _, completed := range ctx.CompletedAttestors() {
		if completed.Attestor.Name() != commandrun.Name {
			continue
		}
		// A command that failed proves nothing about registry state: the
		// push may have been rejected after printing progress output.
		if completed.Error != nil {
			continue
		}
		cmdAttestor, ok := completed.Attestor.(commandrun.CommandRunAttestor)
		if !ok {
			continue
		}
		data := cmdAttestor.Data()
		if data == nil {
			continue
		}
		if data.ExitCode != 0 || !isRegistryPushCommand(data.Cmd) {
			continue
		}
		// Both streams matter: `docker push` reports the digest on stdout,
		// `crane copy` reports it on stderr.
		found = append(found, parseRegistryDigests(data.Stdout, data.Stderr)...)
	}
	return dedupeRegistryDigests(found)
}

// isRegistryPushCommand reports whether argv is a direct invocation of a
// command whose output grammar this parser understands and trusts:
// `docker push` (including the `docker image push` long form) and
// `crane push`/`crane copy`/`crane cp` — exactly the commands the grammars in
// this file were derived from.
//
// Matching is deliberately strict: the subcommand must be argv[1] (argv[2]
// for the `image push` form), with no intervening global flags, and shell
// wrappers (`sh -c "docker push ..."`) do not match because argv names the
// shell, not the push. A missed match costs one queryable digest; a false
// match mints signed evidence from untrusted output. Precision wins.
func isRegistryPushCommand(cmd []string) bool {
	const push = "push"
	if len(cmd) < 2 {
		return false
	}
	tool := strings.TrimSuffix(filepath.Base(cmd[0]), ".exe")
	switch tool {
	case "docker":
		if cmd[1] == push {
			return true
		}
		return len(cmd) >= 3 && cmd[1] == "image" && cmd[2] == push
	case "crane":
		switch cmd[1] {
		case push, "copy", "cp":
			return true
		}
	}
	return false
}

// parseRegistryDigests scans observed output streams for registry manifest
// digests. Streams are scanned in the order given and lines in the order
// written, so the result order is a function of the observed bytes alone.
//
// Output that contains no push report yields nil, not an error: most runs
// never push anything, and a missing digest is a normal outcome rather than
// a failure.
func parseRegistryDigests(streams ...string) []RegistryDigest {
	var found []RegistryDigest
	for _, stream := range streams {
		if stream == "" {
			continue
		}
		// The banner scope is per-stream: a repository announced on stdout
		// must not be used to attribute a tag seen on stderr.
		currentRepo := ""
		for _, line := range strings.Split(stream, "\n") {
			line = strings.TrimRight(line, "\r")

			if m := pushRepoBannerRE.FindStringSubmatch(line); m != nil {
				currentRepo = strings.TrimSpace(m[1])
				continue
			}

			if m := pushDigestLineRE.FindStringSubmatch(line); m != nil {
				if ref := resolveReference(m[1], currentRepo); ref != "" {
					found = append(found, newRegistryDigest(ref, m[2]))
				}
			}
		}
	}
	return found
}

// resolveReference turns the token that preceded ": digest:" into a full
// image reference.
//
// crane prints a fully qualified reference there, which is used as-is.
// docker prints only the tag, which is meaningless without the repository
// from the banner — if no banner was seen (truncated or interleaved output)
// the digest is dropped. An unattributable digest is worse than no digest:
// it would be signed evidence naming an image we cannot identify.
func resolveReference(token, currentRepo string) string {
	if strings.Contains(token, "/") {
		return token
	}
	if currentRepo == "" {
		return ""
	}
	// A tag may not contain "/" or ":", so a token reaching here is a tag.
	return currentRepo + ":" + token
}

func newRegistryDigest(reference, sha256Hex string) RegistryDigest {
	return RegistryDigest{
		Reference: reference,
		Digest: cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA256}: sha256Hex,
		},
	}
}

// dedupeRegistryDigests collapses repeats while preserving first-seen order.
// `crane push` legitimately reports the same reference and digest twice (a
// pinned reference on stdout and a digest line on stderr); that is one push,
// not two.
func dedupeRegistryDigests(in []RegistryDigest) []RegistryDigest {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]RegistryDigest, 0, len(in))
	for _, rd := range in {
		key := rd.Reference + "@" + rd.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rd)
	}
	return out
}
