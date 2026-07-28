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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every fixture below is verbatim output captured from the real binary run
// against a live `registry:2` on localhost:5959. Nothing here is invented.

// docker push localhost:5959/regdigest-demo:v1.0   (stdout; stderr was empty)
const realDockerPushSingle = `The push refers to repository [localhost:5959/regdigest-demo]
9e70d3b0ab62: Preparing
9e70d3b0ab62: Pushed
v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523
`

// docker push --all-tags localhost:5959/regdigest-demo   (one command, two tags)
const realDockerPushAllTags = `The push refers to repository [localhost:5959/regdigest-demo]
9e70d3b0ab62: Preparing
9e70d3b0ab62: Layer already exists
latest: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523
9e70d3b0ab62: Preparing
9e70d3b0ab62: Layer already exists
v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523
`

// docker push localhost:5959/regdigest-other:beta   (a second, different image)
const realDockerPushOther = `The push refers to repository [localhost:5959/regdigest-other]
fac15ea3eb07: Preparing
fac15ea3eb07: Pushed
beta: digest: sha256:38baa6c88e83ba13d7af6ec704b4c4620889b26da01fa450a4661c2ccc9e1e25 size: 523
`

// crane copy ... (stdout was empty; crane logs to stderr)
const realCraneCopyStderr = `2026/07/28 10:01:13 Copying from localhost:5959/regdigest-demo:v1.0 to localhost:5959/regdigest-copy:c1
2026/07/28 10:01:13 mounted blob: sha256:dd02331ea4fc195e46c826f5473bd9b4c7766facb8a909a5005b4a59167399fb
2026/07/28 10:01:13 mounted blob: sha256:7d05fdec43afd21fc7d0d489fa7dbda9d3d5edc4e5ecdb07ed4d94517d777314
2026/07/28 10:01:13 localhost:5959/regdigest-copy:c1: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523
`

// crane push demo.tar localhost:5959/regdigest-cranepush:p1
const realCranePushStdout = `localhost:5959/regdigest-cranepush@sha256:fb1c42dc10cbcfe259b4a3ce1bce89947f5719c0af2c8fd54d3baef1c1618db0
`

const realCranePushStderr = `2026/07/28 10:01:35 pushed blob: sha256:7938d59e5c08c3c8caf6d598c3cc5bf3d96ec199379a5fef3906ad3bd1a2d4a0
2026/07/28 10:01:35 pushed blob: sha256:7d05fdec43afd21fc7d0d489fa7dbda9d3d5edc4e5ecdb07ed4d94517d777314
2026/07/28 10:01:35 localhost:5959/regdigest-cranepush:p1: digest: sha256:fb1c42dc10cbcfe259b4a3ce1bce89947f5719c0af2c8fd54d3baef1c1618db0 size: 423
`

// skopeo copy ... (stdout; stderr was empty). skopeo does NOT report the
// digest on either stream — it needs --digestfile. This fixture exists to
// pin that we emit nothing rather than guessing from "Copying config".
const realSkopeoCopyStdout = `Getting image source signatures
Copying blob sha256:dd02331ea4fc195e46c826f5473bd9b4c7766facb8a909a5005b4a59167399fb
Copying config sha256:7d05fdec43afd21fc7d0d489fa7dbda9d3d5edc4e5ecdb07ed4d94517d777314
Writing manifest to image destination
`

func digestOf(t *testing.T, rd RegistryDigest) string {
	t.Helper()
	return rd.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
}

// pairs flattens results to "reference=digest" for readable assertions.
func pairs(t *testing.T, in []RegistryDigest) []string {
	t.Helper()
	out := make([]string, 0, len(in))
	for _, rd := range in {
		out = append(out, rd.Reference+"="+digestOf(t, rd))
	}
	return out
}

func TestParseRegistryDigests_RealDockerPush(t *testing.T) {
	got := parseRegistryDigests(realDockerPushSingle, "")
	require.Len(t, got, 1)
	assert.Equal(t, "localhost:5959/regdigest-demo:v1.0", got[0].Reference)
	assert.Equal(t,
		"b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
		digestOf(t, got[0]),
		"digest must be the registry-assigned value verbatim")
}

// The bare tag on the digest line is only meaningful next to the banner
// several lines above it. This is the correlation the parser exists to do.
func TestParseRegistryDigests_RealDockerPushAllTags(t *testing.T) {
	got := parseRegistryDigests(realDockerPushAllTags, "")
	assert.Equal(t, []string{
		"localhost:5959/regdigest-demo:latest=b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
		"localhost:5959/regdigest-demo:v1.0=b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
	}, pairs(t, got), "two tags of one image must stay two distinct references")
}

// Two images pushed in one run: two digests, each attributed to its own
// repository. A banner must rebind the repository, not leak across pushes.
func TestParseRegistryDigests_MultiPushTwoImages(t *testing.T) {
	got := parseRegistryDigests(realDockerPushSingle+realDockerPushOther, "")
	require.Len(t, got, 2, "expected one digest per pushed image")
	assert.Equal(t, []string{
		"localhost:5959/regdigest-demo:v1.0=b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
		"localhost:5959/regdigest-other:beta=38baa6c88e83ba13d7af6ec704b4c4620889b26da01fa450a4661c2ccc9e1e25",
	}, pairs(t, got))
}

// crane reports on stderr and prefixes its own timestamp; the reference is
// already fully qualified so no banner is involved.
func TestParseRegistryDigests_RealCraneCopy(t *testing.T) {
	got := parseRegistryDigests("", realCraneCopyStderr)
	require.Len(t, got, 1)
	assert.Equal(t, "localhost:5959/regdigest-copy:c1", got[0].Reference)
	assert.Equal(t, "b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967", digestOf(t, got[0]))
}

// The "mounted blob: sha256:..." lines in that same output are layer blobs,
// not manifest digests. Emitting them would be actively wrong.
func TestParseRegistryDigests_IgnoresBlobLines(t *testing.T) {
	got := parseRegistryDigests("", realCraneCopyStderr)
	for _, rd := range got {
		assert.NotEqual(t, "dd02331ea4fc195e46c826f5473bd9b4c7766facb8a909a5005b4a59167399fb", digestOf(t, rd),
			"a mounted layer blob digest must never be reported as a registry manifest digest")
		assert.NotEqual(t, "7d05fdec43afd21fc7d0d489fa7dbda9d3d5edc4e5ecdb07ed4d94517d777314", digestOf(t, rd),
			"the config blob digest must never be reported as a registry manifest digest")
	}
}

// crane push reports the push on BOTH streams: a bare pinned reference on
// stdout and the digest-line grammar on stderr. Only the stderr form is
// parsed — see pushDigestLineRE's comment for why the bare pinned-reference
// pattern was dropped. This test is the evidence that dropping it costs no
// coverage: the push is still captured, with the more specific tagged
// reference.
func TestParseRegistryDigests_RealCranePushCoveredByStderr(t *testing.T) {
	got := dedupeRegistryDigests(parseRegistryDigests(realCranePushStdout, realCranePushStderr))
	assert.Equal(t, []string{
		"localhost:5959/regdigest-cranepush:p1=fb1c42dc10cbcfe259b4a3ce1bce89947f5719c0af2c8fd54d3baef1c1618db0",
	}, pairs(t, got), "crane push must still be captured, via its stderr digest line")

	// The stdout line alone must produce nothing: a bare pinned reference is
	// not accepted as evidence of a push.
	assert.Empty(t, parseRegistryDigests(realCranePushStdout, ""),
		"a bare pinned reference is not a push report")
}

func TestDedupeRegistryDigests_CollapsesExactRepeats(t *testing.T) {
	got := dedupeRegistryDigests(parseRegistryDigests(realDockerPushSingle, realDockerPushSingle))
	assert.Len(t, got, 1, "the same reference+digest seen on both streams is one push")
}

// ---------- negative cases: silence must be silent ----------

func TestParseRegistryDigests_NoPushObserved(t *testing.T) {
	for name, out := range map[string]string{
		"empty":            "",
		"go build":         "go: downloading github.com/foo/bar v1.2.3\nok\tgithub.com/x/y\t0.12s\n",
		"docker build":     "Step 1/2 : FROM scratch\n ---> Using cache\nSuccessfully built 7d05fdec43af\n",
		"skopeo copy real": realSkopeoCopyStdout,
	} {
		t.Run(name, func(t *testing.T) {
			got := parseRegistryDigests(out, "")
			assert.Empty(t, got, "no push report means no subject, and no error")
		})
	}
}

// A digest line with no banner cannot be attributed to a repository. We drop
// it. Signing "tag v1.0 has digest X" without knowing which image that is
// would be evidence nobody can act on.
func TestParseRegistryDigests_OrphanTagLineIsDropped(t *testing.T) {
	orphan := "v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523\n"
	assert.Empty(t, parseRegistryDigests(orphan, ""),
		"a bare tag with no repository banner must not produce an orphan subject")
}

// A repository announced on stdout must not attribute a tag seen on stderr;
// the two streams are separate observations and interleaving is not ordered.
func TestParseRegistryDigests_BannerDoesNotLeakAcrossStreams(t *testing.T) {
	banner := "The push refers to repository [localhost:5959/regdigest-demo]\n"
	tagLine := "v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523\n"
	assert.Empty(t, parseRegistryDigests(banner, tagLine),
		"banner scope is per-stream")
}

func TestParseRegistryDigests_MalformedProducesNothing(t *testing.T) {
	repo := "The push refers to repository [localhost:5959/regdigest-demo]\n"
	for name, line := range map[string]string{
		"digest truncated to 63 hex": "v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd4996 size: 523\n",
		"digest has non-hex char":    "v1.0: digest: sha256:z21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523\n",
		"uppercase hex":              "v1.0: digest: sha256:B21786D94B8E977E2254DF67758EEE19B1CF94E536FC81B53574F5910FD49967 size: 523\n",
		"unsupported algorithm":      "v1.0: digest: sha512:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523\n",
		"line truncated mid-digest":  "v1.0: digest: sha256:b21786d94b8e97\n",
		"size field missing":         "v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967\n",
		"size not numeric":           "v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: big\n",
		"prose mentioning a digest":  "warning: expected digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 but the push failed\n",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, parseRegistryDigests(repo+line, ""),
				"malformed output must yield no subject rather than a wrong one")
		})
	}
}

// REGRESSION GUARD — do not relax this.
//
// A "<path>@sha256:<hex>" string is NOT unique to registry references. Nix
// store paths, containerd logs, OCI-layout tooling and content-addressed
// artifact managers all print that shape for things that are not images.
// Scraping it would mint an IMAGE_DIGEST for a non-image.
//
// These subjects are SIGNED. A wrong digest is undetectable downstream
// because it looks exactly like a correct one; a missing digest merely costs
// a query. This is a deliberate precision-over-recall choice, and every line
// below must keep producing nothing.
func TestParseRegistryDigests_RejectsNonPushPinnedReferences(t *testing.T) {
	const hex = "fb1c42dc10cbcfe259b4a3ce1bce89947f5719c0af2c8fd54d3baef1c1618db0"
	for name, line := range map[string]string{
		"nix store path":        "/nix/store/abc123-foo@sha256:" + hex + "\n",
		"nix build output":      "building '/nix/store/qwe-pkg/lib@sha256:" + hex + "'\n",
		"containerd log":        "time=\"2026-07-28T10:01:13Z\" level=info msg=\"unpacking docker.io/library/x@sha256:" + hex + "\"\n",
		"go module-ish":         "resolved github.com/foo/bar@sha256:" + hex + "\n",
		"slash-less token":      "resolved dependency foo@sha256:" + hex + "\n",
		"oci layout blob path":  "reading blobs/sha256/layer@sha256:" + hex + "\n",
		"artifact manager line": "cached artifact my-org/my-artifact@sha256:" + hex + "\n",
		"crane push stdout":     "localhost:5959/regdigest-cranepush@sha256:" + hex + "\n",
		"buildkit manifest log": "#6 pushing manifest for localhost:5959/regdigest-buildx:bx1@sha256:" + hex + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, parseRegistryDigests(line, ""),
				"a bare pinned reference must never become a signed subject")
			assert.Empty(t, parseRegistryDigests("", line),
				"...on either stream")
		})
	}
}

// Determinism is the oci attestor's contract. The output is a pure function
// of the observed bytes, so repeated parses must be byte-identical.
func TestParseRegistryDigests_Deterministic(t *testing.T) {
	in := realDockerPushAllTags + realDockerPushOther
	first := dedupeRegistryDigests(parseRegistryDigests(in, realCraneCopyStderr))
	for i := 0; i < 32; i++ {
		got := dedupeRegistryDigests(parseRegistryDigests(in, realCraneCopyStderr))
		require.True(t, reflect.DeepEqual(first, got), "parse must be deterministic across runs")
	}
	assert.Equal(t, []string{
		"localhost:5959/regdigest-demo:latest=b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
		"localhost:5959/regdigest-demo:v1.0=b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
		"localhost:5959/regdigest-other:beta=38baa6c88e83ba13d7af6ec704b4c4620889b26da01fa450a4661c2ccc9e1e25",
		"localhost:5959/regdigest-copy:c1=b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
	}, pairs(t, first))
}

func TestParseRegistryDigests_HandlesCRLF(t *testing.T) {
	crlf := "The push refers to repository [localhost:5959/regdigest-demo]\r\n" +
		"v1.0: digest: sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967 size: 523\r\n"
	got := parseRegistryDigests(crlf, "")
	require.Len(t, got, 1)
	assert.Equal(t, "localhost:5959/regdigest-demo:v1.0", got[0].Reference)
}

// Subjects must carry the registry digest under its own prefix and must not
// disturb or impersonate manifestdigest:.
func TestSubjects_RegistryDigestPrefix(t *testing.T) {
	a := New()
	a.RegistryDigests = []RegistryDigest{
		newRegistryDigest("localhost:5959/regdigest-demo:v1.0", "b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967"),
	}

	subjects := a.Subjects()

	key := "registrydigest:localhost:5959/regdigest-demo:v1.0@sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967"
	require.Contains(t, subjects, key)
	assert.Equal(t,
		"b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967",
		subjects[key][cryptoutil.DigestValue{Hash: crypto.SHA256}])

	for k := range subjects {
		assert.NotContains(t, k, "manifestdigest:",
			"registry digests must never be emitted under the local manifestdigest: prefix")
	}
}

// A push-only run has no tarball, so every tar-derived digest is empty. Those
// must not become empty subjects.
func TestSubjects_SkipsEmptyTarDerivedDigests(t *testing.T) {
	a := New()
	a.RegistryDigests = []RegistryDigest{
		newRegistryDigest("localhost:5959/regdigest-demo:v1.0", "b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967"),
	}

	for k := range a.Subjects() {
		assert.False(t, k == "manifestdigest:" || k == "tardigest:" || k == "imageid:",
			"unpopulated digest must not emit a valueless subject, got %q", k)
	}
}

// ---------------------------------------------------------------------------
// Command binding: push-shaped output is only trusted when it came from a
// successful invocation of a known push command. Any wrapped command can
// PRINT a line matching the push grammar; only `docker push`/`crane push`/
// `crane copy` output may mint a signed registrydigest: subject.
// ---------------------------------------------------------------------------

// fakeCommandRunAttestor synthesizes a completed commandrun attestor without
// executing anything, so tests control argv, exit code and both streams.
type fakeCommandRunAttestor struct {
	data      *commandrun.CommandRun
	attestErr error
}

func (f *fakeCommandRunAttestor) Name() string                 { return commandrun.Name }
func (f *fakeCommandRunAttestor) Type() string                 { return commandrun.Type }
func (f *fakeCommandRunAttestor) RunType() attestation.RunType { return commandrun.RunType }
func (f *fakeCommandRunAttestor) Schema() *jsonschema.Schema   { return nil }
func (f *fakeCommandRunAttestor) Attest(_ *attestation.AttestationContext) error {
	return f.attestErr
}
func (f *fakeCommandRunAttestor) Data() *commandrun.CommandRun { return f.data }

// runTestAttestors builds a context, runs the given attestors so they land in
// CompletedAttestors, and returns the context. Attestor errors are recorded
// on the completed entry, not returned, so this never fails the test setup.
func runTestAttestors(t *testing.T, attestors ...attestation.Attestor) *attestation.AttestationContext {
	t.Helper()
	ctx, err := attestation.NewContext("test", attestors)
	require.NoError(t, err)
	_ = ctx.RunAttestors()
	return ctx
}

func successfulPush(stdout, stderr string) *fakeCommandRunAttestor {
	return &fakeCommandRunAttestor{data: &commandrun.CommandRun{
		Cmd:      []string{"docker", "push", "localhost:5959/regdigest-demo:v1.0"},
		ExitCode: 0,
		Stdout:   stdout,
		Stderr:   stderr,
	}}
}

func TestIsRegistryPushCommand(t *testing.T) {
	for name, tc := range map[string]struct {
		cmd  []string
		want bool
	}{
		"docker push":               {[]string{"docker", "push", "r:t"}, true},
		"docker push absolute path": {[]string{"/usr/local/bin/docker", "push", "r:t"}, true},
		"docker image push":         {[]string{"docker", "image", "push", "r:t"}, true},
		"crane push":                {[]string{"crane", "push", "demo.tar", "r:t"}, true},
		"crane copy":                {[]string{"crane", "copy", "a", "b"}, true},
		"crane cp":                  {[]string{"crane", "cp", "a", "b"}, true},
		"docker pull":               {[]string{"docker", "pull", "r:t"}, false},
		"docker build":              {[]string{"docker", "build", "."}, false},
		"crane digest":              {[]string{"crane", "digest", "r:t"}, false},
		"shell wrapper":             {[]string{"sh", "-c", "docker push r:t"}, false},
		"bash wrapper":              {[]string{"bash", "-c", "docker push r:t"}, false},
		"docker with global flag":   {[]string{"docker", "--config", "/tmp", "push", "r:t"}, false},
		"podman unverified grammar": {[]string{"podman", "push", "r:t"}, false},
		"bare docker":               {[]string{"docker"}, false},
		"empty argv":                {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, isRegistryPushCommand(tc.cmd))
		})
	}
}

func TestCollectRegistryDigests_RejectsPushShapedOutputFromNonPushCommand(t *testing.T) {
	fake := &fakeCommandRunAttestor{data: &commandrun.CommandRun{
		Cmd:      []string{"bash", "-c", "make release"},
		ExitCode: 0,
		Stdout:   realDockerPushSingle,
	}}
	ctx := runTestAttestors(t, fake)
	assert.Empty(t, collectRegistryDigests(ctx),
		"a non-push command printing push-shaped lines must not mint signed image evidence")
}

func TestCollectRegistryDigests_RejectsFailedPush(t *testing.T) {
	fake := &fakeCommandRunAttestor{data: &commandrun.CommandRun{
		Cmd:      []string{"docker", "push", "localhost:5959/regdigest-demo:v1.0"},
		ExitCode: 1,
		Stdout:   realDockerPushSingle,
	}}
	ctx := runTestAttestors(t, fake)
	assert.Empty(t, collectRegistryDigests(ctx),
		"a failed push proves nothing about registry state")
}

func TestCollectRegistryDigests_RejectsErroredCommandAttestor(t *testing.T) {
	fake := successfulPush(realDockerPushSingle, "")
	fake.attestErr = errors.New("wrapped command exited with status 1")
	ctx := runTestAttestors(t, fake)
	assert.Empty(t, collectRegistryDigests(ctx),
		"output from an errored commandrun attestor must not be trusted")
}

func TestCollectRegistryDigests_AcceptsSuccessfulDockerPush(t *testing.T) {
	ctx := runTestAttestors(t, successfulPush(realDockerPushSingle, ""))
	got := collectRegistryDigests(ctx)
	require.Len(t, got, 1)
	assert.Equal(t, "localhost:5959/regdigest-demo:v1.0", got[0].Reference)
	assert.Equal(t, "b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967", digestOf(t, got[0]))
}

// ---------------------------------------------------------------------------
// Attest fail-closed contract: only the explicit no-candidate outcome may be
// masked by observed registry digests. A tarball that exists but is corrupt
// must fail the attestation even when digests were parsed.
// ---------------------------------------------------------------------------

func TestAttest_PushOnlyRunSucceedsWithoutTarball(t *testing.T) {
	ctx := runTestAttestors(t, successfulPush(realDockerPushSingle, ""))
	a := New()
	require.NoError(t, a.Attest(ctx),
		"a push-only run with no tar product is a complete digest-only attestation")
	require.Contains(t, a.Subjects(),
		"registrydigest:localhost:5959/regdigest-demo:v1.0@sha256:b21786d94b8e977e2254df67758eee19b1cf94e536fc81b53574f5910fd49967")
}

func TestAttest_NoDigestsAndNoTarballStillFails(t *testing.T) {
	ctx := runTestAttestors(t, &fakeCommandRunAttestor{data: &commandrun.CommandRun{
		Cmd:      []string{"go", "build", "./..."},
		ExitCode: 0,
	}})
	a := New()
	err := a.Attest(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, errNoCandidate)
}

// tamperedTarProducer registers a tar-mime product whose recorded digest does
// not match the file's real content, simulating a corrupted/tampered product.
type tamperedTarProducer struct {
	path string
}

func (p *tamperedTarProducer) Name() string                                   { return "tampered-producer" }
func (p *tamperedTarProducer) Type() string                                   { return "tampered" }
func (p *tamperedTarProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (p *tamperedTarProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (p *tamperedTarProducer) Schema() *jsonschema.Schema                     { return nil }
func (p *tamperedTarProducer) Products() map[string]attestation.Product {
	return map[string]attestation.Product{
		p.path: {
			MimeType: mimeTypes,
			Digest: cryptoutil.DigestSet{
				cryptoutil.DigestValue{Hash: crypto.SHA256}: "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}
}

func TestAttest_CorruptTarballFailsClosedDespiteRegistryDigests(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "image.tar")
	require.NoError(t, os.WriteFile(tarPath, []byte("not a real tarball"), 0o600))

	ctx := runTestAttestors(t,
		successfulPush(realDockerPushSingle, ""),
		&tamperedTarProducer{path: tarPath},
	)

	a := New()
	err := a.Attest(ctx)
	require.Error(t, err,
		"an existing-but-corrupt tar candidate must fail the attestation even when registry digests were observed")
	assert.NotErrorIs(t, err, errNoCandidate)
	assert.Contains(t, err.Error(), "integrity error")
}
