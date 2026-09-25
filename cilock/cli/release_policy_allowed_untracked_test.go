// jade:ring local

package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/stretchr/testify/require"
)

// signStepMaterialsV450 are the material paths of the `sign` step that no
// `build` artifact covers, taken from the real v4.5.0 release evidence
// (release-fanout run 35883585020, artifact signed-binaries): the linux
// cosign sign envelopes for cilock and jctl on amd64 and arm64 (41 distinct
// untracked paths in all; this list keeps one of each shape). They are
// trace-mode reads, so the paths are absolute.
//
// Today the sign←build chain passes only because 7 system files (libc,
// /etc/ld.so.cache, …) are shared with build; under strict allowedUntracked
// (#9815, enforced by cilock and Judge) the rest would reject it.
var signStepMaterialsV450 = []string{
	"/etc/ssl/certs/.ca-certificates.crt.sha256",
	"/etc/ssl/certs/ca-certificates.crt",
	"/root/.local/bin/cosign",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev.json",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/root.json",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/snapshot.json",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets.json",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/timestamp.json",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/signing_config.v0.2.json",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/tuf_tmp1109724269",
	"/root/.sigstore/root/tuf-repo-cdn.sigstore.dev/tuf_tmp942808392",
	"/usr/lib/libacl.so.1.2.2400",
	"/usr/lib/libattr.so.1.1.2600",
	"/usr/lib/libcrypto.so.3",
	"/usr/lib/libgcc_s.so.1",
	"/usr/lib/libselinux.so.1",
}

// TestSignedBinaryPolicyPassesStrictAllowedUntracked keeps the shipped (if
// dormant) signed-binary release policy green under strict allowedUntracked:
// it validates under the enforced hardening set, its sign step admits every
// material the real v4.5.0 sign runs consumed that build did not produce,
// and it still refuses anything that should need chain of custody.
func TestSignedBinaryPolicyPassesStrictAllowedUntracked(t *testing.T) {
	prev := policy.Hardening()
	t.Cleanup(func() { policy.SetHardening(prev) })
	policy.SetHardening(policy.EnforcedHardening())
	require.True(t, policy.Hardening().EnforceAllowedUntracked)

	p := readReleaseInventoryPolicy(t, "release-policy-signed-binary.json")
	require.NoError(t, p.Validate(), "the policy must load under the enforced hardening set")

	sign, ok := p.Steps["sign"]
	require.True(t, ok)
	require.Equal(t, []string{"build"}, sign.ArtifactsFrom)

	for _, m := range signStepMaterialsV450 {
		ok, err := sign.AllowsUntracked(m)
		require.NoError(t, err)
		require.True(t, ok, "observed v4.5.0 sign material %q must be allow-listed", m)
	}

	// Everything the chain exists to pin, or that an attacker would inject,
	// must stay untracked, i.e. rejected unless build produced it.
	for _, m := range []string{
		"/tmp/build/cilock",
		"/tmp/tmp.mnlZiVSOQT/cilock",
		"/tmp/tmp.mnlZiVSOQT/cilock.exe",
		"/tmp/injected.sh",
		"/root/.local/bin/evil",
		"/usr/lib/x86_64-linux-gnu/evil.so",
		"/usr/lib/../../tmp/evil.so",
		"/usr/bin/cosign",
		"/etc/ssl/private/key.pem",
		"/home/runner/work/judge/judge/scripts/release/sign-binary.sh",
	} {
		ok, err := sign.AllowsUntracked(m)
		require.NoError(t, err)
		require.False(t, ok, "%q must not be allow-listed", m)
	}

	// No other step in this policy has artifactsFrom, so none needs a list.
	for name, s := range p.Steps {
		if name != "sign" {
			require.Empty(t, s.AllowedUntracked, "step %q", name)
		}
	}
}
