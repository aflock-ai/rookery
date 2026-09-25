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

package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/sigstorebundle"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/cobra"
)

type verifyBundleOptions struct {
	bundle      string
	san         string
	issuer      string
	key         string
	trustedRoot string
	staging     bool
}

// VerifyBundleCmd verifies a Sigstore bundle. Its flags are the
// sigstore-conformance CLI protocol's verify-bundle.
func VerifyBundleCmd() *cobra.Command {
	o := verifyBundleOptions{}
	cmd := &cobra.Command{
		Use:   "verify-bundle --bundle FILE (--certificate-identity SAN --certificate-oidc-issuer URL | --key PEM) [--trusted-root FILE] [--staging] FILE|sha256:DIGEST",
		Short: "Verify a Sigstore bundle (application/vnd.dev.sigstore.bundle*)",
		Long: `Verify a Sigstore bundle under the Sigstore client verification procedure.

A certificate-signed bundle must match both --certificate-identity (the exact
SAN) and --certificate-oidc-issuer (the exact issuer). Neither can be empty.
A bundle signed by a managed key is verified with --key instead.

Every check the trusted root can back is required. An SCT is required if the
root distributes CT logs, and a transparency-log entry if it distributes Rekor
logs. The signing time comes from a TSA timestamp or a log inclusion promise
that the root can verify. Without --trusted-root, the public-good trusted root
(or staging, with --staging) is fetched over TUF.

The artifact is a file path, or its digest as <sha256|sha384|sha512>:<hex>.`,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runVerifyBundle(o, args[0]); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Verified OK")
			return nil
		},
	}
	cmd.Flags().StringVar(&o.bundle, "bundle", "", "Path to the Sigstore bundle")
	cmd.Flags().StringVar(&o.san, "certificate-identity", "", "Expected certificate SAN (exact match)")
	cmd.Flags().StringVar(&o.issuer, "certificate-oidc-issuer", "", "Expected certificate OIDC issuer (exact match)")
	cmd.Flags().StringVar(&o.key, "key", "", "PEM public key, for a bundle signed by a managed key")
	cmd.Flags().StringVar(&o.trustedRoot, "trusted-root", "", "Path to trusted_root.json (default: public-good over TUF)")
	cmd.Flags().BoolVar(&o.staging, "staging", false, "Use the Sigstore staging trusted root (over TUF)")
	return cmd
}

func runVerifyBundle(o verifyBundleOptions, subject string) error {
	if o.bundle == "" {
		return errors.New("--bundle is required")
	}
	keyFlow := o.key != ""
	if keyFlow && (o.san != "" || o.issuer != "") {
		return errors.New("use --key or --certificate-identity/--certificate-oidc-issuer, not both")
	}
	b, err := bundle.LoadJSONFromPath(o.bundle)
	if err != nil {
		return fmt.Errorf("load bundle: %w", err)
	}
	tm, err := bundleTrustedMaterial(o.trustedRoot, o.staging)
	if err != nil {
		return err
	}
	artifact, closeArtifact, err := bundleArtifact(subject)
	if err != nil {
		return err
	}
	defer closeArtifact()

	if keyFlow {
		keyMaterial, err := managedKeyMaterial(o.key)
		if err != nil {
			return err
		}
		_, err = sigstorebundle.VerifyKey(b, root.TrustedMaterialCollection{keyMaterial, tm}, artifact)
		return err
	}
	_, err = sigstorebundle.VerifyCertificate(b, tm, artifact, o.san, o.issuer)
	return err
}

func bundleTrustedMaterial(path string, staging bool) (root.TrustedMaterial, error) {
	if path != "" {
		tr, err := root.NewTrustedRootFromPath(path)
		if err != nil {
			return nil, fmt.Errorf("load trusted root: %w", err)
		}
		return tr, nil
	}
	opts := tuf.DefaultOptions()
	if staging {
		opts.Root = tuf.StagingRoot()
		opts.RepositoryBaseURL = tuf.StagingMirror
	}
	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("tuf: %w", err)
	}
	raw, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("tuf: fetch trusted_root.json: %w", err)
	}
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("parse trusted root: %w", err)
	}
	return tr, nil
}

var bundleDigestAlgs = map[string]int{"sha256": 32, "sha384": 48, "sha512": 64}

// bundleArtifact reads <alg>:<hex> as a digest and anything else as a path.
func bundleArtifact(subject string) (verify.ArtifactPolicyOption, func(), error) {
	if alg, digestHex, ok := strings.Cut(subject, ":"); ok {
		if size, known := bundleDigestAlgs[alg]; known {
			digest, err := hex.DecodeString(digestHex)
			if err != nil || len(digest) != size {
				return nil, nil, fmt.Errorf("artifact digest %q: want %d hex-encoded bytes of %s", subject, size, alg)
			}
			return verify.WithArtifactDigest(alg, digest), func() {}, nil
		}
	}
	f, err := os.Open(subject) //nolint:gosec // the artifact path is the user's argument
	if err != nil {
		return nil, nil, fmt.Errorf("open artifact: %w", err)
	}
	return verify.WithArtifact(f), func() { _ = f.Close() }, nil
}

func managedKeyMaterial(path string) (root.TrustedMaterial, error) {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // the key path is the user's argument
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		v, err := signature.LoadDefaultVerifier(pub)
		if err != nil {
			return nil, err
		}
		return root.NewExpiringKey(v, time.Time{}, time.Time{}), nil
	}), nil
}
