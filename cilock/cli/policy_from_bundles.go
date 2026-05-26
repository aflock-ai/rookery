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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/spf13/cobra"
)

const (
	// defaultPolicyExpiry is one year from generation. Users can override
	// with --expires; the value is intentionally short by supply-chain
	// standards because a generated starter policy should be reviewed and
	// re-issued before it's anywhere near production-ready.
	defaultPolicyExpiry = 365 * 24 * time.Hour

	// collectionPredicateURI is the in-toto predicate type cilock uses
	// for its attestation collection wrapper. When we see this, the
	// "real" attestation types live in predicate.attestations[].type
	// and we list those in the policy step rather than the wrapper URI.
	collectionPredicateURI = "https://aflock.ai/attestation-collection/v0.1"
)

// PolicyFromBundlesCmd is `cilock policy from-bundles`. It reads a set
// of signed DSSE bundles (the kind `cilock run` writes), pulls out the
// signing keyids and inner predicate types, matches them to public
// keys the user supplies, and emits a starter witness Policy.
//
// The output is intentionally lossy: it has no Rego, no certificate
// constraints, no time-of-use constraints, default 1-year expiry. The
// goal is to skip the tedious "type out a publickeys map and a steps
// map" step. Users are expected to edit the output before signing it.
//
// UX shape:
//
//	cilock policy from-bundles \
//	    -k signer.pub \
//	    source-git.bundle.json \
//	    build.bundle.json \
//	    sbom.bundle.json \
//	    > policy.json
//
// One public key may cover any number of bundles signed with the same
// key; multiple -k flags can be passed for multi-signer suites.
func PolicyFromBundlesCmd() *cobra.Command {
	var (
		pubKeyPaths    []string
		output         string
		expiresIn      time.Duration
		stepNamePrefix string
	)

	cmd := &cobra.Command{
		Use:   "from-bundles <bundle.json>...",
		Short: "Generate a starter Witness policy from existing signed bundles",
		Long: `from-bundles reads one or more DSSE-signed attestation bundles
(as produced by 'cilock run -o ...'), inspects each envelope for its signing
keyid and inner predicate types, and emits a Witness policy template you can
edit + sign.

The generated policy:
  - lists one step per input bundle (step name = bundle basename without the .bundle.json suffix)
  - populates step.functionaries with the signing keyid for that bundle
  - populates step.attestations with each predicate type found inside
    (for collection envelopes, the inner attestation types; for bare
    predicates, the payload's predicateType)
  - populates publickeys[] with the PEM key material for every key
    that signed at least one input bundle
  - defaults expires to 1 year from now (override with --expires)

You must supply the public key material for every signing key the
bundles use, via one or more -k flags. The subcommand derives each
key's keyid (hex(sha256(PEM(pub))), same as 'cilock keyid show') and
matches it against the signatures[].keyid values it finds in the
bundles. Bundles signed by an unknown key get a placeholder PublicKey
entry the user must fill in before the policy can be signed.

Examples:
  cilock policy from-bundles -k signer.pub *.bundle.json > policy.json
  cilock policy from-bundles -k signer.pub -k otherteam.pub --output policy.json source-git.bundle.json build.bundle.json`,
		Args:          cobra.MinimumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyFromBundles(cmd.OutOrStdout(), args, pubKeyPaths, output, expiresIn, stepNamePrefix)
		},
	}

	cmd.Flags().StringSliceVarP(&pubKeyPaths, "publickey", "k", nil,
		"Public-key PEM file(s) corresponding to the signers of the input bundles. Repeat for multi-signer suites. Required when any bundle is signed by a key whose material you want in the policy.")
	cmd.Flags().StringVarP(&output, "output", "o", "-",
		"Write the generated policy here. '-' (default) is stdout.")
	cmd.Flags().DurationVar(&expiresIn, "expires", defaultPolicyExpiry,
		"How far in the future the policy's `expires` field is set. Defaults to one year. Generated policies are starter templates — set this short and re-issue after review.")
	cmd.Flags().StringVar(&stepNamePrefix, "step-prefix", "",
		"Optional prefix prepended to every generated step name (e.g. 'release-' yields 'release-source-git'). Empty by default.")
	return cmd
}

// bundleSummary is what we extract from one DSSE envelope to build the
// policy. Kept as an internal type so we don't depend on cilock's own
// bundle helpers — this subcommand should be readable in isolation.
type bundleSummary struct {
	path           string
	stepName       string
	signingKeyIDs  []string
	predicateTypes []string
}

func runPolicyFromBundles(stdout io.Writer, bundlePaths, pubKeyPaths []string, outputPath string, expiresIn time.Duration, stepPrefix string) error {
	if len(bundlePaths) == 0 {
		return fmt.Errorf("at least one bundle path is required")
	}

	pubKeys, err := loadPolicyPubKeys(pubKeyPaths)
	if err != nil {
		return err
	}

	summaries, err := summarizeBundles(bundlePaths, stepPrefix)
	if err != nil {
		return err
	}

	pol, err := buildStarterPolicy(summaries, pubKeys, expiresIn)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	if outputPath == "-" {
		_, err := stdout.Write(append(encoded, '\n'))
		return err
	}
	return os.WriteFile(outputPath, append(encoded, '\n'), 0o600)
}

// loadPolicyPubKeys reads every -k file, derives its keyid using
// cilock's own algorithm (so the generated policy lines up with what
// `cilock verify` will expect), and returns a keyid → PEM-bytes map.
func loadPolicyPubKeys(paths []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // user-supplied flag value
		if err != nil {
			return nil, fmt.Errorf("read public key %s: %w", p, err)
		}
		v, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("parse %s as PEM public key: %w", p, err)
		}
		kid, err := v.KeyID()
		if err != nil {
			return nil, fmt.Errorf("derive keyid for %s: %w", p, err)
		}
		out[kid] = raw
	}
	return out, nil
}

func summarizeBundles(paths []string, stepPrefix string) ([]bundleSummary, error) {
	out := make([]bundleSummary, 0, len(paths))
	for _, p := range paths {
		s, err := summarizeOneBundle(p, stepPrefix)
		if err != nil {
			return nil, fmt.Errorf("summarize %s: %w", p, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// summarizeOneBundle parses a DSSE envelope on disk and extracts the
// pieces a policy needs: signing keyids and inner predicate types.
// For attestation-collection envelopes, the inner types live in
// predicate.attestations[].type; for bare-predicate envelopes the
// outer predicateType is the single attestation type.
func summarizeOneBundle(path, stepPrefix string) (bundleSummary, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // user-supplied arg
	if err != nil {
		return bundleSummary{}, err
	}

	var env struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return bundleSummary{}, fmt.Errorf("decode DSSE envelope: %w", err)
	}
	if len(env.Signatures) == 0 {
		return bundleSummary{}, fmt.Errorf("envelope has no signatures")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return bundleSummary{}, fmt.Errorf("decode payload: %w", err)
	}

	var stmt struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Attestations []struct {
				Type string `json:"type"`
			} `json:"attestations"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		return bundleSummary{}, fmt.Errorf("decode in-toto statement: %w", err)
	}

	keyids := make([]string, 0, len(env.Signatures))
	seen := make(map[string]struct{}, len(env.Signatures))
	for _, s := range env.Signatures {
		if s.KeyID == "" {
			continue
		}
		if _, dup := seen[s.KeyID]; dup {
			continue
		}
		seen[s.KeyID] = struct{}{}
		keyids = append(keyids, s.KeyID)
	}

	predicateTypes := extractPredicateTypes(stmt.PredicateType, stmt.Predicate.Attestations)

	stepName := stepPrefix + deriveStepName(path)
	return bundleSummary{
		path:           path,
		stepName:       stepName,
		signingKeyIDs:  keyids,
		predicateTypes: predicateTypes,
	}, nil
}

// extractPredicateTypes flattens a statement into the set of inner
// attestation types a Witness step needs to list. For collection
// envelopes we recurse into predicate.attestations[].type; for bare
// predicates we return the outer type as the only entry.
func extractPredicateTypes(outerType string, atts []struct {
	Type string `json:"type"`
}) []string {
	if outerType != collectionPredicateURI {
		if outerType == "" {
			return nil
		}
		return []string{outerType}
	}
	out := make([]string, 0, len(atts))
	seen := make(map[string]struct{}, len(atts))
	for _, a := range atts {
		if a.Type == "" {
			continue
		}
		if _, dup := seen[a.Type]; dup {
			continue
		}
		seen[a.Type] = struct{}{}
		out = append(out, a.Type)
	}
	sort.Strings(out)
	return out
}

// deriveStepName turns "/path/to/source-git.bundle.json" into
// "source-git". This matches the convention `cilock run -o` users
// already adopt (one bundle per logical step).
func deriveStepName(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, ".json")
	base = strings.TrimSuffix(base, ".bundle")
	// Drop any leading dot so hidden filenames don't yield empty names.
	base = strings.TrimLeft(base, ".")
	if base == "" {
		base = "step"
	}
	return base
}

// buildStarterPolicy assembles the Policy struct from the summaries
// and the keyid → PEM map. Bundles signed by a key the user didn't
// supply via -k get a placeholder publickeys entry with empty Key
// material — the policy file will still validate-as-JSON but fail
// signature verification until the user fills in the PEM.
func buildStarterPolicy(summaries []bundleSummary, pubKeys map[string][]byte, expiresIn time.Duration) (*policy.Policy, error) {
	expires := time.Now().UTC().Add(expiresIn)
	p := &policy.Policy{
		Expires:    metav1.NewTime(expires),
		PublicKeys: make(map[string]policy.PublicKey),
		Steps:      make(map[string]policy.Step, len(summaries)),
	}

	for _, s := range summaries {
		// Add functionaries — one per distinct signing keyid in this bundle.
		funcs := make([]policy.Functionary, 0, len(s.signingKeyIDs))
		for _, kid := range s.signingKeyIDs {
			funcs = append(funcs, policy.Functionary{
				Type:        "publickey",
				PublicKeyID: kid,
			})
			if pem, ok := pubKeys[kid]; ok {
				p.PublicKeys[kid] = policy.PublicKey{KeyID: kid, Key: pem}
			} else if _, exists := p.PublicKeys[kid]; !exists {
				// Placeholder for the user to fill in.
				p.PublicKeys[kid] = policy.PublicKey{KeyID: kid, Key: nil}
			}
		}

		// Add attestations.
		atts := make([]policy.Attestation, 0, len(s.predicateTypes))
		for _, t := range s.predicateTypes {
			atts = append(atts, policy.Attestation{Type: t})
		}

		if _, dup := p.Steps[s.stepName]; dup {
			return nil, fmt.Errorf("duplicate step name %q (two bundles with the same basename — pass --step-prefix or rename inputs)", s.stepName)
		}
		p.Steps[s.stepName] = policy.Step{
			Name:          s.stepName,
			Functionaries: funcs,
			Attestations:  atts,
		}
	}
	return p, nil
}
