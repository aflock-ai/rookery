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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
			return runPolicyFromBundles(cmd.OutOrStdout(), cmd.ErrOrStderr(), args, pubKeyPaths, output, expiresIn, stepNamePrefix)
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
//
// A bundle is either a *collection* envelope (predicateType ==
// collectionPredicateURI; the standard `cilock run` output) or a
// *bare-predicate* envelope (anything else: inclusion-proof, SLSA
// provenance export, sbom export, link export, …). The two go into
// different parts of the witness Policy: collections → Steps[],
// bare predicates → ExternalAttestations[].
type bundleSummary struct {
	path           string
	stepName       string
	signingKeyIDs  []string
	predicateTypes []string
	// outerPredicateType is the statement's top-level predicateType.
	// Used to decide collection vs bare-predicate routing.
	outerPredicateType string
	// sidecars are *-<exportname>.json envelopes auto-discovered
	// alongside the main bundle (e.g., the file the sbom attestor
	// emits when --attestor-sbom-export is set). Empty for
	// bare-predicate bundles (we don't recurse).
	sidecars []sidecarSummary
	// certSigners holds one entry per signatures[] element that
	// carried an x509 certificate chain instead of a raw-keyid
	// pubkey signature. When non-empty, this bundle is "cert-signed"
	// and the policy generator emits Functionary{Type: "root"} with
	// a CertConstraint pointing at policy.Roots[<keyid>] — not the
	// raw-keyid Functionary{Type: "publickey"} shape used for
	// pubkey-signed bundles.
	//
	// Red-team finding (PR #186 follow-up): treating a cert-signed
	// bundle as a pubkey-signed one yields a Functionary the
	// generated policy can never verify; users had to hand-edit.
	certSigners []certSigner

	// productDigests / materialDigests are the sha256 file digests of
	// this step's product (output) and material (input) v0.3 Merkle
	// leaves. They drive cross-step provenance edge detection: a step
	// whose materials include another step's product output consumed
	// that output, so the generator wires an artifactsFrom edge between
	// them. Empty for bundles with no v0.3 product/material attestation
	// (e.g. bare-predicate envelopes, legacy v0.1 collections).
	productDigests  map[string]struct{}
	materialDigests map[string]struct{}
}

// certSigner describes one x509-cert-bearing signature on a DSSE
// envelope. Used to route cert-signed bundles to Policy.Roots[] +
// Functionary{Type: "root"} instead of the pubkey path.
type certSigner struct {
	keyID         string // sigs[].keyid (still present; identifies leaf cert pubkey)
	leafPEM       []byte // raw PEM bytes of the leaf cert, as embedded in the envelope
	intermediates [][]byte
	commonName    string // leaf cert CN, if parseable; "" otherwise (best-effort)
}

// sidecarSummary captures one of the export sidecar envelopes that
// `cilock run --attestor-*-export` emits alongside the main bundle.
// File-naming convention: `<mainBundlePath>-<exportname>.json` (e.g.
// `build.bundle.json-sbom.json`).
type sidecarSummary struct {
	path          string
	name          string // stable name for the ExternalAttestation entry
	signingKeyIDs []string
	predicateType string
}

func runPolicyFromBundles(stdout, stderr io.Writer, bundlePaths, pubKeyPaths []string, outputPath string, expiresIn time.Duration, stepPrefix string) error {
	if len(bundlePaths) == 0 {
		return fmt.Errorf("at least one bundle path is required")
	}

	pubKeys, err := loadPolicyPubKeys(pubKeyPaths)
	if err != nil {
		return err
	}

	summaries, err := summarizeBundles(stderr, bundlePaths, stepPrefix)
	if err != nil {
		return err
	}

	pol, err := buildStarterPolicy(stderr, summaries, pubKeys, expiresIn)
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

func summarizeBundles(stderr io.Writer, paths []string, stepPrefix string) ([]bundleSummary, error) {
	out := make([]bundleSummary, 0, len(paths))
	for _, p := range paths {
		s, err := summarizeOneBundle(stderr, p, stepPrefix)
		if err != nil {
			return nil, fmt.Errorf("summarize %s: %w", p, err)
		}
		out = append(out, s)
	}
	return out, nil
}

// bundleSignature is one DSSE signature entry as cilock writes it. Certificate
// is the leaf x509 cert PEM bytes, JSON-encoded (Go encodes []byte as base64);
// cilock populates it whenever the signer is a TrustBundler (Fulcio leaf, manual
// cert chain, etc) — see attestation/dsse/sign.go.
type bundleSignature struct {
	KeyID         string   `json:"keyid"`
	Certificate   []byte   `json:"certificate,omitempty"`
	Intermediates [][]byte `json:"intermediates,omitempty"`
}

// summarizeOneBundle parses a DSSE envelope on disk and extracts the
// pieces a policy needs: signing keyids and inner predicate types.
// For attestation-collection envelopes, the inner types live in
// predicate.attestations[].type; for bare-predicate envelopes the
// outer predicateType is the single attestation type.
func summarizeOneBundle(stderr io.Writer, path, stepPrefix string) (bundleSummary, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // user-supplied arg
	if err != nil {
		return bundleSummary{}, err
	}

	var env struct {
		Payload     string            `json:"payload"`
		PayloadType string            `json:"payloadType"`
		Signatures  []bundleSignature `json:"signatures"`
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

	// The collection envelope's predicate carries a `name` field that
	// is the authoritative step name (passed to `cilock run -s <name>`).
	// We prefer this over the filename-derived name so that a user
	// renaming `<step>.bundle.json` to `<anything>.att.json` doesn't
	// break the policy. See issue #224.
	var stmt struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Name         string `json:"name"`
			Attestations []struct {
				Type        string `json:"type"`
				Attestation struct {
					Leaves []struct {
						FileDigest string `json:"fileDigest"`
					} `json:"leaves"`
				} `json:"attestation"`
			} `json:"attestations"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		return bundleSummary{}, fmt.Errorf("decode in-toto statement: %w", err)
	}

	// Capture the inner attestation types AND the product (output) + material
	// (input) file digests from the v0.3 Merkle attestations in a single pass.
	// The digests drive cross-step provenance edge detection.
	innerTypes := make([]string, 0, len(stmt.Predicate.Attestations))
	productDigests := make(map[string]struct{})
	materialDigests := make(map[string]struct{})
	for _, a := range stmt.Predicate.Attestations {
		innerTypes = append(innerTypes, a.Type)
		var sink map[string]struct{}
		switch {
		case strings.Contains(a.Type, "/product/"):
			sink = productDigests
		case strings.Contains(a.Type, "/material/"):
			sink = materialDigests
		default:
			continue
		}
		for _, l := range a.Attestation.Leaves {
			if l.FileDigest != "" {
				sink[l.FileDigest] = struct{}{}
			}
		}
	}

	// Walk signatures once, separating cert-signed entries from raw-keyid
	// pubkey entries (see collectSigners).
	keyids, certs := collectSigners(env.Signatures)

	predicateTypes := extractPredicateTypes(stmt.PredicateType, innerTypes)
	sidecars, _ := discoverSidecars(path)

	stepName := stepPrefix + resolveStepName(stderr, path, stmt.Predicate.Name)
	return bundleSummary{
		path:               path,
		stepName:           stepName,
		signingKeyIDs:      keyids,
		predicateTypes:     predicateTypes,
		outerPredicateType: stmt.PredicateType,
		sidecars:           sidecars,
		certSigners:        certs,
		productDigests:     productDigests,
		materialDigests:    materialDigests,
	}, nil
}

// collectSigners walks a bundle's DSSE signatures once, separating cert-signed
// entries from raw-keyid pubkey entries. A signature with non-empty Certificate
// bytes is cert-based: its keyid identifies the leaf cert's public key, but the
// policy must use a CertConstraint / Root rather than a raw publickeys[] entry.
// Mixed envelopes (one pubkey sig + one cert sig) are unusual but supported —
// both shapes land in their respective policy collections. Each keyid is deduped
// so repeat signatures from the same key don't produce duplicate policy entries.
func collectSigners(sigs []bundleSignature) (keyids []string, certs []certSigner) {
	keyids = make([]string, 0, len(sigs))
	certs = make([]certSigner, 0, len(sigs))
	seenKID := make(map[string]struct{}, len(sigs))
	seenCert := make(map[string]struct{}, len(sigs))
	for _, s := range sigs {
		if s.KeyID == "" {
			continue
		}
		if len(s.Certificate) > 0 {
			// Cert-signed: keyid is the leaf-cert pubkey hash. Track uniquely
			// by keyid so two sigs from the same leaf cert don't produce two
			// Roots[] entries.
			if _, dup := seenCert[s.KeyID]; dup {
				continue
			}
			seenCert[s.KeyID] = struct{}{}
			certs = append(certs, certSigner{
				keyID:         s.KeyID,
				leafPEM:       s.Certificate,
				intermediates: s.Intermediates,
				commonName:    extractLeafCommonName(s.Certificate),
			})
			continue
		}
		// Raw-keyid pubkey signature: existing behavior.
		if _, dup := seenKID[s.KeyID]; dup {
			continue
		}
		seenKID[s.KeyID] = struct{}{}
		keyids = append(keyids, s.KeyID)
	}
	return keyids, certs
}

// extractLeafCommonName best-effort parses the leaf cert PEM to pull
// its Subject Common Name. Failure is non-fatal: this is starter-policy
// metadata, and the user is expected to tighten the CertConstraint
// before signing. Returns "" on any parse error.
func extractLeafCommonName(leafPEM []byte) string {
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

// discoverSidecars finds export-sidecar DSSE envelopes adjacent to the
// main bundle. cilock's --attestor-*-export flags emit one envelope per
// exported attestor at `<mainPath>-<exportname>.json`. Each sidecar is
// itself a bare-predicate DSSE that the witness Policy must reference
// via ExternalAttestation (NOT a Step). Without this discovery, a
// `cilock run --attestor-sbom-export` would silently produce an
// unverifiable policy because the SBOM predicate is no longer in the
// main bundle's attestations[] list.
//
// Sidecars are detected by:
//  1. Filename matches `<mainPath>-*.json` (cilock's naming convention)
//  2. The file parses as a DSSE envelope (excludes tree.json /
//     detection.json sidecars which are JSON but not envelopes)
//
// Returns an empty slice (not an error) when no sidecars are found.
// Errors decoding a candidate file are silently skipped — finding the
// main bundle should not fail because a corrupted neighbor exists.
func discoverSidecars(mainPath string) ([]sidecarSummary, error) {
	dir := filepath.Dir(mainPath)
	base := filepath.Base(mainPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("scan sidecar dir %s: %w", dir, err)
	}

	out := make([]sidecarSummary, 0, 2)
	prefix := base + "-" // e.g. "build.bundle.json-"
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		// Exclude cilock's other sidecar kinds (tree, detection) which
		// share the suffix space but aren't DSSE envelopes. Those don't
		// match the `<base>-*.json` pattern (they use `.<kind>.json`),
		// so the prefix check above already excludes them — but we'll
		// also validate by attempting a DSSE decode below.
		side, ok := readSidecar(filepath.Join(dir, name), strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json"))
		if !ok {
			continue
		}
		out = append(out, side)
	}
	return out, nil
}

// readSidecar attempts to parse a candidate file as a DSSE envelope
// carrying a bare-predicate statement. Returns ok=false when the file
// doesn't fit (not JSON, not DSSE, missing fields) — the caller skips
// it without error.
func readSidecar(path, exportName string) (sidecarSummary, bool) {
	raw, err := os.ReadFile(path) //nolint:gosec // adjacent-to-input by construction
	if err != nil {
		return sidecarSummary{}, false
	}
	var env struct {
		Payload    string `json:"payload"`
		Signatures []struct {
			KeyID string `json:"keyid"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return sidecarSummary{}, false
	}
	if env.Payload == "" || len(env.Signatures) == 0 {
		return sidecarSummary{}, false
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return sidecarSummary{}, false
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil || stmt.PredicateType == "" {
		return sidecarSummary{}, false
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
	return sidecarSummary{
		path:          path,
		name:          exportName,
		signingKeyIDs: keyids,
		predicateType: stmt.PredicateType,
	}, true
}

// extractPredicateTypes flattens a statement into the set of inner
// attestation types a Witness step needs to list. For collection
// envelopes we recurse into the inner attestation types; for bare
// predicates we return the outer type as the only entry.
func extractPredicateTypes(outerType string, innerTypes []string) []string {
	if outerType != collectionPredicateURI {
		if outerType == "" {
			return nil
		}
		return []string{outerType}
	}
	out := make([]string, 0, len(innerTypes))
	seen := make(map[string]struct{}, len(innerTypes))
	for _, t := range innerTypes {
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// resolveStepName decides which name to use as the policy step name
// for a bundle. The bundle's predicate.name (what `cilock run -s
// <name>` recorded inside the collection envelope) is authoritative;
// only when it's missing do we fall back to deriving from the file
// basename. When the recorded name differs from what the filename
// would have produced, we emit a notice on stderr — historically the
// filename drove the step name (see issue #224), so a user renaming
// their bundles to a non-standard extension would otherwise be
// silently overridden.
func resolveStepName(stderr io.Writer, path, recordedName string) string {
	filenameDerived := deriveStepName(path)
	if recordedName == "" {
		return filenameDerived
	}
	if stderr != nil && recordedName != filenameDerived {
		_, _ = fmt.Fprintf(stderr,
			"info: bundle %s records step name %q; using that instead of filename-derived %q\n",
			path, recordedName, filenameDerived)
	}
	return recordedName
}

// deriveStepName turns "/path/to/source-git.bundle.json" into
// "source-git". This matches the convention `cilock run -o` users
// already adopt (one bundle per logical step).
//
// Only used as a fallback when the bundle payload's predicate.name is
// missing (issue #224). To accommodate the variety of filename
// conventions users have adopted, we strip the longest known
// double-extension first (`.bundle.json`, `.att.json`, `.envelope.json`)
// before falling through to a plain `.json` strip. Longest-match-first
// ordering matters: `foo.att.json` must produce `foo`, not `foo.att`.
func deriveStepName(path string) string {
	base := filepath.Base(path)
	// Ordered longest-match-first. Each suffix is tried in turn; the
	// first match wins so we don't over-strip when an extension that
	// would otherwise be a prefix of another (e.g. `.json` vs
	// `.bundle.json`) is also a candidate.
	for _, suffix := range []string{".bundle.json", ".att.json", ".envelope.json", ".json"} {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	// Drop any leading dot so hidden filenames don't yield empty names.
	base = strings.TrimLeft(base, ".")
	if base == "" {
		base = "step"
	}
	return base
}

// buildStarterPolicy assembles the Policy struct from the summaries
// and the keyid → PEM map.
//
// Routing:
//   - bundles whose outer predicateType is the attestation-collection
//     URI become Steps[] entries (the standard `cilock run` output)
//   - bundles whose outer predicateType is anything else
//     (inclusion-proof, slsa-provenance, vsa, vex, …) become
//     ExternalAttestations[] entries — witness Policy's primitive for
//     "this signed bare-predicate envelope must be present"
//   - sidecars (auto-discovered next to collection bundles) become
//     ExternalAttestations[] AND are linked back from the parent Step
//     via Step.ExternalFrom so Rego in the step can read them
//
// Bundles signed by a key the user didn't supply via -k get a
// placeholder publickeys entry with empty Key material — the policy
// file will still validate-as-JSON but fail signature verification
// until the user fills in the PEM.
func buildStarterPolicy(stderr io.Writer, summaries []bundleSummary, pubKeys map[string][]byte, expiresIn time.Duration) (*policy.Policy, error) {
	expires := time.Now().UTC().Add(expiresIn)
	p := &policy.Policy{
		Expires:              metav1.NewTime(expires),
		PublicKeys:           make(map[string]policy.PublicKey),
		Steps:                make(map[string]policy.Step),
		ExternalAttestations: make(map[string]policy.ExternalAttestation),
	}

	for _, s := range summaries {
		funcs := buildFunctionaries(s.signingKeyIDs, pubKeys, p.PublicKeys)
		// Cert-signed signatures contribute Functionary{Type:"root"}
		// entries and Roots[] registrations rather than publickeys[].
		// See certSigner doc for the red-team motivation.
		funcs = append(funcs, buildCertFunctionaries(s.certSigners, p)...)

		if s.outerPredicateType == "" || s.outerPredicateType == collectionPredicateURI {
			// Collection envelope → a Step.
			atts := make([]policy.Attestation, 0, len(s.predicateTypes))
			for _, t := range s.predicateTypes {
				atts = append(atts, policy.Attestation{Type: t})
			}
			if _, dup := p.Steps[s.stepName]; dup {
				return nil, fmt.Errorf("duplicate step name %q (two bundles with the same basename — pass --step-prefix or rename inputs)", s.stepName)
			}

			// Attach sidecars as ExternalAttestations, linked via
			// ExternalFrom so the step's Rego (if any) can read them.
			extFrom := make([]string, 0, len(s.sidecars))
			for _, sc := range s.sidecars {
				extName := s.stepName + "-" + sc.name
				if err := addExternalAttestation(p, extName, sc.predicateType, sc.signingKeyIDs, pubKeys); err != nil {
					return nil, err
				}
				extFrom = append(extFrom, extName)
			}

			p.Steps[s.stepName] = policy.Step{
				Name:          s.stepName,
				Functionaries: funcs,
				Attestations:  atts,
				ExternalFrom:  extFrom,
			}
			continue
		}

		// Bare-predicate envelope → an ExternalAttestation. No Step.
		// This is the fix for the blind-test friction where
		// `cilock prove` output was generating an always-failing Step.
		// Cert functionaries (if any) are already in `funcs`.
		if err := addExternalAttestationWithFuncs(p, s.stepName, s.outerPredicateType, funcs); err != nil {
			return nil, err
		}
	}

	// Wire cross-step provenance edges where a step's materials consumed
	// another step's product output, then warn if a multi-step policy still
	// has no cross-step integrity — the linker can't recover that from the
	// github attestor's shared pipelineurl offline, so the result LOOKS
	// complete but won't verify end-to-end. See wireProvenanceEdges.
	edgesEmitted := wireProvenanceEdges(p, summaries)
	warnMissingProvenanceEdges(stderr, p, edgesEmitted)

	return p, nil
}

// wireProvenanceEdges detects product→material flow between the input bundles
// and emits Step.ArtifactsFrom edges: step B consumed step A's output when B's
// material set contains a file whose sha256 digest equals one of A's product
// digests. This recovers the cross-step integrity the offline linker otherwise
// loses (the github attestor's shared pipelineurl is absent offline), so the
// generated policy enforces that the build's inputs really are the upstream
// step's outputs instead of independent, unverified steps.
//
// Returns the number of edges emitted so the caller can warn when a multi-step
// policy ended up with none. Self-edges (a step consuming its own product) are
// skipped. Only collection steps (present in p.Steps) participate.
func wireProvenanceEdges(p *policy.Policy, summaries []bundleSummary) int {
	emitted := 0
	for _, consumer := range summaries {
		step, ok := p.Steps[consumer.stepName]
		if !ok || len(consumer.materialDigests) == 0 {
			continue
		}
		var from []string
		seen := make(map[string]struct{})
		for _, producer := range summaries {
			if producer.stepName == consumer.stepName || len(producer.productDigests) == 0 {
				continue
			}
			if _, dup := seen[producer.stepName]; dup {
				continue
			}
			if digestSetsOverlap(producer.productDigests, consumer.materialDigests) {
				from = append(from, producer.stepName)
				seen[producer.stepName] = struct{}{}
			}
		}
		if len(from) == 0 {
			continue
		}
		sort.Strings(from)
		step.ArtifactsFrom = from
		p.Steps[consumer.stepName] = step
		emitted += len(from)
	}
	return emitted
}

// digestSetsOverlap reports whether any digest in a is also in b. Iterates the
// smaller set for cheapness.
func digestSetsOverlap(a, b map[string]struct{}) bool {
	small, large := a, b
	if len(b) < len(a) {
		small, large = b, a
	}
	for d := range small {
		if _, ok := large[d]; ok {
			return true
		}
	}
	return false
}

// warnMissingProvenanceEdges emits a one-line warning when the generated policy
// has more than one step but no cross-step provenance edge was wired. Such a
// policy looks complete — N independent steps — but enforces NO ordering or
// product→material integrity between them, a silent footgun the offline linker
// can't avoid without the github attestor's pipelineurl. The warning tells the
// operator how to close the gap.
func warnMissingProvenanceEdges(stderr io.Writer, p *policy.Policy, edgesEmitted int) {
	if stderr == nil || len(p.Steps) <= 1 || edgesEmitted > 0 {
		return
	}
	_, _ = fmt.Fprintf(stderr,
		"warning: emitted %d independent steps with no cross-step provenance edges; "+
			"cross-step integrity is NOT enforced. Wire steps with cilock prove-chain, "+
			"or verify each step's product individually.\n",
		len(p.Steps))
}

// buildFunctionaries materializes Functionary entries for a set of
// signing keyids, side-effecting the policy's publickeys map with the
// matching PEM material (or a placeholder if the user didn't pass -k
// for the signing key).
func buildFunctionaries(keyids []string, pubKeys map[string][]byte, policyKeys map[string]policy.PublicKey) []policy.Functionary {
	out := make([]policy.Functionary, 0, len(keyids))
	for _, kid := range keyids {
		out = append(out, policy.Functionary{
			Type:        "publickey",
			PublicKeyID: kid,
		})
		if pem, ok := pubKeys[kid]; ok {
			policyKeys[kid] = policy.PublicKey{KeyID: kid, Key: pem}
		} else if _, exists := policyKeys[kid]; !exists {
			policyKeys[kid] = policy.PublicKey{KeyID: kid, Key: nil}
		}
	}
	return out
}

// addExternalAttestation appends one ExternalAttestation, ensuring
// the name is unique and the functionary keys are recorded in the
// policy's publickeys map. Used for raw-keyid (pubkey-signed) sidecar
// envelopes. For cert-signed envelopes the caller pre-builds the
// functionary list and uses addExternalAttestationWithFuncs.
func addExternalAttestation(p *policy.Policy, name, predicateType string, signingKeyIDs []string, pubKeys map[string][]byte) error {
	return addExternalAttestationWithFuncs(p, name, predicateType,
		buildFunctionaries(signingKeyIDs, pubKeys, p.PublicKeys))
}

// addExternalAttestationWithFuncs is the cert-aware variant: callers
// pre-compute the Functionary slice (mix of publickey + root types)
// and pass it in directly. Used by buildStarterPolicy's bare-
// predicate path so cert-signed bare-predicate envelopes (e.g. a
// Fulcio-signed SLSA provenance) get the correct root-functionary
// shape.
func addExternalAttestationWithFuncs(p *policy.Policy, name, predicateType string, funcs []policy.Functionary) error {
	if _, dup := p.ExternalAttestations[name]; dup {
		return fmt.Errorf("duplicate external attestation name %q", name)
	}
	p.ExternalAttestations[name] = policy.ExternalAttestation{
		Name:          name,
		PredicateType: predicateType,
		Functionaries: funcs,
		Required:      true,
	}
	return nil
}

// buildCertFunctionaries materializes Functionary{Type:"root"} entries
// for cert-signed signatures and side-effects p.Roots with the leaf
// cert chain so the policy is self-contained. The CertConstraint is
// intentionally minimal — a starter template — pinning the trust to
// the specific root we just embedded (Roots: [keyid]). When the leaf
// has a parseable Common Name we copy it into the constraint so the
// generated policy fails fast on cert substitutions; users are
// expected to tighten DNSNames / Emails / Organizations / Extensions
// before production use.
func buildCertFunctionaries(signers []certSigner, p *policy.Policy) []policy.Functionary {
	if len(signers) == 0 {
		return nil
	}
	if p.Roots == nil {
		p.Roots = make(map[string]policy.Root, len(signers))
	}
	out := make([]policy.Functionary, 0, len(signers))
	for _, cs := range signers {
		rootName := cs.keyID
		// Two cert-signed bundles by the same leaf cert share a Root
		// entry — register once. We don't try to merge intermediates
		// across registrations; the first writer wins, and a
		// generator that produces an inconsistent chain is a bug in
		// the upstream signer, not here.
		if _, exists := p.Roots[rootName]; !exists {
			p.Roots[rootName] = policy.Root{
				Certificate:   cs.leafPEM,
				Intermediates: cs.intermediates,
			}
		}
		out = append(out, policy.Functionary{
			Type: "root",
			CertConstraint: policy.CertConstraint{
				Roots:      []string{rootName},
				CommonName: cs.commonName, // empty when parse failed; user fills in
			},
		})
	}
	return out
}
