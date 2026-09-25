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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"sort"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// Local hydration: `cilock policy draft --hydrate-local`.
//
// This is a port of the platform's hydrator (judge-api/pkg/policy/hydrate,
// driven by hydratePushgatePolicySource in
// judge-api/cmd/server/cmd/handlers_pushgate_policies.go). The sentinel names,
// the trust-broadening guards, the root/intermediate partition and the
// post-hydration assertions are kept identical ON PURPOSE: a policy hydrated
// here and the same source hydrated by the platform must carry the same trust
// entries, or the local verify loop proves something about a document nobody
// will publish. rookery cannot import judge-api, so the rules are restated
// rather than shared; a change to either side must be mirrored in the other.
//
// The difference is only WHERE the material comes from. The platform injects
// its own EmbeddedFulcio bundle and TSA chain. Here they come from the
// platform's discovery document (signing.trust_bundle_pem, which the platform
// fills from the same EmbeddedFulcio.TrustBundlePEM, and
// signing.tsa_cert_chain_url), fetched through config.Discover and
// config.FetchTSACertChain so the https and same-origin guards are the ones
// every other trust-sourcing call site uses.

const (
	// localHydrateFulcioRootID mirrors scaffold.PlatformFulcioRootID.
	localHydrateFulcioRootID = "fulcio-root"
	// localHydrateTSAID mirrors scaffold.PlatformTSAID.
	localHydrateTSAID = "platform-tsa"
	// localHydrateWildcardRootID mirrors hydrate.WildcardRootID.
	localHydrateWildcardRootID = "*"
)

var localHydrateBeginCertificate = []byte("-----BEGIN CERTIFICATE-----")

// localHydratePlan is what a policy asks hydration to do, decided from the
// document alone before anything is fetched.
type localHydratePlan struct {
	fillRoot bool
	fillTSA  bool
}

func (p localHydratePlan) empty() bool { return !p.fillRoot && !p.fillTSA }

// planLocalHydration applies EnsurePlatformBodyRoots' and
// EnsurePlatformBodyTSA's decision rules without the trust material, so a
// policy the platform would refuse is refused before a network call, and a
// policy with nothing to fill never touches the network.
func planLocalHydration(p *policy.Policy) (localHydratePlan, error) {
	var plan localHydratePlan

	existing, hasRoot := p.Roots[localHydrateFulcioRootID]
	switch {
	case hasRoot && len(existing.Certificate) > 0:
		if err := localHydrateAssertCertPEM(existing.Certificate); err != nil {
			return plan, fmt.Errorf("policy.roots[%q].certificate is not a valid X.509 PEM certificate. For platform-managed trust, leave the field empty so draft injects the platform Fulcio CA chain. For a BYO root, provide a valid CERTIFICATE PEM and use a key other than %s; that name is reserved for the platform Fulcio root",
				localHydrateFulcioRootID, localHydrateFulcioRootID)
		}
	case hasRoot:
		// The scaffold-emitted empty sentinel: an explicit opt-in.
		plan.fillRoot = true
	case !localHydrateReferencesRoot(p, localHydrateFulcioRootID):
		// Neither declared nor referenced: injecting would broaden trust.
	case localHydrateReferencesRoot(p, localHydrateWildcardRootID):
		return plan, fmt.Errorf("the policy mixes explicit %s references with a wildcard %q root constraint. Provide roots[%q].certificate so the policy shows the expanded trust set, or remove the wildcard",
			localHydrateFulcioRootID, localHydrateWildcardRootID, localHydrateFulcioRootID)
	default:
		plan.fillRoot = true
	}

	// TSA: only an explicitly declared, empty slot is filled. An author's own
	// certificate is never overwritten, and an absent key is not an opt-in.
	if tsa, ok := p.TimestampAuthorities[localHydrateTSAID]; ok && len(tsa.Certificate) == 0 {
		plan.fillTSA = true
	}
	return plan, nil
}

func localHydrateReferencesRoot(p *policy.Policy, wanted string) bool {
	for _, step := range p.Steps {
		for _, fn := range step.Functionaries {
			for _, id := range fn.CertConstraint.Roots {
				if id == wanted {
					return true
				}
			}
		}
	}
	return false
}

// localHydratePlaced records one certificate written into the policy, for the
// operator to review before signing.
type localHydratePlaced struct {
	slot    string // e.g. roots[fulcio-root]
	role    string // root | intermediate
	subject string
	sha256  string // of the DER
}

// runPolicyDraftLocal is `cilock policy draft --hydrate-local`: fill the
// platform sentinels from discovery, write the UNSIGNED result, print what was
// placed. No session is required and the platform hydration endpoint is never
// called. Like the platform path, it never signs.
func runPolicyDraftLocal(cmd *cobra.Command, o policyDraftOpts) error {
	out := cmd.OutOrStdout()

	platformURL := o.platformURL
	if platformURL == "" {
		if active := auth.ActivePlatformURL(); active != "" {
			platformURL = active
		} else {
			platformURL = config.DefaultPlatformURL
		}
	}
	platformURL = config.NormalizeURL(platformURL)

	source, datatype, err := readTypedPolicySource(cmd, o.file, o.datatype)
	if err != nil {
		return err
	}
	output := o.output
	if output == "" {
		output = defaultHydratedOutputPath(o.file)
	}
	if err := ensureWritableOutput(output, "--output", o.force); err != nil {
		return err
	}

	var typed policy.Policy
	if err := json.Unmarshal([]byte(source), &typed); err != nil {
		return fmt.Errorf("parse policy source %s: %w", o.file, err)
	}
	plan, err := planLocalHydration(&typed)
	if err != nil {
		return fmt.Errorf("refusing to hydrate %s: %w", o.file, err)
	}

	if plan.empty() {
		// Nothing to fill: hand the author's bytes back untouched rather than
		// re-marshaling a document nobody asked us to change.
		if err := writeHydratedPolicy(output, source, o.force); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(out, "✓ %s has no empty %s / %s sentinel to fill; wrote it unchanged to %s (UNSIGNED)\n",
			o.file, localHydrateFulcioRootID, localHydrateTSAID, output)
		printDraftNextSteps(out, output, datatype)
		return nil
	}

	_, _ = fmt.Fprintf(out, "Hydrating %s locally from %s discovery ...\n", o.file, platformURL)
	placed, err := hydrateFromDiscovery(out, platformURL, &typed, plan)
	if err != nil {
		return err
	}
	if err := localHydrateAssertReferencedRootsPresent(&typed); err != nil {
		return fmt.Errorf("policy references roots without certificates: %w", err)
	}
	if err := localHydrateAssertAllTrustParses(&typed); err != nil {
		return err
	}

	hydrated, err := localHydrateRemarshal(source, &typed)
	if err != nil {
		return err
	}
	if err := writeHydratedPolicy(output, hydrated, o.force); err != nil {
		return err
	}

	sum := sha256.Sum256([]byte(hydrated))
	_, _ = fmt.Fprintf(out, "\n✓ hydrated %s → %s locally (UNSIGNED)\n", o.file, output)
	_, _ = fmt.Fprintf(out, "  hydrated: sha256:%s\n", hex.EncodeToString(sum[:]))
	_, _ = fmt.Fprintf(out, "\nPlaced certificates (review these before you sign):\n")
	for _, pl := range placed {
		_, _ = fmt.Fprintf(out, "  %-38s %-12s %s\n  %-38s %-12s sha256:%s\n", pl.slot, pl.role, pl.subject, "", "", pl.sha256)
	}
	printDraftNextSteps(out, output, datatype)
	return nil
}

// hydrateFromDiscovery fetches the trust material the plan needs and injects
// it. The discovery bundle is checked against the trust-on-first-use pin a
// `cilock verify` recorded for this platform (GHSA #5988): a bundle that
// changed since it was pinned is refused, never silently written into a
// document a human is about to sign.
func hydrateFromDiscovery(out io.Writer, platformURL string, p *policy.Policy, plan localHydratePlan) ([]localHydratePlaced, error) {
	disc, err := config.Discover(platformURL)
	if err != nil {
		return nil, fmt.Errorf("platform discovery for %s: %w", platformURL, err)
	}
	if disc.Signing == nil {
		return nil, fmt.Errorf("platform %s discovery advertises no signing trust material; cannot fill %s / %s",
			platformURL, localHydrateFulcioRootID, localHydrateTSAID)
	}
	if err := checkLocalHydratePin(out, platformURL, disc.Signing.TrustBundlePEM); err != nil {
		return nil, err
	}

	var placed []localHydratePlaced
	if plan.fillRoot {
		if disc.Signing.TrustBundlePEM == "" {
			return nil, fmt.Errorf("platform %s discovery has no trust_bundle_pem; cannot fill roots[%q]", platformURL, localHydrateFulcioRootID)
		}
		if p.Roots == nil {
			p.Roots = map[string]policy.Root{}
		}
		entry, got, err := localHydrateEntry("roots["+localHydrateFulcioRootID+"]", []byte(disc.Signing.TrustBundlePEM))
		if err != nil {
			return nil, fmt.Errorf("platform %s trust bundle: %w", platformURL, err)
		}
		p.Roots[localHydrateFulcioRootID] = entry
		placed = append(placed, got...)
	}
	if plan.fillTSA {
		chain, err := config.FetchTSACertChain(platformURL, disc)
		if err != nil {
			return nil, err
		}
		if len(chain) == 0 {
			return nil, fmt.Errorf("platform %s discovery advertises no tsa_cert_chain_url; cannot fill timestampauthorities[%q]", platformURL, localHydrateTSAID)
		}
		entry, got, err := localHydrateEntry("timestampauthorities["+localHydrateTSAID+"]", chain)
		if err != nil {
			return nil, fmt.Errorf("platform %s TSA chain: %w", platformURL, err)
		}
		p.TimestampAuthorities[localHydrateTSAID] = entry
		placed = append(placed, got...)
	}
	return placed, nil
}

// checkLocalHydratePin compares the discovery bundle with the TOFU pin, if
// one exists. A credential store that cannot be read is refused rather than
// treated as "no pin": that distinction is the whole point of the pin.
func checkLocalHydratePin(out io.Writer, platformURL, bundle string) error {
	sum := sha256.Sum256([]byte(bundle))
	got := hex.EncodeToString(sum[:])
	cred, err := auth.LookupAnyIncludingExpired(platformURL)
	if err != nil {
		return fmt.Errorf("read the trust pin for %s: %w", platformURL, err)
	}
	switch {
	case cred == nil || cred.TrustBundleSPKI == "":
		_, _ = fmt.Fprintf(out, "  trust bundle sha256:%s is NOT pinned for %s; compare the certificate fingerprints below with a source you trust before signing\n",
			got, platformURL)
		return nil
	case cred.TrustBundleSPKI == got:
		_, _ = fmt.Fprintf(out, "  trust bundle sha256:%s matches the pin recorded for %s\n", got, platformURL)
		return nil
	default:
		return fmt.Errorf("platform %s now serves a trust bundle (sha256:%s) that differs from the one pinned on first use (sha256:%s); "+
			"refusing to write it into a policy for signing. If the rotation is expected, re-pin with `cilock verify --trust-discovery` (GHSA #5988)",
			platformURL, got, cred.TrustBundleSPKI)
	}
}

// localHydrateEntry partitions a PEM chain exactly as
// hydrate.PartitionCAChain does (the self-signed CA is the root, every other
// parseable certificate an intermediate, in input order) and reports each
// certificate placed.
func localHydrateEntry(slot string, chainPEM []byte) (policy.Root, []localHydratePlaced, error) {
	var root []byte
	var rootPlaced *localHydratePlaced
	var inters [][]byte
	var placed []localHydratePlaced
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		pl := localHydratePlaced{slot: slot, subject: cert.Subject.String(), sha256: hex.EncodeToString(sum[:])}
		certPEM := pem.EncodeToMemory(block)
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			root = certPEM
			pl.role = "root"
			rootPlaced = &pl
			continue
		}
		pl.role = "intermediate"
		inters = append(inters, certPEM)
		placed = append(placed, pl)
	}
	if root == nil {
		return policy.Root{}, nil, fmt.Errorf("no self-signed root certificate found in the chain for %s", slot)
	}
	return policy.Root{Certificate: root, Intermediates: inters}, append([]localHydratePlaced{*rootPlaced}, placed...), nil
}

// localHydrateRemarshal writes only the two trust maps back into the author's
// document, preserving every other key (name, _comment, ...) that the typed
// policy does not model. UseNumber keeps large integers exact.
func localHydrateRemarshal(source string, p *policy.Policy) (string, error) {
	var envelope map[string]any
	dec := json.NewDecoder(bytes.NewReader([]byte(source)))
	dec.UseNumber()
	if err := dec.Decode(&envelope); err != nil {
		return "", fmt.Errorf("parse policy source: %w", err)
	}
	if len(p.Roots) > 0 {
		envelope["roots"] = p.Roots
	}
	if len(p.TimestampAuthorities) > 0 {
		envelope["timestampauthorities"] = p.TimestampAuthorities
	}
	// Compact json.Marshal, exactly as the platform re-marshals, so the same
	// source hydrated here and by the platform yields the same BYTES, not just
	// the same trust entries.
	b, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("re-marshal hydrated policy: %w", err)
	}
	return string(b), nil
}

// localHydrateAssertCertPEM mirrors hydrate.assertCertPEM: exactly one
// CERTIFICATE block, starting a line, with nothing but whitespace around it.
func localHydrateAssertCertPEM(pemBytes []byte) error {
	idx := bytes.Index(pemBytes, localHydrateBeginCertificate)
	if idx < 0 {
		return fmt.Errorf("no CERTIFICATE block found")
	}
	if len(bytes.TrimSpace(pemBytes[:idx])) != 0 {
		return fmt.Errorf("data before the CERTIFICATE block; a trust entry must hold exactly one certificate and nothing else")
	}
	if idx > 0 && pemBytes[idx-1] != '\n' {
		return fmt.Errorf("the CERTIFICATE block must begin a line; leading whitespace on the same line makes these bytes unparseable")
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("not a valid PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("expected CERTIFICATE pem block, got %q", block.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("trailing data after the CERTIFICATE block; a trust entry must hold exactly one certificate")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	return err
}

// localHydrateAssertReferencedRootsPresent mirrors
// hydrate.AssertAllReferencedRootsPresent.
func localHydrateAssertReferencedRootsPresent(p *policy.Policy) error {
	usesWildcard := false
	stepNames := make([]string, 0, len(p.Steps))
	for name := range p.Steps {
		stepNames = append(stepNames, name)
	}
	sort.Strings(stepNames)
	for _, stepName := range stepNames {
		for i, fn := range p.Steps[stepName].Functionaries {
			for _, rootID := range fn.CertConstraint.Roots {
				switch rootID {
				case "":
					continue
				case localHydrateWildcardRootID:
					usesWildcard = true
					continue
				}
				root, ok := p.Roots[rootID]
				if !ok {
					return fmt.Errorf("steps.%s.functionaries[%d].certConstraint.roots references %q, but no such root is defined", stepName, i, rootID)
				}
				if len(root.Certificate) == 0 {
					return fmt.Errorf("steps.%s.functionaries[%d].certConstraint.roots references %q, but roots[%q].certificate is empty", stepName, i, rootID, rootID)
				}
			}
		}
	}
	if !usesWildcard {
		return nil
	}
	if len(p.Roots) == 0 {
		return fmt.Errorf("policy uses wildcard root %q but defines no roots; downstream verification would have an empty trust bundle", localHydrateWildcardRootID)
	}
	for _, name := range localHydrateSortedKeys(p.Roots) {
		if len(p.Roots[name].Certificate) == 0 {
			return fmt.Errorf("policy uses wildcard root %q and roots[%q] has an empty certificate", localHydrateWildcardRootID, name)
		}
	}
	return nil
}

// localHydrateAssertAllTrustParses mirrors hydrate.AssertAllTrustMaterialParses.
func localHydrateAssertAllTrustParses(p *policy.Policy) error {
	if err := localHydrateAssertGroupParses("roots", p.Roots); err != nil {
		return err
	}
	return localHydrateAssertGroupParses("timestampauthorities", p.TimestampAuthorities)
}

func localHydrateAssertGroupParses(kind string, group map[string]policy.Root) error {
	for _, name := range localHydrateSortedKeys(group) {
		entry := group[name]
		if len(entry.Certificate) == 0 {
			if kind == "timestampauthorities" {
				return fmt.Errorf("policy.%s[%q].certificate is empty; a timestamp authority must carry a CERTIFICATE PEM", kind, name)
			}
			continue
		}
		if err := localHydrateAssertCertPEM(entry.Certificate); err != nil {
			return fmt.Errorf("policy.%s[%q].certificate is not a parseable X.509 PEM certificate: %w", kind, name, err)
		}
		for i, inter := range entry.Intermediates {
			if len(inter) == 0 {
				return fmt.Errorf("policy.%s[%q].intermediates[%d] is empty; a chain entry must be a CERTIFICATE PEM", kind, name, i)
			}
			if err := localHydrateAssertCertPEM(inter); err != nil {
				return fmt.Errorf("policy.%s[%q].intermediates[%d] is not a parseable X.509 PEM certificate: %w", kind, name, i, err)
			}
		}
	}
	return nil
}

func localHydrateSortedKeys(m map[string]policy.Root) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
