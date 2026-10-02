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
	"fmt"
	"io"

	"github.com/aflock-ai/rookery/attestation/policy"
)

// trustPlatformTSAFlag is the explicit, operator-designated TSA trust option
// on the authoring commands (#7709).
const trustPlatformTSAFlag = "trust-platform-tsa"

const trustPlatformTSAUsage = "Anchor the platform's TSA root in timestampauthorities[\"" + localHydrateTSAID + "\"], " +
	"fetched over https from the platform's own discovery document (tsa_cert_chain_url, same origin only) " +
	"and checked against the trust pin `cilock verify` recorded. The TSA certificates embedded in the " +
	"evidence are never trusted, with or without this flag."

// finishStarterTSA settles timestampauthorities[] on a generated starter
// policy. With no platform named it only warns, exactly as before: evidence
// cannot vouch for its own signing time (#5989), so nothing is anchored.
//
// With a platform named (--trust-platform-tsa) it anchors THAT platform's TSA
// root, through the same path `cilock policy draft --hydrate-local` fills the
// platform-tsa slot with (hydrateFromDiscovery): https or loopback only, the
// chain URL on the platform's own origin, and the discovery trust bundle
// checked against the trust-on-first-use pin. RFC 5280 section 6.1.1 (d):
// "The trust anchor information is trusted because it was delivered to the
// path processing procedure by some trustworthy out-of-band procedure." The
// out-of-band procedure is the operator naming the platform; the evidence's
// own TSA certificates take no part in it.
func finishStarterTSA(stderr io.Writer, p *policy.Policy, summaries []bundleSummary, tsaPlatformURL string) error {
	if tsaPlatformURL == "" {
		warnMissingTimestampAuthorities(stderr, p, summaries)
		return nil
	}
	if existing, ok := p.TimestampAuthorities[localHydrateTSAID]; ok && len(existing.Certificate) > 0 {
		return fmt.Errorf("--%s: timestampauthorities[%q] is already set; refusing to replace it", trustPlatformTSAFlag, localHydrateTSAID)
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if p.TimestampAuthorities == nil {
		p.TimestampAuthorities = map[string]policy.Root{}
	}
	_, _ = fmt.Fprintf(stderr, "Anchoring the TSA root published by %s (--%s) ...\n", tsaPlatformURL, trustPlatformTSAFlag)
	placed, err := hydrateFromDiscovery(stderr, tsaPlatformURL, p, localHydratePlan{fillTSA: true})
	if err != nil {
		delete(p.TimestampAuthorities, localHydrateTSAID)
		return fmt.Errorf("--%s: %w", trustPlatformTSAFlag, err)
	}
	if err := localHydrateAssertAllTrustParses(p); err != nil {
		return fmt.Errorf("--%s: %w", trustPlatformTSAFlag, err)
	}
	_, _ = fmt.Fprintf(stderr, "Placed TSA certificates (review these before you sign):\n")
	for _, pl := range placed {
		_, _ = fmt.Fprintf(stderr, "  %-38s %-12s %s\n  %-38s %-12s sha256:%s\n", pl.slot, pl.role, pl.subject, "", "", pl.sha256)
	}
	return nil
}
