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

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// Doctor check outcome levels. An agent can branch on these without parsing
// prose; "fail" means a run/upload against this platform will not work as-is.
const (
	doctorPass = "pass"
	doctorWarn = "warn"
	doctorFail = "fail"
	doctorSkip = "skip"
)

// DoctorCheck is one preflight check in the doctor report.
type DoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail | skip
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"` // actionable remediation
}

// DoctorReport is the full preflight result: the platform it probed, the
// per-check outcomes, and a single ok rollup an agent can gate on.
type DoctorReport struct {
	PlatformURL string        `json:"platform_url"`
	OK          bool          `json:"ok"` // false if any check failed
	Checks      []DoctorCheck `json:"checks"`
}

// add appends a check and keeps the OK rollup in sync (any fail flips it).
func (r *DoctorReport) add(c DoctorCheck) {
	if c.Status == doctorFail {
		r.OK = false
	}
	r.Checks = append(r.Checks, c)
}

// DoctorCmd is the dry-run preflight: it answers, without running a build,
// "is my environment sane to attest against this platform?" — logged in?
// platform reachable? what are the Fulcio/TSA/Archivista destinations? will
// the login session actually authorize an upload (same-origin)? Agents love a
// single "is my environment sane" call before a multi-minute run.
//
// It is strictly READ-ONLY: it fetches the unauthenticated discovery document
// and inspects the local credential store. It deliberately does NOT perform a
// throwaway upload — writing test data into a real tenant is a side effect the
// operator didn't ask for. The same-origin + login checks report whether an
// upload WOULD be authorized.
func DoctorCmd() *cobra.Command {
	var platformURL string
	var archivistaServer string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Preflight check: is the environment sane to attest against the platform?",
		Long: `Preflight check (read-only, no build, no upload) of a cilock attestation
environment. Prints a green/red checklist:

  - logged in?            (local credential store)
  - platform reachable?   (.well-known/judge-configuration discovery)
  - Fulcio / TSA / Archivista destinations (derived + discovered)
  - upload authorization?  (login session origin matches Archivista origin)

Use it before a multi-minute 'cilock run' to confirm signing + upload will
work, instead of discovering a misconfiguration after the build. Pass --json
for a machine-readable report an agent can gate on (report.ok).`,
		Example: `  # Check the default hosted platform
  cilock doctor

  # Check a self-hosted / standalone platform, machine-readable
  cilock doctor --platform-url https://judge.example.com --json`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			report := runDoctorChecks(platformURL, archivistaServer)
			out := cmd.OutOrStdout()
			if jsonOut {
				if err := writeDoctorJSON(out, report); err != nil {
					return err
				}
			} else {
				writeDoctorHuman(out, report)
			}
			if !report.OK {
				// Non-zero exit so CI / an agent can gate on the rollup
				// without parsing output.
				return fmt.Errorf("cilock doctor: one or more checks failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL to probe (default "+platformconfig.DefaultPlatformURL+")")
	cmd.Flags().StringVar(&archivistaServer, "archivista-server", "", "Archivista server you intend to upload to (defaults to the platform's own); the upload-auth check compares its origin to your login session")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the preflight report as a single JSON object (report.ok is the rollup to gate on)")
	return cmd
}

// runDoctorChecks executes the read-only preflight and returns a structured
// report. Pure with respect to its side effects beyond the network discovery
// fetch + credential-store read, so the assembly is straightforward to reason
// about. Discovery and credential failures are reported as checks, never
// panics.
func runDoctorChecks(platformURL, archivistaServer string) *DoctorReport {
	resolved := platformURL
	if resolved == "" {
		resolved = platformconfig.DefaultPlatformURL
	}
	pc := platformconfig.Derive(resolved)
	report := &DoctorReport{PlatformURL: pc.PlatformURL, OK: true}

	// 1. Logged in? (local credential store — no network)
	// Resolve through the provider seam with the expiry-INCLUSIVE mode: a usable
	// (ForDisplay) resolve filters out an expired credential and returns nil,
	// which checkLoggedIn would mislabel as "no stored session" (warn) and let
	// preflight pass on an expired login. The doctor must surface expiry as a hard
	// fail, so it needs to see the expired credential. (It must never SIGN with
	// it — checkUploadAuth treats an expired bearer as no bearer.) Resolving (not
	// the LookupAnyIncludingExpired shim) also yields the source + capability
	// posture, which checkLoggedIn prints as session provenance.
	resolvedCred, lookupErr := auth.Resolve(resolved, auth.IncludingExpired)
	var cred *auth.Credential
	posture := ""
	if resolvedCred != nil {
		cred = resolvedCred.Credential
		posture = resolvedCred.Posture()
	}
	checkLoggedIn(report, resolved, cred, posture, lookupErr)

	// 2. Platform reachable + discovery.
	disc, discErr := platformconfig.Discover(resolved)
	checkPlatformReachable(report, discErr)

	// 3. Destinations: derived URLs, cross-checked against discovery when present.
	checkDestinations(report, pc, disc)

	// 4. Upload authorization (same-origin login session vs Archivista origin).
	archivistaTarget := archivistaServer
	if archivistaTarget == "" {
		archivistaTarget = pc.Archivista
	}
	checkUploadAuth(report, cred, archivistaTarget, pc.Archivista)

	return report
}

func checkLoggedIn(report *DoctorReport, platformURL string, cred *auth.Credential, posture string, err error) {
	if err != nil {
		report.add(DoctorCheck{Name: "logged-in", Status: doctorWarn, Detail: fmt.Sprintf("could not read credential store: %v", err)})
		return
	}
	if cred == nil {
		report.add(DoctorCheck{
			Name:   "logged-in",
			Status: doctorWarn,
			Detail: "no stored session for this platform",
			Hint:   fmt.Sprintf("run: cilock login --platform-url %s (a signed upload to a multi-tenant Archivista needs a tenant-scoped session token)", auth.NormalizeURL(platformURL)),
		})
		return
	}
	if cred.Expired() {
		report.add(DoctorCheck{
			Name:   "logged-in",
			Status: doctorFail,
			Detail: "stored session is EXPIRED",
			Hint:   fmt.Sprintf("run: cilock login --platform-url %s", auth.NormalizeURL(platformURL)),
		})
		return
	}
	detail := "session present"
	if cred.AuthMode == auth.AuthModeWorkflowOIDC {
		detail = "workflow identity (GitHub Actions OIDC); signs keyless but a raw workflow identity maps to no tenant — upload needs --enable-archivista with a tenant-authorized path"
	} else if cred.TenantName != "" {
		detail = "session for tenant " + cred.TenantName
		if cred.Email != "" {
			detail += " (" + cred.Email + ")"
		}
	}
	// Append the session provenance (source + capability posture) so the operator
	// can see WHICH source vouched for the session and whether it can pin trust —
	// the property `cilock verify`'s GHSA #5988 gate keys on. Display-only.
	if posture != "" {
		detail += " — " + posture
	}
	report.add(DoctorCheck{Name: "logged-in", Status: doctorPass, Detail: detail})
}

func checkPlatformReachable(report *DoctorReport, err error) {
	if err != nil {
		report.add(DoctorCheck{
			Name:   "platform-reachable",
			Status: doctorFail,
			Detail: fmt.Sprintf("discovery failed: %v", err),
			Hint:   "confirm the platform URL is correct and reachable; discovery is served at /.well-known/judge-configuration (https required except on loopback)",
		})
		return
	}
	report.add(DoctorCheck{Name: "platform-reachable", Status: doctorPass, Detail: "discovery document fetched"})
}

func checkDestinations(report *DoctorReport, pc platformconfig.PlatformConfig, disc *platformconfig.Discovery) {
	report.add(DoctorCheck{Name: "fulcio", Status: doctorPass, Detail: pc.Fulcio})
	report.add(DoctorCheck{Name: "tsa", Status: doctorPass, Detail: pc.TSA})

	archivistaDetail := pc.Archivista
	status := doctorPass
	// Cross-check the derived Archivista against discovery; a mismatch is a
	// loud signal the platform serves it elsewhere than the URL-derivation
	// assumes.
	if disc != nil && disc.ArchivistaURL != "" && !sameOriginDoctor(disc.ArchivistaURL, pc.Archivista) {
		status = doctorWarn
		archivistaDetail = fmt.Sprintf("%s (discovery advertises %s — they differ; pass --archivista-server to match)", pc.Archivista, disc.ArchivistaURL)
	}
	report.add(DoctorCheck{Name: "archivista", Status: status, Detail: archivistaDetail})
}

func checkUploadAuth(report *DoctorReport, cred *auth.Credential, archivistaTarget, platformArchivista string) {
	switch {
	case cred == nil || cred.Token == "" || cred.Expired():
		// No usable session token to attach — not logged in, a workflow
		// identity (which carries no stored bearer), or an EXPIRED session
		// (which would 401 just like a missing one; checkLoggedIn already
		// flagged the expiry as a hard fail).
		report.add(DoctorCheck{
			Name:   "upload-auth",
			Status: doctorWarn,
			Detail: "no session bearer to attach to an Archivista upload",
			Hint:   "a multi-tenant Archivista upload needs a tenant-scoped Judge API token — get one via 'cilock login' (the Fulcio signing token will 401 on /archivista/upload)",
		})
	case !sameOriginDoctor(archivistaTarget, platformArchivista):
		// The session bearer is scoped to the platform's own Archivista and
		// is withheld (fail-closed) when the target origin differs — the
		// silent sameOrigin footgun the spec calls out.
		report.add(DoctorCheck{
			Name:   "upload-auth",
			Status: doctorWarn,
			Detail: fmt.Sprintf("Archivista target %s differs from platform origin %s — the login session bearer will be WITHHELD (fail-closed 401)", archivistaTarget, platformArchivista),
			Hint:   "upload to the platform's own Archivista, or pass an explicit --archivista-headers Authorization for the third-party target",
		})
	default:
		report.add(DoctorCheck{Name: "upload-auth", Status: doctorPass, Detail: "login session will authorize uploads to " + archivistaTarget})
	}
}

// sameOriginDoctor reports whether two URLs share scheme+host. Mirrors the
// options.sameOrigin guard that actually withholds the session bearer, so the
// doctor's prediction matches run-time behavior. A parse failure returns false
// (matching the fail-closed guard).
func sameOriginDoctor(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil || ua.Host == "" {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

func writeDoctorJSON(w io.Writer, report *DoctorReport) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal doctor report: %w", err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write doctor report: %w", err)
	}
	return nil
}

func writeDoctorHuman(w io.Writer, report *DoctorReport) {
	var b strings.Builder
	fmt.Fprintf(&b, "cilock doctor — preflight for %s\n", report.PlatformURL)
	for _, c := range report.Checks {
		fmt.Fprintf(&b, "  %s %-18s %s\n", doctorMark(c.Status), c.Name, c.Detail)
		if c.Hint != "" {
			fmt.Fprintf(&b, "       ↳ %s\n", c.Hint)
		}
	}
	if report.OK {
		b.WriteString("\nOK — environment looks sane to attest against this platform.\n")
	} else {
		b.WriteString("\nNOT OK — at least one check failed; fix the items above before running.\n")
	}
	_, _ = io.WriteString(w, b.String())
}

// doctorMark renders a status glyph for the human checklist.
func doctorMark(status string) string {
	switch status {
	case doctorPass:
		return "✓"
	case doctorWarn:
		return "!"
	case doctorFail:
		return "✗"
	default:
		return "-"
	}
}
