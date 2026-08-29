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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// policyHydrationVersion is the wire version of the platform's policy-hydration
// contract. It is echoed in the request and expected back in the response; a
// different value means the server is speaking a contract this client does not
// know how to read.
const policyHydrationVersion = "pushgate.policy-hydration.v1"

// policyHydratePath is the platform endpoint that fills a hand-authored policy
// in with the tenant's platform trust roots and timestamp authorities. It is
// mounted on the platform origin, NOT on Archivista or GraphQL, and it is
// resolved from the session's platform URL rather than from the discovery
// document — a discovery doc is untrusted input and must never be able to steer
// the session bearer at another host (#5987).
const policyHydratePath = "/api/pushgate/policies/hydrate"

// policyHydrateTimeout caps the hydration round trip. A var (not a const) so
// tests can shrink it.
var policyHydrateTimeout = 60 * time.Second

// policyHydrateRequest is the request body for POST /api/pushgate/policies/hydrate.
type policyHydrateRequest struct {
	Version     string `json:"version"`
	PayloadType string `json:"payload_type"`
	Source      string `json:"source"`
}

// policyHydrateResponse is the platform's reply. On a refusal, Valid is false,
// Errors carries the reasons, and HydratedSource is absent.
type policyHydrateResponse struct {
	Version             string   `json:"version"`
	TenantID            string   `json:"tenant_id"`
	SourceSHA256        string   `json:"source_sha256"`
	HydratedSource      string   `json:"hydrated_source"`
	HydratedSHA256      string   `json:"hydrated_sha256"`
	Valid               bool     `json:"valid"`
	Errors              []string `json:"errors"`
	EnforcementEligible bool     `json:"enforcement_eligible"`
	// Summary is the other half of the feedback loop: Errors says what the
	// author got wrong, Summary says what the policy they wrote actually does.
	// A pointer, and every render is guarded — an older platform omits it and
	// that is not an error.
	Summary *policyHydrateSummary `json:"summary"`
}

// policyHydrateSummary mirrors the platform's summary shape. Deliberately
// lossy: no rego bodies, no certificate material — enough to see what the
// policy enforces and what is missing, not enough to mistake for the policy.
type policyHydrateSummary struct {
	Requirements []policyHydrateRequirement `json:"requirements"`
	Expires      string                     `json:"expires"`
	Identity     []string                   `json:"identity"`
	Trust        []string                   `json:"trust"`
	Gaps         []string                   `json:"gaps"`
}

type policyHydrateRequirement struct {
	Kind            string `json:"kind"`
	Step            string `json:"step"`
	AttestationType string `json:"attestation_type"`
	RegoPolicyCount int    `json:"rego_policy_count"`
	AIPolicyCount   int    `json:"ai_policy_count"`
}

// policyDraftOpts groups the resolved flag values for `policy draft`.
type policyDraftOpts struct {
	file        string
	output      string
	platformURL string
	datatype    string
	force       bool
}

// PolicyDraftCmd is `cilock policy draft`. It takes a hand-authored policy
// source, asks the platform to hydrate it (fill in the tenant's platform trust
// roots and timestamp authorities), and writes back the hydrated but UNSIGNED
// document plus the exact next steps.
//
// It deliberately does NOT sign, and does not shell out to `cilock sign`.
// Signing a policy is the act that makes it authoritative, and by contract that
// act belongs to a human with their own key/identity — never to a command that
// just fetched something over the network. draft's whole job is to remove the
// one part authors should not have to hand-write (trust roots), and to stop
// there.
//
// Flow: draft (this) → sign (`cilock sign`, human) → push (`cilock policy push`)
// → bind (`cilock policy bind`).
func PolicyDraftCmd() *cobra.Command {
	var o policyDraftOpts

	cmd := &cobra.Command{
		Use:   "draft",
		Short: "Hydrate a hand-authored policy with platform trust roots (unsigned)",
		Long: `draft turns a hand-authored policy source into a complete, verifiable policy
document without you ever looking up a trust root.

You write the part that expresses intent — the steps, the functionaries, the
rego — and leave the trust material out. draft sends that source to the
platform, which fills in the tenant's platform Fulcio roots and timestamp
authorities, validates the result, and returns it. draft verifies the returned
digest against the bytes it actually received, then writes the hydrated
document to --output.

What draft does NOT do is sign it. The hydrated document is inert until a human
signs it, and that is on purpose: signing is what makes a policy authoritative,
so it stays an explicit human act with a human identity. draft never signs and
never invokes ` + "`cilock sign`" + ` for you — it prints the exact command for you
to run.

Auth: a logged-in session with the policy:validate scope. If the platform
rejects the call for a missing scope, run ` + "`cilock login`" + ` again to pick it up.`,
		Example: `  # Hydrate a hand-authored policy — writes policy.hydrated.json, UNSIGNED
  cilock policy draft -f policy.json

  # Then sign it yourself; cilock never signs a policy for you:
  #   cilock sign -f policy.hydrated.json -o policy.hydrated.signed.json

  # Explicit output, overwriting a previous draft
  cilock policy draft -f policy.json -o hydrated.json --force

  # Against a specific platform
  cilock policy draft -f policy.json --platform-url https://platform.testifysec.com`,
		Args:              cobra.NoArgs,
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyDraft(cmd, o)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&o.file, "file", "f", "", "Path to the hand-authored policy source (required)")
	f.StringVarP(&o.output, "output", "o", "",
		"Where to write the hydrated, UNSIGNED policy (default: the source path with a .hydrated.json suffix)")
	f.StringVar(&o.platformURL, "platform-url", "", "TestifySec platform URL (default: the logged-in platform)")
	f.StringVarP(&o.datatype, "datatype", "t", policy.PolicyPredicate, "Policy payload type sent for hydration")
	f.BoolVar(&o.force, "force", false, "Overwrite --output if it already exists")

	_ = cmd.MarkFlagRequired("file")
	return cmd
}

// runPolicyDraft executes the draft flow: resolve the session, read the source,
// hydrate it on the platform, verify the returned digest locally, write the
// hydrated document, then print the human-only next steps.
func runPolicyDraft(cmd *cobra.Command, o policyDraftOpts) error {
	out := cmd.OutOrStdout()

	sess, err := resolvePolicySession(o.platformURL)
	if err != nil {
		return err
	}

	source, err := readPolicySource(o.file)
	if err != nil {
		return err
	}

	output := o.output
	if output == "" {
		output = defaultHydratedOutputPath(o.file)
	}
	// Check the destination BEFORE the network call so an accidental clobber is
	// refused without burning a hydration request.
	if err := ensureWritableOutput(output, o.force); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Hydrating %s against %s ...\n", o.file, sess.platformURL)
	resp, err := hydratePolicySource(cmdContext(cmd), sess, o.datatype, source)
	if err != nil {
		return err
	}
	// REQUIRE the version, do not warn about it. This client can only interpret
	// one contract, and it goes on to WRITE A DOCUMENT FOR SIGNING from fields
	// whose meanings that contract defines. A warning printed to stderr does not
	// stop the write — so under a version whose field meanings differ, the
	// operator is handed a policy to sign that this build read wrongly, with a
	// line of stderr as the only clue. Missing is refused for the same reason:
	// absence is not agreement.
	if resp.Version != policyHydrationVersion {
		got := resp.Version
		if got == "" {
			got = "(none)"
		}
		return fmt.Errorf(
			"platform returned hydration version %s, this build understands only %s — refusing to "+
				"write a policy for signing from a contract it cannot interpret; upgrade cilock",
			got, policyHydrationVersion)
	}
	if !resp.Valid {
		return refusedHydrationError(cmd.ErrOrStderr(), o.file, resp)
	}
	if resp.HydratedSource == "" {
		return fmt.Errorf("platform reported %s valid but returned no hydrated policy", o.file)
	}
	// Never trust a digest you can compute yourself: the bytes we are about to
	// write must hash to the digest the platform claims for them.
	if err := verifyHydratedDigest(resp); err != nil {
		return err
	}
	// And that the response is about the source WE sent. The hydrated digest
	// only proves the response is internally consistent — a stale or misrouted
	// answer carrying its own matching pair passes that check while describing a
	// DIFFERENT policy, which is then written for a human to sign.
	if err := verifySourceDigest(resp, source); err != nil {
		return err
	}
	// And that it was hydrated for OUR tenant. Both digest checks are about the
	// policy bytes; neither says whose trust material was injected into them.
	if err := verifyResponseTenant(resp, sess.cred.TenantID); err != nil {
		return err
	}

	if err := writeHydratedPolicy(output, resp.HydratedSource, o.force); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "\n✓ hydrated %s → %s (UNSIGNED)\n", o.file, output)
	_, _ = fmt.Fprintf(out, "  tenant:   %s\n  source:   sha256:%s\n  hydrated: sha256:%s\n",
		resp.TenantID, resp.SourceSHA256, resp.HydratedSHA256)
	if !resp.EnforcementEligible {
		_, _ = fmt.Fprintf(out, "  note:     not enforcement-eligible yet — it must be signed and published first\n")
	}
	printDraftSummary(out, resp.Summary)
	printDraftNextSteps(out, output, o.datatype)
	return nil
}

// printDraftSummary renders what the hydrated policy enforces.
//
// This is the authoring feedback an agent iterates against: the requirements
// are what the policy demands, identity is who may satisfy them, trust is
// whose roots vouch for that, and gaps are the findings that make the policy
// weaker or more vacuous than its author probably intended.
//
// A platform that does not send a summary renders nothing — an older server is
// not an error, and a silent section is better than a fabricated one.
func printDraftSummary(out io.Writer, summary *policyHydrateSummary) {
	if summary == nil {
		return
	}
	_, _ = fmt.Fprintf(out, "\nWhat this policy does:\n")
	if summary.Expires != "" {
		_, _ = fmt.Fprintf(out, "  expires: %s\n", summary.Expires)
	}
	if len(summary.Requirements) == 0 {
		_, _ = fmt.Fprintf(out, "  (no steps or external attestations — it verifies nothing)\n")
	}
	for _, req := range summary.Requirements {
		line := fmt.Sprintf("  %s %q requires %s", req.Kind, req.Step, req.AttestationType)
		if req.RegoPolicyCount > 0 {
			line += fmt.Sprintf("; %d rego rule(s)", req.RegoPolicyCount)
		}
		if req.AIPolicyCount > 0 {
			line += fmt.Sprintf("; %d ai rule(s)", req.AIPolicyCount)
		}
		_, _ = fmt.Fprintf(out, "%s\n", line)
	}
	for _, line := range summary.Identity {
		_, _ = fmt.Fprintf(out, "  %s\n", line)
	}
	for _, line := range summary.Trust {
		_, _ = fmt.Fprintf(out, "  %s\n", line)
	}
	if len(summary.Gaps) > 0 {
		_, _ = fmt.Fprintf(out, "\nGaps — fix these before this policy is worth signing:\n")
		for _, gap := range summary.Gaps {
			_, _ = fmt.Fprintf(out, "  ! %s\n", gap)
		}
	}
}

// readPolicySource reads the hand-authored policy source. An unreadable source
// is refused before any network call — there is nothing to hydrate.
func readPolicySource(path string) (string, error) {
	if path == "" {
		return "", errors.New("--file is required (the hand-authored policy source to hydrate)")
	}
	data, err := os.ReadFile(path) //nolint:gosec // user-supplied policy path
	if err != nil {
		return "", fmt.Errorf("read policy source %q: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", fmt.Errorf("policy source %q is empty", path)
	}
	return string(data), nil
}

// defaultHydratedOutputPath derives the default --output from the source path:
// the source with its extension replaced by ".hydrated.json", so policy.json
// becomes policy.hydrated.json alongside it.
func defaultHydratedOutputPath(source string) string {
	return strings.TrimSuffix(source, filepath.Ext(source)) + ".hydrated.json"
}

// ensureWritableOutput refuses to clobber an existing --output unless --force.
// A draft is cheap to regenerate; a hand-edited or already-signed file at that
// path is not.
func ensureWritableOutput(path string, force bool) error {
	if force {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("output %q already exists — pass --force to overwrite it, or choose another --output", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat output %q: %w", path, err)
	}
	return nil
}

// hydratePolicySource POSTs the source to the platform's hydration endpoint
// with the login-session bearer and decodes the reply.
func hydratePolicySource(ctx context.Context, sess *policySession, datatype, source string) (*policyHydrateResponse, error) {
	body, err := json.Marshal(policyHydrateRequest{
		Version:     policyHydrationVersion,
		PayloadType: datatype,
		Source:      source,
	})
	if err != nil {
		return nil, fmt.Errorf("encode hydration request: %w", err)
	}

	url := strings.TrimRight(sess.platformURL, "/") + policyHydratePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build hydration request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+sess.cred.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// This request carries the session bearer, and Go's default client follows
	// 30x while RE-SENDING the Authorization header to the new location. A
	// redirect to another host, a subdomain, a different port, or an
	// HTTPS-to-HTTP downgrade would hand the login session to whoever answers
	// there — and the policy source with it.
	//
	// config.SameOriginRedirect is the repository's existing answer to exactly
	// this (its own doc: "Set this on every client that carries the session
	// bearer"), already used by trust.go, policypublish.go and discovery.go. It
	// requires an identical scheme AND host, so a downgrade or a sibling
	// subdomain is refused, and it additionally blocks redirects to non-public
	// IP literals such as 169.254.169.254.
	client := &http.Client{Timeout: policyHydrateTimeout, CheckRedirect: config.SameOriginRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call policy hydration on %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read hydration response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, hydrationStatusError(sess.platformURL, resp.StatusCode, raw)
	}

	var out policyHydrateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse hydration response from %s: %w", url, err)
	}
	return &out, nil
}

// hydrationStatusError maps a non-200 from the hydration endpoint onto an
// actionable message, so the caller learns which remedy applies rather than
// reading a bare status code.
func hydrationStatusError(platformURL string, status int, body []byte) error {
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("not signed in to %s (401) — run `cilock login` first", platformURL)
	case http.StatusForbidden:
		return fmt.Errorf("this session lacks the policy:validate scope for %s (403) — run `cilock login` again to pick it up", platformURL)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("policy hydration is unavailable on %s (503) — retry shortly: %s", platformURL, snippet(body))
	default:
		return fmt.Errorf("policy hydration on %s failed with HTTP %d: %s", platformURL, status, snippet(body))
	}
}

// snippet trims a response body down to something safe to put in an error.
func snippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "(empty response body)"
	}
	const max = 300
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// refusedHydrationError prints each server-reported error on its own line and
// returns a nonzero-exit error. Nothing is written to disk on this path.
func refusedHydrationError(stderr io.Writer, file string, resp *policyHydrateResponse) error {
	_, _ = fmt.Fprintf(stderr, "\n✗ the platform refused to hydrate %s:\n", file)
	if len(resp.Errors) == 0 {
		_, _ = fmt.Fprintln(stderr, "  (the platform reported no error detail)")
	}
	for _, e := range resp.Errors {
		_, _ = fmt.Fprintf(stderr, "  - %s\n", e)
	}
	_, _ = fmt.Fprintln(stderr)
	return fmt.Errorf("policy hydration refused: %d error(s) in %s — fix the source and re-run (nothing was written)",
		len(resp.Errors), file)
}

// verifyHydratedDigest recomputes sha256 over the hydrated document and refuses
// on any mismatch with the digest the platform claims. The digest is the only
// thing standing between "the platform hydrated my policy" and "something in
// the middle handed me a document I am about to sign".
func verifyHydratedDigest(resp *policyHydrateResponse) error {
	sum := sha256.Sum256([]byte(resp.HydratedSource))
	local := hex.EncodeToString(sum[:])
	if !strings.EqualFold(local, resp.HydratedSHA256) {
		return fmt.Errorf(
			"hydrated policy digest mismatch: platform claims sha256:%s, received bytes hash to sha256:%s — refusing to write a document that does not match its own digest",
			resp.HydratedSHA256, local)
	}
	return nil
}

// verifySourceDigest refuses a response that is not about the bytes we sent.
//
// verifyHydratedDigest proves the response agrees with ITSELF. It cannot tell a
// correct answer from a stale or misrouted one that happens to be
// self-consistent, and the difference matters because the result is written for
// a human to sign. Recomputing the SOURCE hash binds the answer to the question.
func verifySourceDigest(resp *policyHydrateResponse, source string) error {
	sum := sha256.Sum256([]byte(source))
	local := hex.EncodeToString(sum[:])
	if !strings.EqualFold(local, resp.SourceSHA256) {
		return fmt.Errorf(
			"hydration response is about a different source: platform echoes sha256:%s, the file "+
				"sent hashes to sha256:%s — refusing a response that does not answer this request",
			resp.SourceSHA256, local)
	}
	return nil
}

// verifyResponseTenant binds the response to the tenant this session is
// authenticated for.
//
// Both digest checks are about the policy BYTES: one proves the response is
// internally consistent, the other that it answers the source we sent. Neither
// says whose trust material was injected into it. Hydration is precisely the
// step that adds a tenant's roots, timestamp authorities and Fulcio chain, so
// identical source hydrated for a DIFFERENT tenant produces a response that
// passes every byte-level check while carrying that tenant's trust into a
// document a human is about to sign — the trust set is exactly the part of a
// hydrated policy a reviewer cannot verify by reading their own source file.
//
// Empty is refused rather than skipped: a response that declines to say which
// tenant it belongs to cannot be attributed, and unattributed is the case this
// check exists to stop.
func verifyResponseTenant(resp *policyHydrateResponse, sessionTenant string) error {
	if resp.TenantID == "" {
		return fmt.Errorf(
			"hydration response names no tenant — refusing to write a policy whose trust material "+
				"cannot be attributed to this session's tenant (%s)", sessionTenant)
	}
	if resp.TenantID != sessionTenant {
		return fmt.Errorf(
			"hydration response is for tenant %s but this session is authenticated for tenant %s — "+
				"refusing to write another tenant's trust material into a policy for signing",
			resp.TenantID, sessionTenant)
	}
	return nil
}

// writeHydratedPolicy writes the hydrated document byte-exact. It re-checks the
// destination so a file that appeared between the pre-flight check and here is
// still not clobbered.
func writeHydratedPolicy(path, content string, force bool) error {
	if err := ensureWritableOutput(path, force); err != nil {
		return err
	}
	// 0644: the hydrated policy is an unsigned, non-secret document — it carries
	// public trust roots and is meant to be reviewed and committed.
	if !force {
		return createHydratedPolicyExclusively(path, content)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // G306: public, unsigned policy document
		return fmt.Errorf("write hydrated policy %q: %w", path, err)
	}
	return nil
}

// createHydratedPolicyExclusively writes the document only if nothing is at the
// path, letting the KERNEL decide rather than a preceding stat.
//
// A stat followed by WriteFile is a race, and the no-clobber promise matters
// precisely when something else is competing for the path: a file — or a
// SYMLINK pointing somewhere else entirely — created in the gap is truncated.
// O_EXCL closes that window and does not follow symlinks.
func createHydratedPolicyExclusively(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G304/G306: caller-chosen path, public unsigned document
	// Flat rather than nested: os.IsExist(nil) is false, so the existence case
	// can be tested before the general one without an enclosing branch.
	if os.IsExist(err) {
		return fmt.Errorf("%s already exists — pass --force to overwrite it", path)
	}
	if err != nil {
		return fmt.Errorf("write hydrated policy %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("write hydrated policy %q: %w", path, err)
	}
	return f.Close()
}

// printDraftNextSteps prints the exact commands that finish the flow. The sign
// step is the human's: cilock will not run it, here or anywhere else.
func printDraftNextSteps(out io.Writer, output, datatype string) {
	signed := strings.TrimSuffix(output, ".json") + ".signed.json"
	_, _ = fmt.Fprintf(out, "\nNext steps — signing is deliberately left to you; cilock will not sign a policy on your behalf:\n")
	_, _ = fmt.Fprintf(out, "  1. review %s, then sign it yourself:\n", output)
	_, _ = fmt.Fprintf(out, "     cilock sign -f %s -o %s -t %s\n",
		shellQuote(output), shellQuote(signed), shellQuote(datatype))
	_, _ = fmt.Fprintf(out, "  2. publish the signed policy:\n")
	_, _ = fmt.Fprintf(out, "     cilock policy push -f %s -d <definition> -t <tag>\n", shellQuote(signed))
}
