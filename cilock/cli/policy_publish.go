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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/spf13/cobra"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// `cilock policy publish` — the ONE-STEP ceremony.
//
// Before this command, publishing a policy was three acts and the middle one
// was impossible for an agent to perform honestly: draft (hydrate), sign
// (a human's key), push (create the release). An agent that ran all three
// signed as whatever session sat on the machine — which is exactly how a
// policy came to be signed at AAL1 with nobody asked (see
// docs/design/policy-publish-ceremony.md in the judge repository).
//
// publish keeps the human's act and removes the hand-off. It hydrates the
// source, starts a device sign-in whose APPROVAL is the exact hydrated
// document's sha256 plus the definition and tag, prints the URL for the
// human, and waits. The human reads what the policy requires on the approve
// page, steps up to a passkey when the tenant requires it, and approves. The
// platform then signs those exact bytes AS THE APPROVER, at the assurance
// level it observed, and creates the release. The agent never holds a key and
// the human never runs a second command.
//
// What this command can NOT do, by construction: publish anything the human
// did not see. The approval is digested by the platform from the bytes the
// page rendered, and the publish endpoint refuses a document whose sha256 is
// not the one inside that approval.
const (
	// policyPublishScope is the approval scope: what the platform grants a
	// sign-in that carries a publish approval, honored only by the bound
	// publish endpoint. Not policy:publish — that is a standing grant the
	// GraphQL publication mutations also honor, and a human approving one
	// document must not be handing this CLI a bearer for any release. The
	// platform grants this scope regardless of what is requested here
	// (RFC 6749 §3.3); requesting it keeps the consent screen honest.
	policyPublishScope   = "sign:policy-approval"
	policyPublishPath    = "/api/pushgate/policies/publish"
	policyPublishKind    = "pushgate.policy-publish.v1"
	policyPublishTimeout = 15 * time.Minute
)

type policyPublishOpts struct {
	file        string
	definition  string
	tag         string
	description string
	platformURL string
	datatype    string
}

// policyPublishApproval mirrors the platform's struct field for field. It is
// what the human is shown and what the platform digests; cilock builds it,
// sends it with the device-code request, and sends it again with the publish
// call, but never computes its digest — a client-claimed digest is not read.
type policyPublishApproval struct {
	Kind         string   `json:"kind"`
	Definition   string   `json:"definition"`
	Tag          string   `json:"tag"`
	PayloadType  string   `json:"payload_type"`
	PolicySHA256 string   `json:"policy_sha256"`
	Summary      []string `json:"summary,omitempty"`
	Description  string   `json:"description,omitempty"`
}

type policyPublishResult struct {
	DefinitionID string `json:"definition_id"`
	Definition   string `json:"definition"`
	ReleaseID    string `json:"release_id"`
	Tag          string `json:"tag"`
	PolicyGitoid string `json:"policy_gitoid"`
	PolicySHA256 string `json:"policy_sha256"`
	ACR          string `json:"acr"`
	// SignerEmail is who the platform signed AS — the human who approved,
	// resolved from the ceremony credential — which is not necessarily the
	// email of the session this command holds.
	SignerEmail string `json:"signer_email"`
	Replayed    bool   `json:"replayed"`
}

// approvalIsForHydration refuses an approval the platform minted for a tenant
// other than the one the document was hydrated for. The hydration is bound
// to the session's tenant (verifyResponseTenant); the human's approval may
// have been granted in any tenant they belong to, and a credential for
// tenant B presented with bytes hydrated for tenant A would publish the
// release in B. The platform reports the tenant it minted for; an approval
// that does not say is not trusted to be the right one.
func approvalIsForHydration(approvedTenant, hydratedTenant string) error {
	switch {
	case hydratedTenant == "":
		return fmt.Errorf("the hydration response named no tenant; refusing to publish")
	case approvedTenant == "":
		return fmt.Errorf("the approval named no tenant; refusing to publish a document hydrated for tenant %s with it", hydratedTenant)
	case approvedTenant != hydratedTenant:
		return fmt.Errorf("the approval was granted in tenant %s but the document was hydrated for tenant %s; approve in the tenant the policy belongs to", approvedTenant, hydratedTenant)
	}
	return nil
}

// publishSignedLine renders who signed, from what the PLATFORM reported. A
// platform that did not name the signer gets the level alone: the session's
// own email is not evidence of who approved.
func publishSignedLine(res *policyPublishResult) string {
	if res.SignerEmail == "" {
		return "at " + res.ACR
	}
	return res.SignerEmail + " at " + res.ACR
}

func PolicyPublishCmd() *cobra.Command {
	var o policyPublishOpts
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Hydrate a policy, ask a human to sign it, and publish the release — one step",
		Long: `publish is draft + sign + push as a single ceremony.

It hydrates the hand-authored source against the platform, then starts a
sign-in whose approval names the exact hydrated document. Your human opens the
printed URL, reads what the policy requires, and approves with a passkey. The
platform signs those exact bytes as them — never as you, never at a lower
assurance than the session it observed — and creates the release.

You do not hold a key and your human does not run a second command. The
release is created Off; turning it on for a repository stays a separate act on
Pushgate.`,
		Example: `  # Publish v1 of judge-gates from a hand-authored source
  cilock policy publish -f deploy/pushgate/judge-gates.policy.json -d judge-gates -t v1`,
		RunE: func(cmd *cobra.Command, _ []string) error { return runPolicyPublish(cmd, o) },
	}
	f := cmd.Flags()
	f.StringVarP(&o.file, "file", "f", "", "Path to the hand-authored policy source (required)")
	f.StringVarP(&o.definition, "definition", "d", "", "PolicyDefinition name; created if it does not exist (required)")
	f.StringVarP(&o.tag, "tag", "t", "", "Release tag, e.g. v1 (required)")
	f.StringVar(&o.description, "description", "", "Description used only when the ceremony creates a new PolicyDefinition")
	f.StringVar(&o.platformURL, "platform-url", "", "TestifySec platform URL (default: the logged-in platform)")
	f.StringVar(&o.datatype, "datatype", policy.PolicyPredicate, "Policy payload type")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("definition")
	_ = cmd.MarkFlagRequired("tag")
	return cmd
}

func runPolicyPublish(cmd *cobra.Command, o policyPublishOpts) error {
	out := cmd.OutOrStdout()
	ctx := cmdContext(cmd)

	sess, err := resolvePolicySession(o.platformURL)
	if err != nil {
		return err
	}
	source, err := readPolicySource(o.file)
	if err != nil {
		return err
	}

	// 1. HYDRATE — the same call `policy draft` makes, so what the human
	// approves is the document the platform itself completed, and the summary
	// on the approve page is the platform's own reading of it.
	_, _ = fmt.Fprintf(out, "Hydrating %s against %s ...\n", o.file, sess.platformURL)
	hyd, err := hydratePolicySource(ctx, sess, o.datatype, source)
	if err != nil {
		return err
	}
	if !hyd.Valid {
		return refusedHydrationError(cmd.ErrOrStderr(), o.file, hyd)
	}
	if hyd.HydratedSource == "" {
		return fmt.Errorf("platform reported %s valid but returned no hydrated policy", o.file)
	}
	if err := verifyHydratedDigest(hyd); err != nil {
		return err
	}
	if err := verifySourceDigest(hyd, source); err != nil {
		return err
	}
	if err := verifyResponseTenant(hyd, sess.cred.TenantID); err != nil {
		return err
	}
	printDraftSummary(out, hyd.Summary)

	// 2. THE APPROVAL — what the human will be shown and what binds their
	// signature. The sha256 is computed over the hydrated bytes this process
	// holds, and step 4 sends those same bytes; the platform refuses the pair
	// if they disagree.
	sum := sha256.Sum256([]byte(hyd.HydratedSource))
	approval := policyPublishApproval{
		Kind:         policyPublishKind,
		Definition:   o.definition,
		Tag:          o.tag,
		PayloadType:  o.datatype,
		PolicySHA256: hex.EncodeToString(sum[:]),
		Summary:      publishSummaryLines(hyd.Summary),
		Description:  o.description,
	}
	approvalJSON, err := json.Marshal(approval)
	if err != nil {
		return err
	}

	// 3. THE HUMAN'S ACT. The device sign-in carries the approval; the
	// platform shows it, gates it at AAL2 when the tenant requires it, and
	// mints a credential bound to the digest of exactly those bytes.
	_, _ = fmt.Fprintf(out, "\nAsk your human to approve this publish:\n")
	approved, err := auth.DeviceApproval(ctx, sess.platformURL, auth.ApprovalRequest{
		ClientID: "cilock",
		Scopes:   []string{policyPublishScope},
		Approval: approvalJSON,
		Timeout:  policyPublishTimeout,
		Prompt: func(userCode, url string) {
			_, _ = fmt.Fprintf(out, "  %s\n  code: %s\n\nWaiting for approval (%s) ...\n", url, userCode, policyPublishTimeout)
		},
	})
	if err != nil {
		return err
	}
	// The approval must be for the tenant the document was hydrated for:
	// the credential decides which tenant the release lands in.
	if err := approvalIsForHydration(approved.TenantID, hyd.TenantID); err != nil {
		return err
	}

	// 4. PUBLISH. The credential signs as the human, for this document only.
	res, err := postPolicyPublish(ctx, sess.platformURL, approved.Token, approvalJSON, hyd.HydratedSource)
	if err != nil {
		return err
	}

	printPublishResult(out, res, sess.platformURL)
	return nil
}

// printPublishResult is the completion block: what was published, the
// signature the PLATFORM reported, and the human's next step. The next step
// names the Pushgate origin the platform advertises in discovery; with no such
// origin there is nowhere to send the human, so the line is omitted rather
// than pointing at a host derived from the platform's name.
func printPublishResult(out io.Writer, res *policyPublishResult, platformURL string) {
	verb := "published"
	if res.Replayed {
		verb = "already published (replayed)"
	}
	_, _ = fmt.Fprintf(out, "\n✓ %s %s %s\n", verb, res.Definition, res.Tag)
	_, _ = fmt.Fprintf(out, "  release:  %s\n  policy:   sha256:%s\n  gitoid:   %s\n  signed:   %s\n",
		res.ReleaseID, res.PolicySHA256, res.PolicyGitoid, publishSignedLine(res))
	if origin := publishNextStepPushgateOrigin(platformURL); origin != "" {
		_, _ = fmt.Fprintf(out, "\nNext: your human turns it on for a repository at %s/policy (Warn first).\n", origin)
	}
}

// publishNextStepPushgateOrigin returns the scheme://host of the Pushgate the
// platform advertises, or "" when discovery fails, advertises none, or
// advertises something that is not a bare secure origin. The result is shown
// to a person as a link, so a path, query or userinfo is refused rather than
// printed.
func publishNextStepPushgateOrigin(platformURL string) string {
	advertised, err := discoverPushgateOrigin(platformURL)
	if err != nil || advertised == "" {
		return ""
	}
	if config.RequireSecurePlatformURL(advertised) != nil {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(advertised))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// publishSummaryLines renders the platform's summary as the lines the approve
// page shows. It is bound by the digest, so it is deliberately the platform's
// own words about the policy, never a description cilock invents.
func publishSummaryLines(s *policyHydrateSummary) []string {
	if s == nil {
		return nil
	}
	lines := make([]string, 0, len(s.Requirements)+len(s.Identity)+len(s.Trust)+1)
	if s.Expires != "" {
		lines = append(lines, "expires "+s.Expires)
	}
	for _, r := range s.Requirements {
		lines = append(lines, fmt.Sprintf("step %s requires %s (%d rego, %d ai)",
			r.Step, r.AttestationType, r.RegoPolicyCount, r.AIPolicyCount))
	}
	lines = append(lines, s.Identity...)
	lines = append(lines, s.Trust...)
	// Never trimmed: the platform re-derives these lines from the bytes and
	// refuses a summary the approve page cannot show whole, so a policy that
	// summarises past the page's limit is refused with the remedy named,
	// not approved from its first page.
	return lines
}

func postPolicyPublish(ctx context.Context, platformURL, bearer string, approval json.RawMessage, hydrated string) (*policyPublishResult, error) {
	body, err := json.Marshal(map[string]any{"approval": approval, "source": hydrated})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(platformURL, "/") + policyPublishPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Same-origin redirects only: this request carries the ceremony credential
	// AND the policy bytes, and Go re-sends Authorization across a redirect.
	client := &http.Client{Timeout: policyHydrateTimeout, CheckRedirect: config.SameOriginRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call policy publish on %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read the publish response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, publishStatusError(platformURL, resp.StatusCode, raw)
	}
	var res policyPublishResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("platform returned an unreadable publish response: %w", err)
	}
	if res.ReleaseID == "" {
		return nil, fmt.Errorf("platform reported success but named no release")
	}
	return &res, nil
}

// publishStatusError renders the platform's structured refusal in its own
// words — the remediation is written for the person who has to act on it.
func publishStatusError(platformURL string, status int, body []byte) error {
	var refusal struct {
		Error       string `json:"error"`
		Remediation string `json:"remediation"`
	}
	if json.Unmarshal(body, &refusal) == nil && refusal.Error != "" {
		if refusal.Remediation != "" {
			return fmt.Errorf("%s refused to publish (%s): %s", platformURL, refusal.Error, refusal.Remediation)
		}
		return fmt.Errorf("%s refused to publish: %s", platformURL, refusal.Error)
	}
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 512 {
		trimmed = trimmed[:512] + "…"
	}
	return fmt.Errorf("publish returned %d from %s: %s", status, platformURL, trimmed)
}
