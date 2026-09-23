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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/cilock/internal/assurance"
	"github.com/aflock-ai/rookery/cilock/internal/canonicaljson"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// `cilock verify --envelope <file>` checks one Pushgate policy-assignment
// approval, the DSSE the platform signs keyless for the approving human.
// Contract: docs/design/approval-page-verify-command.md §1.

const (
	approvalStatementType    = "https://in-toto.io/Statement/v1"
	approvalPredicateType    = "https://pushgate.dev/attestations/policy-assignment-approval/v1"
	maxApprovalEnvelopeBytes = 1 << 20
	approvalDisclaimer       = "This is a signature check only: it does not show that the signer could approve " +
		"this change, that the platform applied it, or that it is still current."
)

// flagPublicKey is verify's --publickey (-k), the policy signer's key.
const flagPublicKey = "publickey"

// envelopeHonouredSignerFlags are the policy-signature flags envelope mode
// applies: the trust anchors and the OIDC issuer (requireApprovalIssuer).
var envelopeHonouredSignerFlags = map[string]bool{
	"policy-ca-roots": true, "policy-ca": true, "policy-ca-intermediates": true,
	"policy-timestamp-servers": true, "policy-fulcio-oidc-issuer": true,
}

// envelopeModeFlags are the verify flags envelope mode honours: the approval,
// the trust to check it under (envelopeHonouredSignerFlags among them), and
// the output format. It refuses every other verify flag by name, one added
// later included, rather than ignore it.
var envelopeModeFlags = func() map[string]bool {
	m := map[string]bool{
		"envelope": true, "format": true, "platform-url": true, flagOffline: true, "trust-discovery": true,
		"no-embedded-trust": true,
	}
	for name := range envelopeHonouredSignerFlags {
		m[name] = true
	}
	return m
}()

// envelopeModeConflicts refuses a positional artifact and every verify flag
// set that envelope mode does not honour. It reads Changed, never a field: a
// session turns Archivista on and defaults --policy-emails to the reader, and
// neither is the operator's choice. An explicit --policy-emails is refused
// (open question 2): ignored, it would read as an approver pin that never ran.
func envelopeModeConflicts(flags *pflag.FlagSet, args []string) error {
	var refused []string
	if len(args) > 0 {
		refused = append(refused, "a positional artifact")
	}
	flags.VisitAll(func(f *pflag.Flag) {
		if !f.Changed || envelopeModeFlags[f.Name] {
			return
		}
		name := "--" + f.Name
		if f.Shorthand != "" {
			name = "-" + f.Shorthand + "/" + name
		}
		refused = append(refused, name)
	})
	if len(refused) == 0 {
		return nil
	}
	msg := "verify --envelope checks one signed approval and takes no policy-verification input; refusing " +
		strings.Join(refused, ", ")
	if flags.Changed("policy-emails") {
		msg += ". --policy-emails does not pin an approver here: the signer is the certificate's one email SAN, " +
			"which predicate.approver.email must name and the output prints"
	}
	return errors.New(msg)
}

// verifyEnvelopeMode refuses policy-verification input before any file,
// session or platform is read (LocalFlags leaves out the root command's -l),
// then resolves the platform defaults, for discovered trust, and verifies.
// runVerifyEnvelope refuses signer pins again on its own (defence in depth):
// both checks read Changed, and ResolvePlatformDefaults writes fields only,
// so a session default is explicit to neither.
func verifyEnvelopeMode(cmd *cobra.Command, vo options.VerifyOptions, args []string) error {
	if err := envelopeModeConflicts(cmd.LocalFlags(), args); err != nil {
		return err
	}
	if err := vo.ResolvePlatformDefaults(cmd); err != nil {
		return err
	}
	return runVerifyEnvelope(vo, cmd.Flags(), cmd.OutOrStdout())
}

type approvalVerdict struct {
	Passed        bool      `json:"passed"`
	Signer        string    `json:"signer"`
	Assurance     string    `json:"assurance"`
	Connection    string    `json:"connection"`
	SubjectDigest string    `json:"subjectDigest"`
	BeforePresets []string  `json:"beforePresets"`
	AfterPresets  []string  `json:"afterPresets"`
	SignedAt      time.Time `json:"signedAt"`
	// recordedACR is predicate.approver.acr, nil when the predicate records
	// none. It is compared with the leaf, never printed.
	recordedACR *string
}

// runVerifyEnvelope never applies the embedded signer identity or the
// session-defaulted --policy-emails: both name a POLICY signer (the release
// workflow, the logged-in reader), not an approver.
func runVerifyEnvelope(vo options.VerifyOptions, flags *pflag.FlagSet, out io.Writer) error {
	if err := refuseEnvelopeSignerFlags(flags); err != nil {
		return err
	}
	env, err := readApprovalEnvelope(vo.EnvelopePath)
	if err != nil {
		return err
	}
	emb, err := loadEmbeddedPolicyTrust(vo)
	if err != nil {
		return err
	}
	trust, err := resolvePolicySignatureTrust(&vo, emb, false)
	if err != nil {
		return err
	}
	if len(trust.roots) == 0 || len(trust.timestampVerifiers) == 0 {
		return errors.New("no trusted root CA and timestamp authority to verify the approval against: pass " +
			"--policy-ca-roots and --policy-timestamp-servers, log in with `cilock login`, or use a release build")
	}
	leaf, signedAt, err := verifyApprovalSignature(env, trust)
	if err != nil {
		return err
	}
	signer, err := approvalHumanSigner(leaf)
	if err != nil {
		return err
	}
	v, approverEmail, err := parseApprovalStatement(env.Payload)
	if err != nil {
		return err
	}
	if approverEmail == "" || !strings.EqualFold(approverEmail, signer) {
		return fmt.Errorf("predicate.approver.email %q does not name the signer %q", approverEmail, signer)
	}
	if err := requireApprovalIssuer(leaf, vo, flags.Changed); err != nil {
		return err
	}
	level, err := approvalAssurance(leaf, v.recordedACR)
	if err != nil {
		return err
	}
	v.Passed, v.Signer, v.Assurance, v.SignedAt = true, signer, level, signedAt.UTC()
	if vo.OutputJSON() {
		return json.NewEncoder(out).Encode(v)
	}
	_, err = fmt.Fprintf(out, "verified: approval signed by %s\n  assurance: %s\n  connection: %s\n  subject: %s\n"+
		"  presets: %q -> %q\n  signed at: %s (RFC 3161 timestamp)\n%s\n",
		approvalDisplay(v.Signer), approvalDisplay(v.Assurance), approvalDisplay(v.Connection), v.SubjectDigest,
		v.BeforePresets, v.AfterPresets, v.SignedAt.Format(time.RFC3339), approvalDisclaimer)
	return err
}

// readApprovalEnvelope admits one DSSE envelope of at most 1 MiB with an
// in-toto payload and exactly one signature (two would leave the signer unclear).
func readApprovalEnvelope(path string) (dsse.Envelope, error) {
	var env dsse.Envelope
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the envelope to verify
	if err != nil {
		return env, err
	}
	defer f.Close() //nolint:errcheck // read-only
	raw, err := io.ReadAll(io.LimitReader(f, maxApprovalEnvelopeBytes+1))
	switch {
	case err != nil:
		return env, err
	case len(raw) > maxApprovalEnvelopeBytes:
		return env, fmt.Errorf("%s is larger than 1 MiB; an approval envelope is a few KiB", path)
	}
	if err := canonicaljson.RejectDuplicateKeys(raw); err != nil {
		return env, fmt.Errorf("%s is not one unambiguous DSSE envelope: %w", path, err)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return env, fmt.Errorf("%s is not a DSSE envelope: %w", path, err)
	}
	if env.PayloadType != intoto.PayloadType {
		return env, fmt.Errorf("envelope payloadType is %q, want %s", env.PayloadType, intoto.PayloadType)
	}
	if len(env.Signatures) != 1 {
		return env, fmt.Errorf("envelope carries %d signatures; an approval carries exactly one", len(env.Signatures))
	}
	return env, nil
}

// refuseEnvelopeSignerFlags refuses, before any file is read, every signer
// constraint the operator set that envelope mode does not apply: --publickey
// and every --policy-* flag but the trust anchors and the issuer, one added
// later included. Ignored, an explicit --policy-emails alice would read as
// "only Alice's approval passes" while Bob's exits 0. Envelope mode does not
// pin an approver (design open question 2, deferred), and the platform leaf
// carries no CN, organization, DNS, URI or build identity to match, so any
// value is refused, even the signer's own. It reads Changed, never a field:
// the session defaults --policy-emails to the reader, not the operator.
func refuseEnvelopeSignerFlags(flags *pflag.FlagSet) error {
	var refused []string
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed && (f.Name == flagPublicKey || (strings.HasPrefix(f.Name, "policy-") && !envelopeHonouredSignerFlags[f.Name])) {
			refused = append(refused, "--"+f.Name)
		}
	})
	if len(refused) == 0 {
		return nil
	}
	return fmt.Errorf("verify --envelope does not pin a signer; refusing %s. The approval's signer is its certificate's one "+
		"email SAN, which predicate.approver.email must name and the output prints: compare that with the approver you expect",
		strings.Join(refused, ", "))
}

// verifyApprovalSignature never passes dsse.VerifyWithCurrentTimeFallback:
// the leaf lives minutes, so only the TSA's time may carry it. A rotated root
// fails exactly like a changed byte, so the message never guesses which.
func verifyApprovalSignature(env dsse.Envelope, trust policySignatureTrust) (*x509.Certificate, time.Time, error) {
	const failed = "the approval's signature does not chain to the trusted roots under a trusted timestamp"
	checked, err := env.Verify(dsse.VerifyWithRoots(trust.roots...), dsse.VerifyWithIntermediates(trust.intermediates...),
		dsse.VerifyWithTimestampVerifiers(trust.timestampVerifiers...))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", failed, err)
	}
	for _, c := range checked {
		if x, ok := c.Verifier.(*cryptoutil.X509Verifier); ok && c.Error == nil && len(c.VerifiedTimestamps) > 0 {
			return x.Certificate(), c.VerifiedTimestamps[0], nil
		}
	}
	return nil, time.Time{}, errors.New(failed)
}

// approvalHumanSigner returns the leaf's one email SAN. Agent leaves chain to
// the same root with a SPIFFE URI SAN (judge-api/pkg/fulcioca/agent_principal.go)
// and `cilock sign` signs any bytes, so an agent could sign an approval.
func approvalHumanSigner(leaf *x509.Certificate) (string, error) {
	if len(leaf.URIs) > 0 {
		return "", fmt.Errorf("the approval is signed by an agent principal, not a human (certificate URI SAN %q)", leaf.URIs[0].String())
	}
	if len(leaf.EmailAddresses) != 1 || len(leaf.DNSNames) > 0 || len(leaf.IPAddresses) > 0 {
		return "", fmt.Errorf("the approval's certificate must name exactly one email address and nothing else (%d email, %d DNS, %d IP SANs)",
			len(leaf.EmailAddresses), len(leaf.DNSNames), len(leaf.IPAddresses))
	}
	return leaf.EmailAddresses[0], nil
}

// requireApprovalIssuer enforces an explicit --policy-fulcio-oidc-issuer, else
// the logged-in platform's discovered (email) issuer. The flag's GitHub
// Actions default is never applied: the platform Fulcio issues approvals.
func requireApprovalIssuer(leaf *x509.Certificate, vo options.VerifyOptions, flagChanged func(string) bool) error {
	want := vo.PolicyFulcioCertExtensions.Issuer
	if want == "" || (!flagChanged("policy-fulcio-oidc-issuer") && !vo.PolicyFulcioIssuerDiscovered) {
		return nil
	}
	exts, err := certificate.ParseExtensions(leaf.Extensions)
	if err != nil {
		return fmt.Errorf("read the approval certificate's Fulcio extensions: %w", err)
	}
	if exts.Issuer != want {
		return fmt.Errorf("the approval certificate was issued for OIDC issuer %q, not %q", exts.Issuer, want)
	}
	return nil
}

// approvalAssurance reports the level the leaf records. When the predicate
// records one too (approver.acr, v5; the platform refuses it on earlier
// versions), the two must name the same known level. A leaf without the
// extension is "not recorded", never read as a level.
func approvalAssurance(leaf *x509.Certificate, recorded *string) (string, error) {
	acr, present, err := assurance.FromLeaf(leaf)
	level := assurance.ShortAAL(acr)
	shown := level
	switch {
	case err != nil:
		shown = "unreadable"
	case !present:
		shown = "not recorded"
	case level == "":
		shown = fmt.Sprintf("unrecognised %q", acr)
	}
	if recorded != nil && (level == "" || *recorded != level) {
		return "", fmt.Errorf("predicate.approver.acr records %q, but the approval certificate's assurance is %s", *recorded, shown)
	}
	return shown, nil
}

// parseApprovalStatement reads the payload by EXACT key (encoding/json
// matches struct fields case-insensitively, so "Predicate" would stand in for
// "predicate") and recomputes the sealed digest itself, never trusting the
// platform's check. It returns the verdict's statement fields and the
// predicate's approver email.
func parseApprovalStatement(payload []byte) (approvalVerdict, string, error) {
	var v approvalVerdict
	if err := canonicaljson.RejectAmbiguous(payload); err != nil {
		return v, "", fmt.Errorf("the approval statement is ambiguous: %w", err)
	}
	var x exactJSON
	top := x.object(payload, "statement")
	if typ, pt := x.str(top, "_type"), x.str(top, "predicateType"); typ != approvalStatementType || pt != approvalPredicateType {
		return v, "", fmt.Errorf("not a Pushgate policy-assignment approval: _type %q, predicateType %q", typ, pt)
	}
	var subjects []json.RawMessage
	if err := json.Unmarshal(top["subject"], &subjects); err != nil || len(subjects) != 1 {
		return v, "", errors.New("an approval statement carries exactly one subject")
	}
	subject := x.object(subjects[0], "subject")
	digest := x.object(subject["digest"], "subject digest")
	name, sha := x.str(subject, "name"), x.str(digest, "sha256")
	predicate := x.object(top["predicate"], "predicate")
	approver := x.object(predicate["approver"], "predicate.approver")
	approverEmail := x.str(approver, "email")
	if _, ok := approver["acr"]; ok {
		acr := x.str(approver, "acr")
		v.recordedACR = &acr
	}
	sealed := x.object(predicate["sealed"], "predicate.sealed")
	v.Connection = x.str(sealed, "connection_id")
	if x.err != nil {
		return v, "", x.err
	}
	if len(digest) != 1 {
		return v, "", errors.New("the subject digest must name sha256 and nothing else")
	}
	want, err := canonicaljson.Digest(predicate["sealed"])
	if err != nil {
		return v, "", fmt.Errorf("predicate.sealed: %w", err)
	}
	if sha != want {
		return v, "", fmt.Errorf("the subject digest sha256:%s is not the digest of predicate.sealed (sha256:%s)", sha, want)
	}
	if v.Connection != name {
		return v, "", fmt.Errorf("the subject %q is not the sealed connection %q", name, v.Connection)
	}
	for key, dst := range map[string]*[]string{"before_presets": &v.BeforePresets, "after_presets": &v.AfterPresets} {
		if raw, ok := sealed[key]; ok {
			if err := json.Unmarshal(raw, dst); err != nil {
				return v, "", fmt.Errorf("predicate.sealed.%s: %w", key, err)
			}
		}
	}
	v.SubjectDigest = "sha256:" + sha
	return v, approverEmail, nil
}

// exactJSON reads objects by exact key. The first failure sticks, so a chain
// of reads is checked once; an absent key and null are both refused.
type exactJSON struct{ err error }

func (x *exactJSON) object(raw json.RawMessage, what string) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); x.err == nil && (err != nil || m == nil) {
		x.err = fmt.Errorf("the approval's %s is not a JSON object", what)
	}
	return m
}

func (x *exactJSON) str(m map[string]json.RawMessage, key string) string {
	var s *string
	if err := json.Unmarshal(m[key], &s); err != nil || s == nil {
		if x.err == nil {
			x.err = fmt.Errorf("the approval's %s is not a string", key)
		}
		return ""
	}
	return *s
}

// approvalDisplay quotes a signed string that would otherwise write control
// characters to the reader's terminal.
func approvalDisplay(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return strconv.Quote(s)
	}
	return s
}
