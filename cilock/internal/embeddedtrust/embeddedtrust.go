// Package embeddedtrust exposes policy-signing trust compiled into the cilock
// binary at build time. It pins ONLY policy trust — the roots and signer
// identity allowed to sign a policy — never attestation trust. Attestation
// trust is always defined by the (now-trusted) policy itself; see
// docs/design/cilock-baked-policy-trust.md.
//
// The committed default (trust.json = `{}`) embeds nothing, so a stock cilock
// behaves exactly as before and still requires --policy-ca-roots / --policy-*.
// A purpose-built cilock (e.g. for self-host-minimal) ships a trust.json with
// the Sigstore Fulcio + TSA roots and the trusted policy-signer Functionary,
// collapsing the customer verify command to `cilock verify <art> --policy --attestations`.
package embeddedtrust

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// trust.json is the compiled-in trust document. The committed default is `{}`
// (no embedded trust). Builders overwrite it before `go build` to bake roots
// and a policy signer into a specific cilock distribution.
//
//go:embed trust.json
var trustJSON []byte

const (
	KindFulcioRoot = "FULCIO_ROOT"
	KindTSARoot    = "TSA_ROOT"
)

// Root is a named trust-root bundle, mirroring the TrustSource entity's
// (name, kind, pem) shape.
type Root struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	PEM  string `json:"pem"`
}

// Trust is the compiled-in policy-signing trust. PolicySigners are
// policy.Functionary values verbatim — the same shape the policy uses for its
// per-step functionaries — so there is no parallel trust model to review.
type Trust struct {
	// Source is the platform URL whose Fulcio + TSA trust was baked in (e.g.
	// https://platform.testifysec.com). Provenance only — it makes the embedded
	// trust auditable via `cilock version` so a user can see WHICH platform a
	// binary trusts (prod vs staging) rather than it being implicit. Optional.
	Source         string               `json:"source,omitempty"`
	Roots          []Root               `json:"roots"`
	PolicySigners  []policy.Functionary `json:"policy_signers"`
	PolicyTSARoots []string             `json:"policy_timestamp_roots,omitempty"`
}

// Load returns the trust compiled into this binary, or (nil, nil) when the
// binary was built with the empty default (nothing embedded).
func Load() (*Trust, error) {
	return parse(trustJSON)
}

// parse decodes a trust document, returning (nil, nil) when it is empty/`{}` or
// carries no roots and no signers. Rejects unknown keys so a typo in a baked
// trust document fails the build's verify gate loudly rather than silently
// trusting less than intended.
func parse(raw []byte) (*Trust, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "{}" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	var t Trust
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("parse embedded trust.json: %w", err)
	}
	if len(t.Roots) == 0 && len(t.PolicySigners) == 0 {
		return nil, nil
	}
	return &t, nil
}

// FulcioRoots parses the embedded FULCIO_ROOT bundles into x509 certs for use
// as the policy-signature CA root pool.
func (t *Trust) FulcioRoots() ([]*x509.Certificate, error) {
	return t.rootsOfKind(KindFulcioRoot, nil)
}

// TSARoots parses the embedded TSA_ROOT bundles used to anchor the policy
// signature's RFC3161 timestamp. When PolicyTSARoots is non-empty it selects
// only those roots by name; otherwise all TSA_ROOT bundles are returned.
func (t *Trust) TSARoots() ([]*x509.Certificate, error) {
	var filter map[string]struct{}
	if len(t.PolicyTSARoots) > 0 {
		filter = make(map[string]struct{}, len(t.PolicyTSARoots))
		for _, n := range t.PolicyTSARoots {
			filter[n] = struct{}{}
		}
	}
	return t.rootsOfKind(KindTSARoot, filter)
}

// Summary loads the trust compiled into this binary and renders it as human
// lines for `cilock version`, or (nil, nil) when nothing is embedded. This is
// the explicit-disclosure surface: a baked binary states exactly which platform
// trust it carries instead of it being invisible until a verify runs.
func Summary() ([]string, error) {
	t, err := Load()
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, nil
	}
	return t.Describe()
}

// Describe renders the policy-signing trust as auditable lines: the source
// platform, the Fulcio CA + TSA roots (count + SPKI fingerprints, matching the
// platform PKI docs' first-8-hex-of-sha256(SubjectPublicKeyInfo) convention so a
// user can cross-check), and the pinned policy-signer identity.
func (t *Trust) Describe() ([]string, error) {
	var lines []string
	if t.Source != "" {
		lines = append(lines, fmt.Sprintf("Source platform: %s", t.Source))
	}
	fr, err := t.FulcioRoots()
	if err != nil {
		return nil, err
	}
	lines = append(lines, fmt.Sprintf("Fulcio CA roots: %d%s", len(fr), spkiSuffix(fr)))
	tr, err := t.TSARoots()
	if err != nil {
		return nil, err
	}
	lines = append(lines, fmt.Sprintf("TSA roots:       %d%s", len(tr), spkiSuffix(tr)))
	for _, f := range t.PolicySigners {
		cc := f.CertConstraint
		signer := strings.Join(cc.Emails, ", ")
		if signer == "" {
			signer = "(no email constraint)"
		}
		if iss := cc.Extensions.Issuer; iss != "" {
			lines = append(lines, fmt.Sprintf("Policy signer:   %s (issuer %s)", signer, iss))
		} else {
			lines = append(lines, fmt.Sprintf("Policy signer:   %s", signer))
		}
	}
	return lines, nil
}

// spkiSuffix renders a "(SPKI ab12cd34, ...)" tail of per-cert public-key
// fingerprints (first 4 bytes of sha256(SubjectPublicKeyInfo)), or "" when empty.
func spkiSuffix(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	fps := make([]string, 0, len(certs))
	for _, c := range certs {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		fps = append(fps, hex.EncodeToString(sum[:4]))
	}
	return " (SPKI " + strings.Join(fps, ", ") + ")"
}

func (t *Trust) rootsOfKind(kind string, nameFilter map[string]struct{}) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, r := range t.Roots {
		if r.Kind != kind {
			continue
		}
		if nameFilter != nil {
			if _, ok := nameFilter[r.Name]; !ok {
				continue
			}
		}
		cert, err := cryptoutil.TryParseCertificate([]byte(r.PEM))
		if err != nil {
			return nil, fmt.Errorf("embedded %s root %q: %w", kind, r.Name, err)
		}
		out = append(out, cert)
	}
	return out, nil
}
