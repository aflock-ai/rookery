// Package platform provides a cilock attestor that binds an attestation to the
// TestifySec platform tenant and product it was produced under, and records
// audit info about the signing identity.
//
// It runs only when a platform session exists (after `cilock login`): it emits
// in-toto subjects `tenant:<id>` and `product:<id>` — the `product:<id>` subject
// is the convention the platform's ingestion autodiscovery matches to create a
// high-confidence Dsse↔Product link, so the attestation shows up under the
// product in the Test Plans tab. When not logged in it is a no-op (SoftError),
// so the attestor is present iff the run is platform-authenticated.
package platform

import (
	"crypto"
	"fmt"
	"os"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/invopop/jsonschema"
)

const (
	// Name is the attestor name; add it to cilock's default attestors so it
	// runs automatically (and no-ops when there's no session).
	Name = "platform"
	// Type is the predicate type URI for the platform binding attestation.
	Type = "https://testifysec.com/attestations/platform/v0.1"
	// RunType: prematerial — the subjects are static platform identifiers, so
	// they can be contributed before materials are collected.
	RunType = attestation.PreMaterialRunType

	// PlatformURLEnv lets `cilock run` tell the attestor which platform session
	// to bind to. Falls back to the default platform when unset.
	PlatformURLEnv = "CILOCK_PLATFORM_URL"
)

// Attestor records the platform tenant/product the attestation was produced
// under plus audit info about the signing identity. The marshaled struct is the
// attestation predicate.
type Attestor struct {
	PlatformURL string `json:"platform_url"`
	TenantID    string `json:"tenant_id,omitempty"`
	TenantName  string `json:"tenant_name,omitempty"`
	ProductID   string `json:"product_id,omitempty"`
	ProductName string `json:"product_name,omitempty"`
	Email       string `json:"email,omitempty"`
	// WorkflowIdentity is true when the run authenticated to the platform via an
	// ambient CI workflow OIDC identity (no `cilock login`). In that mode the
	// tenant/product IDs are unknown client-side — they are resolved server-side
	// from the OIDC credential on upload — so they are omitted here.
	WorkflowIdentity bool   `json:"workflow_identity,omitempty"`
	SignedAt         string `json:"signed_at,omitempty"`
}

// Interface assertions.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// New returns an empty platform attestor.
func New() *Attestor { return &Attestor{} }

// Name returns the attestor name.
func (a *Attestor) Name() string { return Name }

// Type returns the predicate type URI.
func (a *Attestor) Type() string { return Type }

// RunType returns the run phase.
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema returns the JSON schema for the predicate.
func (a *Attestor) Schema() *jsonschema.Schema { return jsonschema.Reflect(&Attestor{}) }

// Attest populates the attestor from the active platform binding. A stored
// session (`cilock login`) gives the full tenant/product binding. Failing that,
// an ambient CI workflow OIDC identity (signalled by `cilock run` setting
// CILOCK_PLATFORM_URL when it authenticates the upload via OIDC) records a
// platform binding without tenant/product — those are resolved server-side from
// the OIDC credential. With neither, it returns a SoftError and is skipped.
func (a *Attestor) Attest(_ *attestation.AttestationContext) error {
	rawPlatformURL := os.Getenv(PlatformURLEnv)
	platformURL := rawPlatformURL
	if platformURL == "" {
		platformURL = config.DefaultPlatformURL
	}

	cred, err := auth.Lookup(platformURL)
	if err != nil {
		return fmt.Errorf("look up platform session: %w", err)
	}
	if cred != nil {
		a.PlatformURL = cred.PlatformURL
		a.TenantID = cred.TenantID
		a.TenantName = cred.TenantName
		a.ProductID = cred.ProductID
		a.ProductName = cred.ProductName
		a.Email = cred.Email
		a.SignedAt = time.Now().UTC().Format(time.RFC3339)
		return nil
	}

	// No stored session. The keyless-CI case: `cilock run` authenticated an upload
	// to the platform's OWN Archivista under an ambient workflow OIDC identity.
	//
	// Trust gate: CILOCK_PLATFORM_URL alone is NOT sufficient — it is an inheritable,
	// user-controllable env var, so a hostile CI step could export it directly and
	// make this attestor stamp a forged platform_url into the signed predicate
	// without the resolver's same-origin check ever running. We additionally require
	// the in-process trust marker that ResolvePlatformDefaults sets (only after it
	// confirmed same-origin + ambient OIDC) and that it matches the URL we are about
	// to bind. An externally-injected env var cannot flip that marker, so it cannot
	// forge a binding on its own. When the marker is present we record the platform
	// binding without inventing tenant/product (the server resolves them from the
	// OIDC credential on upload).
	if rawPlatformURL != "" && auth.WorkflowOIDCAvailable() {
		bound := auth.NormalizeURL(platformURL)
		if trusted, ok := config.TrustedPlatformBinding(); ok && trusted == bound {
			a.PlatformURL = bound
			a.WorkflowIdentity = true
			a.SignedAt = time.Now().UTC().Format(time.RFC3339)
			return nil
		}
		return attestation.NewSoftError("untrusted CILOCK_PLATFORM_URL for ambient workflow binding — skipping platform binding (the binding is set by `cilock run` after a same-origin check, not by a raw environment variable)")
	}

	return attestation.NewSoftError("no platform session — skipping platform binding (run `cilock login`, or in CI grant `id-token: write` for ambient workflow identity)")
}

// Subjects emits the platform tenant/product as in-toto subjects. The
// `testifysec-product:<id>` name is the convention the platform's ingestion
// autodiscovery matches to bind this attestation to the product (HIGH
// confidence); `testifysec-tenant:<id>` is additive self-description. The
// `testifysec-` namespace avoids collision with the in-toto product/material
// attestor vocabulary.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	if a.ProductID != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ProductID), hashes); err == nil {
			subjects[fmt.Sprintf("testifysec-product:%s", a.ProductID)] = ds
		}
	}
	if a.TenantID != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.TenantID), hashes); err == nil {
			subjects[fmt.Sprintf("testifysec-tenant:%s", a.TenantID)] = ds
		}
	}
	return subjects
}
