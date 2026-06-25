package options

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// Package note — `cilock trust`:
//
// trust registers an OIDC *federated* identity the platform will trust for
// attestation upload (the createCredential mutation, type=OIDC). It NEVER
// creates an OAUTH/API-token (a long-lived bearer secret) — keyless federation
// is the whole point, so there is no secret-minting path through cilock.
//
// The same binary that mints the CI token (`cilock run`) registers what to trust
// here, so the subject + audience can't drift: the audience defaults to the same
// `${platform}/archivista` cilock run uses, and the subject is templated from the
// provider's claim convention. That alignment is what prevents the "token maps
// to no tenant -> 401 on upload" class of failure.

// TrustCredentialType is the only credential type trust ever creates. cilock
// deliberately cannot mint OAUTH (secret-bearing) credentials.
const TrustCredentialType = "OIDC"

// DefaultTrustScopes is the least-privilege scope set for a CI signer/uploader:
// just upload. `--verify` adds attestation:read (needed by `cilock verify
// --enable-archivista`, which searches Archivista by subject).
var DefaultTrustScopes = []string{"attestation:upload"}

// Provider captures a CI/OIDC provider's conventions for turning a repository
// slug into an OIDC issuer URL and a subject-claim glob. Adding a provider is a
// single map entry — the platform side is provider-agnostic (issuer+subject+
// audience), so no server change is needed for a new provider.
type Provider struct {
	Name string
	// saasIssuer is the hosted provider's public OIDC issuer.
	saasIssuer string
	// onPremIssuer formats the issuer for a self-hosted instance from --host;
	// the single %s is the host (e.g. "github.acme.com").
	onPremIssuer string
	// subjectGlob formats the OIDC subject-match glob from the slug; the single
	// %s is the slug (e.g. "testifysec/judge").
	subjectGlob string
	// exactSegments is the required number of "/"-separated slug segments, or 0
	// to allow any count >= 2 (e.g. GitLab nested groups: group/subgroup/proj).
	exactSegments int
	// slugLabel is what the slug is called in help/errors for this provider.
	slugLabel string
}

// Provider name constants — used as the providers map keys, the Provider.Name
// values, and in ParseOriginRemote's host-based inference.
const (
	providerGitHub = "github"
	providerGitLab = "gitlab"
)

// providers is the built-in registry. Order is irrelevant; KnownProviders sorts.
var providers = map[string]Provider{
	providerGitHub: {
		Name:          providerGitHub,
		saasIssuer:    "https://token.actions.githubusercontent.com",
		onPremIssuer:  "https://%s/_services/token", // GitHub Enterprise Server
		subjectGlob:   "repo:%s:*",
		exactSegments: 2,
		slugLabel:     "owner/repo",
	},
	providerGitLab: {
		Name:          providerGitLab,
		saasIssuer:    "https://gitlab.com",
		onPremIssuer:  "https://%s",
		subjectGlob:   "project_path:%s:*",
		exactSegments: 0, // nested groups allowed
		slugLabel:     "group/project",
	},
}

// KnownProviders returns the sorted provider names for help and error text.
func KnownProviders() []string {
	names := make([]string, 0, len(providers))
	for n := range providers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// slugRe matches a repo slug: 2+ segments separated by "/", each non-empty and
// free of whitespace and slashes. Rejects schemes, .git suffixes, and
// leading/trailing slashes by construction.
var slugRe = regexp.MustCompile(`^[^/\s]+(?:/[^/\s]+)+$`)

// TrustOptions are the resolved inputs for `cilock trust`. Either Provider+Slug
// (the ergonomic path) or Issuer+Subject (the generic escape hatch) must be set.
type TrustOptions struct {
	PlatformURL string

	// Provider-shorthand path.
	Provider string // e.g. providerGitHub
	Slug     string // e.g. "testifysec/judge"
	Host     string // on-prem instance host, e.g. "github.acme.com"

	// Generic escape-hatch path (any OIDC provider).
	Issuer  string
	Subject string

	// Common.
	Audience    string
	Scopes      []string
	AllowedIPs  []string
	Tags        []string
	Name        string
	Description string
	TenantID    string
	Verify      bool // also grant attestation:read
}

// ResolvedTrust is the validated, fully-derived credential to create.
type ResolvedTrust struct {
	Name       string
	Subject    string
	Audience   string
	IssuerURL  string
	Scopes     []string
	Tags       []string
	AllowedIPs []string
	TenantID   string
}

// resolveIdentity fills r.IssuerURL, r.Subject and o.Name from either the
// provider shorthand (--<provider> <slug>) or the generic --issuer/--subject
// pair, validating the inputs along the way.
func (o *TrustOptions) resolveIdentity(r *ResolvedTrust) error {
	switch {
	case o.Provider != "":
		p, ok := providers[strings.ToLower(o.Provider)]
		if !ok {
			return fmt.Errorf("unknown provider %q (known: %s); or use --issuer + --subject for a custom provider",
				o.Provider, strings.Join(KnownProviders(), ", "))
		}
		if o.Slug == "" {
			return fmt.Errorf("%s repository required, as %q (e.g. %s)", p.Name, p.slugLabel, exampleSlug(p))
		}
		if err := validateSlug(p, o.Slug); err != nil {
			return err
		}
		r.IssuerURL = deriveIssuer(p, o.Host)
		r.Subject = fmt.Sprintf(p.subjectGlob, o.Slug)
		if o.Name == "" {
			o.Name = p.Name + ":" + o.Slug
		}
	case o.Issuer != "" && o.Subject != "":
		if err := validateIssuer(o.Issuer); err != nil {
			return err
		}
		r.IssuerURL = strings.TrimRight(o.Issuer, "/")
		r.Subject = o.Subject
		if o.Name == "" {
			o.Name = "oidc:" + hostOf(o.Issuer)
		}
	default:
		return fmt.Errorf("specify a provider + repository (e.g. `cilock trust github %s`) or --issuer + --subject", "owner/repo")
	}
	r.Name = o.Name
	return nil
}

// Resolve derives the issuer, subject, audience, scopes, and name from the
// options and validates them. defaultTenantID is the logged-in working tenant
// (used when --tenant is not given). It does not perform any network call.
func (o *TrustOptions) Resolve(defaultTenantID string) (*ResolvedTrust, error) {
	r := &ResolvedTrust{
		Tags:       o.Tags,
		AllowedIPs: o.AllowedIPs,
	}

	if err := o.resolveIdentity(r); err != nil {
		return nil, err
	}

	// Audience — default to the same archivista origin `cilock run` mints for,
	// derived from --platform-url. This alignment is the anti-drift guarantee.
	r.Audience = o.Audience
	if r.Audience == "" {
		base := auth.NormalizeURL(o.PlatformURL)
		if base == "" {
			return nil, fmt.Errorf("--audience required when --platform-url is empty")
		}
		r.Audience = base + "/archivista"
	}

	// Scopes — least privilege. Never silently grant management scopes.
	r.Scopes = o.Scopes
	if len(r.Scopes) == 0 {
		r.Scopes = append([]string{}, DefaultTrustScopes...)
		if o.Verify {
			r.Scopes = append(r.Scopes, "attestation:read")
		}
	}
	if err := guardScopes(r.Scopes); err != nil {
		return nil, err
	}

	// Tenant.
	r.TenantID = o.TenantID
	if r.TenantID == "" {
		r.TenantID = defaultTenantID
	}
	if r.TenantID == "" {
		return nil, fmt.Errorf("no tenant: pass --tenant <id> or run `cilock login` to select one")
	}

	return r, nil
}

// guardScopes refuses to mint a federated credential carrying management or
// admin scopes — `cilock trust` only ever grants attestation evidence scopes.
// This caps the blast radius of the credential and of the oidc:write capability
// that creates it (no privilege escalation, no self-replication of trust).
func guardScopes(scopes []string) error {
	allowed := map[string]bool{
		"attestation:upload": true,
		"attestation:read":   true,
		"attestation:verify": true,
	}
	for _, s := range scopes {
		if !allowed[s] {
			return fmt.Errorf("scope %q is not allowed for `cilock trust`: federated CI credentials may only carry attestation:{upload,read,verify} — not management/admin scopes", s)
		}
	}
	return nil
}

func deriveIssuer(p Provider, host string) string {
	if host == "" {
		return p.saasIssuer
	}
	return fmt.Sprintf(p.onPremIssuer, strings.TrimSpace(host))
}

func validateSlug(p Provider, slug string) error {
	if !slugRe.MatchString(slug) {
		return fmt.Errorf("invalid %s repository %q: want %q (no scheme, no .git, no trailing slash) — e.g. %s",
			p.Name, slug, p.slugLabel, exampleSlug(p))
	}
	if p.exactSegments > 0 && strings.Count(slug, "/")+1 != p.exactSegments {
		return fmt.Errorf("invalid %s repository %q: want exactly %q — e.g. %s", p.Name, slug, p.slugLabel, exampleSlug(p))
	}
	return nil
}

func validateIssuer(issuer string) error {
	// Require https:// only. OIDC issuer URLs are dereferenced server-side for
	// discovery/JWKS, so an http:// (or scheme-relative) issuer is an insecure
	// trust root / SSRF vector — reject it client-side too (the platform's
	// createCredential independently enforces ValidateExternalHTTPSURL).
	if !strings.HasPrefix(issuer, "https://") {
		return fmt.Errorf("--issuer %q must be an absolute https:// URL", issuer)
	}
	return nil
}

func exampleSlug(p Provider) string {
	switch p.Name {
	case providerGitLab:
		return "gitlab acme/app"
	default:
		return "github testifysec/judge"
	}
}

func hostOf(rawurl string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(rawurl, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ParseOriginRemote derives (provider, slug) from a `git remote get-url origin`
// value. Recognises both SSH (git@github.com:owner/repo.git) and HTTPS
// (https://github.com/owner/repo(.git)) forms for the built-in providers. The
// returned host is non-empty for a non-SaaS host (so the caller can pass --host).
func ParseOriginRemote(remote string) (provider, slug, host string, err error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", "", "", fmt.Errorf("empty remote URL")
	}
	var h, path string
	switch {
	case strings.HasPrefix(remote, "git@"), strings.Contains(remote, "@") && strings.Contains(remote, ":") && !strings.Contains(remote, "://"):
		// scp-like: [user@]host:owner/repo(.git)
		at := strings.LastIndex(remote, "@")
		rest := remote[at+1:]
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			return "", "", "", fmt.Errorf("unrecognised SSH remote %q", remote)
		}
		h, path = rest[:colon], rest[colon+1:]
	case strings.Contains(remote, "://"):
		// scheme://[user@]host/owner/repo(.git)
		rest := remote[strings.Index(remote, "://")+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		sl := strings.IndexByte(rest, '/')
		if sl < 0 {
			return "", "", "", fmt.Errorf("unrecognised remote %q", remote)
		}
		h, path = rest[:sl], rest[sl+1:]
	default:
		return "", "", "", fmt.Errorf("unrecognised remote %q", remote)
	}

	h = strings.TrimSuffix(h, ":443")
	slug = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if slug == "" {
		return "", "", "", fmt.Errorf("could not extract repository from remote %q", remote)
	}

	switch {
	case h == "github.com":
		return providerGitHub, slug, "", nil
	case h == "gitlab.com":
		return providerGitLab, slug, "", nil
	case strings.HasPrefix(h, "github."), strings.Contains(h, providerGitHub):
		return providerGitHub, slug, h, nil // GHES on-prem
	case strings.HasPrefix(h, "gitlab."), strings.Contains(h, providerGitLab):
		return providerGitLab, slug, h, nil // self-hosted GitLab
	default:
		// Unknown host: hand back the slug + host; caller must pick a provider.
		return "", slug, h, fmt.Errorf("could not infer provider from host %q; specify it: cilock trust <provider> %s --host %s", h, slug, h)
	}
}

// --- platform GraphQL: createCredential (type=OIDC) ---

const createCredentialMutation = `mutation CilockTrust($input: CreateCredentialInput!) {
  createCredential(input: $input) {
    credential { id name type subject audience issuerURL scopes }
  }
}`

// CreatedCredential is the slice of the createCredential result trust reports.
type CreatedCredential struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Subject   string   `json:"subject"`
	Audience  string   `json:"audience"`
	IssuerURL string   `json:"issuerURL"`
	Scopes    []string `json:"scopes"`
}

// CreateOIDCCredential POSTs the createCredential mutation (type=OIDC) to the
// platform GraphQL endpoint, authenticated with the session bearer. It mirrors
// auth.ExchangeSignToken's authenticated-POST shape. The long-lived session
// token only ever goes to its own platform origin (the caller owns that check).
func CreateOIDCCredential(ctx context.Context, graphqlURL, sessionToken string, r *ResolvedTrust) (*CreatedCredential, error) {
	// Refuse to attach the admin session bearer (oidc:write) over cleartext to a
	// non-loopback host (#5997) — this credential can register CI trust.
	if err := config.RequireSecurePlatformURL(graphqlURL); err != nil {
		return nil, err
	}
	input := map[string]any{
		"name":      r.Name,
		"type":      TrustCredentialType,
		"tenantID":  r.TenantID,
		"subject":   r.Subject,
		"audience":  r.Audience,
		"issuerURL": r.IssuerURL,
		"scopes":    r.Scopes,
	}
	if len(r.AllowedIPs) > 0 {
		input["allowedIps"] = r.AllowedIPs
	}
	if len(r.Tags) > 0 {
		input["tags"] = r.Tags
	}
	body, err := json.Marshal(map[string]any{
		"query":     createCredentialMutation,
		"variables": map[string]any{"input": input},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal trust request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build trust request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("trust request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) //nolint:errcheck // diagnostic
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("platform returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Data struct {
			CreateCredential struct {
				Credential CreatedCredential `json:"credential"`
			} `json:"createCredential"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode trust response: %w", err)
	}
	if len(out.Errors) > 0 {
		msgs := make([]string, 0, len(out.Errors))
		for _, e := range out.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("platform rejected trust: %s", strings.Join(msgs, "; "))
	}
	cred := out.Data.CreateCredential.Credential
	if cred.ID == "" {
		return nil, fmt.Errorf("platform returned no credential")
	}
	return &cred, nil
}
