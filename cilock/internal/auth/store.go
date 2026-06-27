// Package auth handles cilock's interactive login to a Judge platform. A
// browser authorization-code-with-loopback flow yields a tenant-scoped session
// JWT, stored for subsequent platform calls (Archivista reads, Fulcio
// signing-token exchange). See docs/design/cilock-platform-identity-signing.md.
//
// The session/credential model and the keyring-backed store live in the shared
// github.com/aflock-ai/rookery/platformauth library so cilock and jctl resolve
// the same session. This package is cilock's adapter over it: the session model
// types are aliases, and every store function routes through ONE predicate
// (useShared) that delegates to platformauth's keyring-backed store only when the
// shared-session flag is on AND the one-time legacy→keyring migration has
// succeeded; otherwise it stays on cilock's legacy cleartext store for that
// operation. Routing reads and writes through the same predicate keeps them
// consistent: a migration failure drops the whole store (resolve, scope, trust-pin,
// active-platform, delete) to legacy together rather than mixing sources. The flag
// (JUDGE_SHARED_SESSION) makes the cutover reversible; the legacy store stays a
// readable fallback during the transition. See platformauth/DESIGN.md (phase 3).
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aflock-ai/rookery/platformauth"
	"github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
)

// AuthMode records how a stored credential was obtained, so `cilock whoami` can
// describe the session and `cilock run` can tell a real session JWT apart from a
// workflow-identity marker that carries no stored token. These mirror the shared
// platformauth constants.
const (
	// AuthModeToken — credential is a directly-supplied --token.
	AuthModeToken = platformauth.AuthModeToken
	// AuthModeBrowser — credential came from the interactive browser flow.
	AuthModeBrowser = platformauth.AuthModeBrowser
	// AuthModeWorkflowOIDC — CI workflow identity. No long-lived token is stored;
	// `cilock run` sources a fresh ambient OIDC token per call.
	AuthModeWorkflowOIDC = platformauth.AuthModeWorkflowOIDC
)

// Credential is a stored platform session, keyed by platform URL. It carries the
// working scope (tenant + product) negotiated at login plus the discovery
// trust-on-first-use pin (TrustBundleSPKI, GHSA #5988). It is the shared
// platformauth session type.
type Credential = platformauth.Credential

// sharedSessionEnvVar gates the cutover to the platformauth keyring-backed store.
// When set to "1" / "true" AND the one-time legacy→keyring migration has
// succeeded, the shared store becomes authoritative for EVERY operation (see
// useShared). Until migration succeeds — or whenever the flag is unset — every
// operation stays on the legacy cilock cleartext store, preserving prior behavior
// consistently across reads and writes. The flip is reversible: the legacy file
// stays readable so a flag flip back still finds it.
const sharedSessionEnvVar = "JUDGE_SHARED_SESSION"

// sharedSessionFlagOn reports only whether the operator turned the cutover flag
// on. It has no side effects — it does NOT attempt migration. Use useShared for
// the actual store-selection decision; this exists so the flag check and the
// migration attempt are separable.
func sharedSessionFlagOn() bool {
	v := os.Getenv(sharedSessionEnvVar)
	return v == "1" || v == "true"
}

// useShared is the SINGLE source-of-truth predicate every Store operation routes
// through to decide shared-keyring vs legacy-cleartext. It returns true ONLY when
// (a) the operator turned the flag on AND (b) the one-time legacy→keyring
// migration has actually SUCCEEDED. Calling it attempts the migration (via the
// retryable once-guard) as a side effect, so a transient migration failure is
// retried on the next operation.
//
// This collapses the former per-operation inconsistency: previously every method
// keyed off "flag on?" alone and routed unconditionally to the shared store, while
// only Resolve carried a legacy fallback — so on a migration failure a read could
// still resolve the legacy credential (with CapCanPinTrust) but a write
// (SetTrustBundleSPKI, SetScope, Delete) hit the empty shared store and failed or
// reported "unpinnable". With this predicate the three states are coherent:
//
//   - flag off                        → legacy everywhere (prior behavior, unchanged).
//   - flag on  + migration SUCCEEDED  → shared everywhere.
//   - flag on  + migration FAILED     → legacy everywhere, consistently — full
//     no-relogin: Resolve, ActivePlatformURL, SetScope, SetTrustBundleSPKI, Save,
//     and Delete all operate on the legacy store, so the trust-pin actually
//     persists (no false "unpinnable") and the active platform is preserved.
//
// Once migration succeeds the legacy store is never consulted again.
func useShared() bool {
	if !sharedSessionFlagOn() {
		return false
	}
	migrateLegacyOnce() // retryable; sets the guard only on success
	return migrated.Load()
}

// migration guard. Unlike a sync.Once (which is consumed even when the work it
// guards fails), this pair marks the migration "done" ONLY on success, so a
// failed migration is retried on the next read instead of leaving the process
// wedged on fallbacks until restart. migrated is the fast-path flag; migrateMu
// serializes the retries so a thundering herd of concurrent reads runs the
// migration once at a time rather than all at once.
var (
	migrated  atomic.Bool
	migrateMu sync.Mutex
)

// resetMigrateOnceForTest re-arms the one-shot legacy migration so a test can
// exercise the migration path from a clean slate. Test-only.
func resetMigrateOnceForTest() {
	migrateMu.Lock()
	defer migrateMu.Unlock()
	migrated.Store(false)
}

// doMigrateLegacy runs the actual legacy import once. It is a package var so a
// test can substitute a failing or succeeding migration to exercise the
// retry-on-failure guard without standing up a real keyring backend.
var doMigrateLegacy = func() error {
	store, err := platformauth.DefaultStore()
	if err != nil {
		return err
	}
	if _, err := platformauth.MigrateLegacyCilock(store); err != nil {
		return err
	}
	return nil
}

// migrateLegacyOnce imports the legacy cilock cleartext store into the shared
// keyring store at most once SUCCESSFULLY per process. It is best-effort and
// retryable: a failure (e.g. a keyring write error, or the shared store being
// momentarily unavailable) leaves the guard UNSET, so the next read path retries
// the migration. The legacy file stays in place and the session keeps working off
// the fallbacks meanwhile — the token is never dropped. A successful run sets the
// guard so subsequent reads skip the work.
//
// Double-checked locking: the lock-free fast path skips the mutex once migration
// has succeeded; otherwise the mutex serializes concurrent retries (one attempt at
// a time, not a thundering herd), and the second check under the lock collapses a
// race where another goroutine just succeeded.
func migrateLegacyOnce() {
	if migrated.Load() {
		return
	}
	migrateMu.Lock()
	defer migrateMu.Unlock()
	if migrated.Load() {
		return
	}
	if err := doMigrateLegacy(); err != nil {
		// Leave the guard unset so the next read retries. Warn at most once would be
		// nicer, but a per-attempt warning keeps a persistently-failing keyring
		// visible; it is on stderr, not the program's output.
		fmt.Fprintf(os.Stderr, "cilock: warning: legacy session migration incomplete (will retry): %v\n", err)
		return
	}
	migrated.Store(true)
}

// sharedResolver builds a resolver over the shared keyring store with the jctl
// read-through as its sole fallback (so a prior `jctl login` works for cilock
// too — a jctl credential declares no capabilities, keeping the verify trust gate
// fail-closed against it exactly as before).
//
// useShared() is the gate to reach this path, and it is true only once the legacy
// session has actually migrated INTO the shared store — so the migration-failure
// "resolve legacy with full capabilities" job is no longer this resolver's
// concern. On migration failure useShared() is false and resolution runs through
// the legacy seam instead (resolveLegacy), keeping read AND write consistently on
// the legacy store. The legacy cilock provider is therefore intentionally NOT a
// fallback here.
func sharedResolver() (*platformauth.Resolver, error) {
	store, err := platformauth.DefaultStore()
	if err != nil {
		return nil, err
	}
	return platformauth.NewResolver(store, jctlProvider{})
}

// sharedStore returns the platformauth keyring-backed store.
func sharedStore() (*platformauth.Store, error) { return platformauth.DefaultStore() }

// resolveShared runs resolution through the shared keyring-backed store.
func resolveShared(platformURL string, mode ResolveMode) (*Resolved, error) {
	r, err := sharedResolver()
	if err != nil {
		return nil, err
	}
	return r.Resolve(platformURL, mode)
}

// TokenCredential builds a session credential from an explicit --token, validating
// the JWT audience and deriving expiry from its `exp` claim (GHSA #5991). It is the
// shared platformauth implementation.
var TokenCredential = platformauth.TokenCredential

// NormalizeURL trims a trailing slash so lookups are stable.
func NormalizeURL(u string) string { return platformauth.NormalizeURL(u) }

// legacyFileStore is cilock's pre-shared-store on-disk shape: a token-bearing
// 0600 JSON map keyed by normalized platform URL plus the active-platform pointer.
type legacyFileStore struct {
	Credentials map[string]Credential `json:"credentials"`
	// CurrentPlatform is the platform of the most recent login/use — the active
	// working platform. Cleared when its credential is deleted.
	CurrentPlatform string `json:"current_platform,omitempty"`
}

// StorePath is cilock's own credential file (~/.config/cilock/credentials.json
// on Linux; Application Support on macOS). cilock owns this file; it does not
// write jctl's config.
func StorePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "cilock", "credentials.json"), nil
}

func load() (*legacyFileStore, error) {
	path, err := StorePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is under the user's own config dir
	if os.IsNotExist(err) {
		return &legacyFileStore{Credentials: map[string]Credential{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read credential store: %w", err)
	}
	var s legacyFileStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse credential store %s: %w", path, err)
	}
	if s.Credentials == nil {
		s.Credentials = map[string]Credential{}
	}
	return &s, nil
}

// writeLegacyStore writes the legacy cleartext store to path with mode 0600,
// ENFORCED even when path already exists at a looser mode. os.WriteFile alone
// does NOT tighten a pre-existing 0644 file, which would leave the cleartext
// bearer token world-readable. It writes a sibling temp file (created 0600,
// chmod-pinned against a permissive umask), then atomically renames it over the
// target so a concurrent reader never sees a partial or looser-mode file; a
// pre-existing target is also chmod-tightened first as a belt-and-suspenders step.
func writeLegacyStore(path string, data []byte) error {
	if _, statErr := os.Stat(path); statErr == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("tighten credential store perms: %w", err)
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp credential store: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set temp credential store perms: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp credential store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp credential store: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil { //nolint:gosec // path is the store's own file under the user's config dir (StorePath), not external input
		return fmt.Errorf("write credential store: %w", err)
	}
	return nil
}

// Save writes (or replaces) the credential for its platform URL. With the shared
// session flag on it goes to the platformauth keyring store; otherwise to the
// legacy cilock cleartext file at 0600.
func Save(c Credential) error {
	if useShared() {
		store, err := sharedStore()
		if err != nil {
			return err
		}
		return store.Save(c)
	}
	c.PlatformURL = NormalizeURL(c.PlatformURL)
	s, err := load()
	if err != nil {
		return err
	}
	s.Credentials[c.PlatformURL] = c
	s.CurrentPlatform = c.PlatformURL
	path, err := StorePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeLegacyStore(path, data)
}

// SetScope updates only the working tenant/product binding on the stored
// credential for platformURL, preserving its token, auth mode, email, and
// expiry. It requires an existing credential (run `cilock login` first). Empty
// arguments are left unchanged, so a caller can rebind product alone or tenant
// alone. This is the mechanism behind `cilock use` and the headless binding path.
func SetScope(platformURL, tenantID, tenantName, productID, productName string) error {
	if useShared() {
		store, err := sharedStore()
		if err != nil {
			return err
		}
		return store.SetScope(platformURL, tenantID, tenantName, productID, productName)
	}
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return err
	}
	c, ok := s.Credentials[key]
	if !ok {
		return fmt.Errorf("not logged in to %s (run: cilock login --platform-url %s)", key, key)
	}
	if tenantID != "" {
		c.TenantID = tenantID
	}
	if tenantName != "" {
		c.TenantName = tenantName
	}
	if productID != "" {
		c.ProductID = productID
	}
	if productName != "" {
		c.ProductName = productName
	}
	return Save(c)
}

// SetTrustBundleSPKI records the trust-on-first-use pin (the SHA-256 hex of the
// platform's discovery trust_bundle_pem) onto the stored credential for
// platformURL, preserving its token, scope, email, and expiry. It is used by
// verify's discovery-trust adoption (GHSA #5988).
//
// It returns persisted=true only when the pin was actually written. When no
// credential exists for the platform — a jctl-only session, which has no store
// entry to pin onto — it returns persisted=false with a nil error: the pin is
// UN-PINNABLE for this session and the caller MUST treat that as a hard security
// stop for silent first-use adoption. A non-nil error is a real store I/O failure.
func SetTrustBundleSPKI(platformURL, spki string) (persisted bool, err error) {
	if useShared() {
		store, sErr := sharedStore()
		if sErr != nil {
			return false, sErr
		}
		return store.SetTrustBundleSPKI(platformURL, spki)
	}
	key := NormalizeURL(platformURL)
	s, err := load()
	if err != nil {
		return false, err
	}
	c, ok := s.Credentials[key]
	if !ok {
		return false, nil // nothing in cilock's own store to pin onto — un-pinnable
	}
	if c.TrustBundleSPKI == spki {
		return true, nil // already pinned to this value; avoid a needless rewrite
	}
	c.TrustBundleSPKI = spki
	if err := Save(c); err != nil {
		return false, err
	}
	return true, nil
}

// ActivePlatformURL returns the platform a bare command should target when
// --platform-url is not given: the most recent login/use if it still has a stored
// credential, else the sole stored credential's URL, else "" (callers fall back to
// the compiled default).
func ActivePlatformURL() string {
	if useShared() {
		store, err := sharedStore()
		if err != nil {
			return ""
		}
		return store.ActivePlatformURL()
	}
	s, err := load()
	if err != nil {
		return ""
	}
	if s.CurrentPlatform != "" {
		if _, ok := s.Credentials[s.CurrentPlatform]; ok {
			return s.CurrentPlatform
		}
	}
	if len(s.Credentials) == 1 {
		for url := range s.Credentials {
			return url
		}
	}
	return ""
}

// Delete removes the credential for a platform URL. Returns whether one existed.
func Delete(platformURL string) (bool, error) {
	if useShared() {
		store, err := sharedStore()
		if err != nil {
			return false, err
		}
		return store.Delete(platformURL)
	}
	s, err := load()
	if err != nil {
		return false, err
	}
	key := NormalizeURL(platformURL)
	if _, ok := s.Credentials[key]; !ok {
		return false, nil
	}
	delete(s.Credentials, key)
	if s.CurrentPlatform == key {
		s.CurrentPlatform = "" // don't leave a dangling active platform
	}
	path, err := StorePath()
	if err != nil {
		return false, err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return false, err
	}
	if err := writeLegacyStore(path, data); err != nil {
		return false, err
	}
	return true, nil
}

// Lookup returns a non-expired credential with a non-empty Token for the platform
// URL, or nil if none. It is a thin shim over Resolve(url, ForBearer): the
// resolver holds the filtering and precedence. Callers attach the result's Token
// as a Bearer.
func Lookup(platformURL string) (*Credential, error) {
	res, err := Resolve(platformURL, ForBearer)
	if err != nil || res == nil {
		return nil, err
	}
	return res.Credential, nil
}

// LookupAny returns a non-expired stored credential for the platform URL
// regardless of whether it carries a token (including a workflow-identity marker
// with an empty Token). Use it for status/display (`cilock whoami`), never to
// obtain a bearer token. Thin shim over Resolve(url, ForDisplay).
func LookupAny(platformURL string) (*Credential, error) {
	res, err := Resolve(platformURL, ForDisplay)
	if err != nil || res == nil {
		return nil, err
	}
	return res.Credential, nil
}

// LookupAnyIncludingExpired returns the credential the platform call would use,
// but unlike LookupAny it surfaces an EXPIRED credential rather than collapsing it
// to nil — so diagnostic callers (`cilock doctor`) can tell an EXPIRED session
// apart from a MISSING one. NEVER use this to obtain a bearer token. Thin shim
// over Resolve(url, IncludingExpired).
func LookupAnyIncludingExpired(platformURL string) (*Credential, error) {
	res, err := Resolve(platformURL, IncludingExpired)
	if err != nil || res == nil {
		return nil, err
	}
	return res.Credential, nil
}

// jctlKeyringService is jctl's keychain service identifier — every token jctl
// scrubs out of ~/.jctl/config.yaml lives in the OS keychain under this service,
// keyed by the context NAME as the account. Must stay in sync with
// judge-api/cmd/jctl/internal/config (keyringService).
const jctlKeyringService = "jctl"

// jctlKeyringTimeout caps the keychain read. A wedged secret-service daemon can
// otherwise hang every cilock command indefinitely. A var (not const) so tests
// can shrink it.
var jctlKeyringTimeout = 3 * time.Second

// getJctlKeyringToken is a seam over keyring.Get so tests can simulate a hanging
// or failing keychain backend.
var getJctlKeyringToken = func(contextName string) (string, error) {
	return keyring.Get(jctlKeyringService, contextName)
}

// jctlKeyringToken reads the token jctl stored in the OS keychain for
// contextName, bounded by jctlKeyringTimeout. Any error, miss, or timeout reports
// ok=false — the caller then behaves exactly as if the context had no token. On
// timeout the read goroutine is abandoned; its buffered channel send cannot block,
// so it exits whenever the backend finally answers.
func jctlKeyringToken(contextName string) (string, bool) {
	type result struct {
		token string
		err   error
	}
	get := getJctlKeyringToken
	ch := make(chan result, 1)
	go func() {
		token, err := get(contextName)
		ch <- result{token: token, err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil || r.token == "" {
			return "", false
		}
		return r.token, true
	case <-time.After(jctlKeyringTimeout):
		return "", false
	}
}

// jctlContext is the per-context shape cilock reads from jctl's config.
type jctlContext struct {
	JudgeURL    string `yaml:"judgeURL"`
	Token       string `yaml:"token"`
	TenantID    string `yaml:"tenant_id"`
	TenantName  string `yaml:"tenant_name"`
	ProductID   string `yaml:"product_id"`
	ProductName string `yaml:"product_name"`
}

// credential builds the cilock Credential a jctl context resolves to. token is
// passed explicitly because it may come from the YAML or the OS keychain.
func (ctx jctlContext) credential(platformURL, token string) *Credential {
	return &Credential{
		PlatformURL: platformURL,
		Token:       token,
		TenantID:    ctx.TenantID,
		TenantName:  ctx.TenantName,
		ProductID:   ctx.ProductID,
		ProductName: ctx.ProductName,
	}
}

// lookupJctl reads ~/.jctl/config.yaml (best-effort) for a context whose judgeURL
// matches. Tokens come from the YAML when present (jctl file mode /
// JCTL_DISABLE_KEYRING=1); when the YAML token is empty, jctl scrubbed it into the
// OS keychain (service "jctl", account = context name) and the fallback reads it
// from there — otherwise the documented "jctl login works for cilock too" interop
// is silently dead on macOS and desktop Linux, where the keychain is jctl's default.
func lookupJctl(platformURL string) (*Credential, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(home, ".jctl", "config.yaml")) //nolint:gosec // user's own jctl config
	if err != nil {
		return nil, false
	}
	var cfg struct {
		Contexts map[string]jctlContext `yaml:"contexts"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, false
	}
	// Pass 1: contexts whose token is inline in the YAML. Never touches the
	// keychain — a wedged daemon can't slow down an install that already works.
	for _, ctx := range cfg.Contexts {
		if NormalizeURL(ctx.JudgeURL) == platformURL && ctx.Token != "" {
			return ctx.credential(platformURL, ctx.Token), true
		}
	}
	// Pass 2: matching contexts with an empty YAML token — read the keychain entry
	// jctl scrubbed the token into. The account is the context NAME (the YAML map
	// key), not a recomputed hostname. Any miss/error/timeout leaves us with no
	// credential, exactly as before this fallback existed.
	for name, ctx := range cfg.Contexts {
		if NormalizeURL(ctx.JudgeURL) != platformURL || ctx.Token != "" {
			continue
		}
		if token, ok := jctlKeyringToken(name); ok {
			return ctx.credential(platformURL, token), true
		}
	}
	return nil, false
}
