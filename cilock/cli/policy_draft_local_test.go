// jade:ring local

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// draftHydrateCert is one generated certificate: its PEM, parsed form, and the
// sha256 of its DER, the fingerprint the command must print.
type draftHydrateCert struct {
	pem  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (c draftHydrateCert) fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// draftHydrateIssue mints a CA certificate. parent == nil makes it self-signed
// (a root); otherwise it is an intermediate signed by parent.
func draftHydrateIssue(t *testing.T, cn string, parent *draftHydrateCert) draftHydrateCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Draft Hydrate Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return draftHydrateCert{
		pem:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		cert: cert,
		key:  key,
	}
}

// draftHydratePlatform is an httptest stand-in for the platform: discovery,
// the TSA chain endpoint, and the server-side hydration endpoint, each counted
// so a test can prove which of them the command actually touched.
type draftHydratePlatform struct {
	*httptest.Server
	fulcioRoot, fulcioInter draftHydrateCert
	tsaRoot, tsaInter       draftHydrateCert

	discoveryHits atomic.Int32
	chainHits     atomic.Int32
	hydrateHits   atomic.Int32
	gotHydrateSrc atomic.Value // string

	// tsaChainURL overrides the advertised tsa_cert_chain_url when non-empty.
	tsaChainURL string
}

func (p *draftHydratePlatform) trustBundlePEM() string {
	// Production order: the Fulcio intermediate first, then the root.
	return p.fulcioInter.pem + p.fulcioRoot.pem
}

func newDraftHydratePlatform(t *testing.T, configure func(p *draftHydratePlatform)) *draftHydratePlatform {
	t.Helper()
	p := &draftHydratePlatform{}
	p.fulcioRoot = draftHydrateIssue(t, "Draft Hydrate Platform Root CA", nil)
	p.fulcioInter = draftHydrateIssue(t, "Draft Hydrate Platform Fulcio CA", &p.fulcioRoot)
	p.tsaRoot = draftHydrateIssue(t, "Draft Hydrate TSA Root", nil)
	p.tsaInter = draftHydrateIssue(t, "Draft Hydrate TSA Intermediate", &p.tsaRoot)
	if configure != nil {
		configure(p)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/judge-configuration", func(w http.ResponseWriter, _ *http.Request) {
		p.discoveryHits.Add(1)
		chainURL := p.tsaChainURL
		if chainURL == "" {
			chainURL = p.URL + "/api/v1/timestamp/certchain"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"signing": map[string]any{
				"trust_bundle_pem":   p.trustBundlePEM(),
				"tsa_cert_chain_url": chainURL,
			},
		})
	})
	mux.HandleFunc("/api/v1/timestamp/certchain", func(w http.ResponseWriter, _ *http.Request) {
		p.chainHits.Add(1)
		// Leaf-to-root order, as the platform serves it.
		_, _ = w.Write([]byte(p.tsaInter.pem + p.tsaRoot.pem))
	})
	mux.HandleFunc("/api/pushgate/policies/hydrate", func(w http.ResponseWriter, r *http.Request) {
		p.hydrateHits.Add(1)
		var req draftReqWire
		_ = json.NewDecoder(r.Body).Decode(&req)
		p.gotHydrateSrc.Store(req.Source)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(okHydration(req, req.Source))
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// draftHydrateIsolateHome points the credential store at an empty temp dir so
// a developer's real login (and its trust pin) never leaks into a test.
func draftHydrateIsolateHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
}

// draftHydrateSentinelSource is a policy that asks for both platform
// sentinels, plus an authoring key the typed policy does not model.
const draftHydrateSentinelSource = `{
  "name": "keep-me",
  "expires": "2030-01-01T00:00:00Z",
  "roots": {"fulcio-root": {"certificate": ""}},
  "timestampauthorities": {"platform-tsa": {"certificate": ""}},
  "steps": {"build": {"name": "build", "functionaries": [
    {"type": "root", "certConstraint": {"commonname": "*", "emails": ["judge-internal@testifysec.com"], "roots": ["fulcio-root"]}}
  ]}}
}`

func draftHydrateWriteSource(t *testing.T, src string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	return dir, path
}

// draftHydrateTrust is the wire shape of one trust entry (base64 PEM bytes).
type draftHydrateTrust struct {
	Certificate   []byte   `json:"certificate"`
	Intermediates [][]byte `json:"intermediates"`
}

func draftHydrateReadOutput(t *testing.T, path string) (map[string]json.RawMessage, map[string]draftHydrateTrust, map[string]draftHydrateTrust) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test temp path
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("output is not a JSON object: %v\n%s", err, raw)
	}
	var roots, tsas map[string]draftHydrateTrust
	if r, ok := doc["roots"]; ok {
		if err := json.Unmarshal(r, &roots); err != nil {
			t.Fatalf("decode roots: %v", err)
		}
	}
	if r, ok := doc["timestampauthorities"]; ok {
		if err := json.Unmarshal(r, &tsas); err != nil {
			t.Fatalf("decode timestampauthorities: %v", err)
		}
	}
	return doc, roots, tsas
}

func draftHydrateAssertEntry(t *testing.T, label string, got draftHydrateTrust, root draftHydrateCert, inters ...draftHydrateCert) {
	t.Helper()
	if string(got.Certificate) != root.pem {
		t.Errorf("%s.certificate = %q, want the self-signed root %q", label, got.Certificate, root.cert.Subject.CommonName)
	}
	if len(got.Intermediates) != len(inters) {
		t.Fatalf("%s.intermediates has %d entries, want %d", label, len(got.Intermediates), len(inters))
	}
	for i, inter := range inters {
		if string(got.Intermediates[i]) != inter.pem {
			t.Errorf("%s.intermediates[%d] is not %q", label, i, inter.cert.Subject.CommonName)
		}
	}
}

func TestDraftHydrateLocal_FillsBothSentinelsFromDiscovery(t *testing.T) {
	draftHydrateIsolateHome(t) // no login: local hydration must not need one
	p := newDraftHydratePlatform(t, nil)
	dir, src := draftHydrateWriteSource(t, draftHydrateSentinelSource)
	out := filepath.Join(dir, "hydrated.json")

	stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local")
	if err != nil {
		t.Fatalf("draft --hydrate-local: %v\n%s", err, stdout)
	}

	doc, roots, tsas := draftHydrateReadOutput(t, out)
	// Same placement as judge-api/pkg/policy/hydrate.PartitionCAChain: the
	// self-signed cert is the root, everything else an intermediate.
	draftHydrateAssertEntry(t, "roots[fulcio-root]", roots["fulcio-root"], p.fulcioRoot, p.fulcioInter)
	draftHydrateAssertEntry(t, "timestampauthorities[platform-tsa]", tsas["platform-tsa"], p.tsaRoot, p.tsaInter)

	if string(doc["name"]) != `"keep-me"` {
		t.Errorf("authoring key 'name' not preserved: %s", doc["name"])
	}
	if p.hydrateHits.Load() != 0 {
		t.Errorf("--hydrate-local called the platform hydration endpoint %d times; it must not", p.hydrateHits.Load())
	}
	if raw, _ := os.ReadFile(out); strings.Contains(string(raw), `"signatures"`) { //nolint:gosec // test temp path
		t.Errorf("local hydration wrote something that looks signed:\n%s", raw)
	}

	// Every placed certificate is named by subject and sha256.
	for _, c := range []draftHydrateCert{p.fulcioRoot, p.fulcioInter, p.tsaRoot, p.tsaInter} {
		if !strings.Contains(stdout, c.cert.Subject.CommonName) {
			t.Errorf("stdout does not name placed certificate %q:\n%s", c.cert.Subject.CommonName, stdout)
		}
		if !strings.Contains(stdout, "sha256:"+c.fingerprint()) {
			t.Errorf("stdout lacks sha256:%s for %q:\n%s", c.fingerprint(), c.cert.Subject.CommonName, stdout)
		}
	}
	if !strings.Contains(stdout, "UNSIGNED") {
		t.Errorf("stdout must say the output is UNSIGNED:\n%s", stdout)
	}
}

func TestDraftHydrateLocal_InjectsAnExplicitlyReferencedAbsentFulcioRoot(t *testing.T) {
	// Server parity: EnsurePlatformBodyRoots injects when a functionary names
	// fulcio-root even though the roots map has no such key.
	draftHydrateIsolateHome(t)
	p := newDraftHydratePlatform(t, nil)
	source := `{"expires":"2030-01-01T00:00:00Z","steps":{"build":{"name":"build","functionaries":[{"type":"root","certConstraint":{"roots":["fulcio-root"]}}]}}}`
	dir, src := draftHydrateWriteSource(t, source)
	out := filepath.Join(dir, "hydrated.json")

	if stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local"); err != nil {
		t.Fatalf("draft: %v\n%s", err, stdout)
	}
	_, roots, tsas := draftHydrateReadOutput(t, out)
	draftHydrateAssertEntry(t, "roots[fulcio-root]", roots["fulcio-root"], p.fulcioRoot, p.fulcioInter)
	if tsas != nil {
		t.Errorf("no platform-tsa key was declared, so none may be injected; got %v", tsas)
	}
	if p.chainHits.Load() != 0 {
		t.Errorf("TSA chain fetched %d times with no platform-tsa slot to fill", p.chainHits.Load())
	}
}

func TestDraftHydrateLocal_RefusesACrossOriginTSAChain(t *testing.T) {
	draftHydrateIsolateHome(t)
	other := newDraftHydratePlatform(t, nil) // a different origin serving a chain
	p := newDraftHydratePlatform(t, func(p *draftHydratePlatform) {
		p.tsaChainURL = other.URL + "/api/v1/timestamp/certchain"
	})
	dir, src := draftHydrateWriteSource(t, draftHydrateSentinelSource)
	out := filepath.Join(dir, "hydrated.json")

	stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local")
	if err == nil {
		t.Fatalf("a cross-origin tsa_cert_chain_url was accepted:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "cross-origin") {
		t.Errorf("error should name the cross-origin refusal, got: %v", err)
	}
	if other.chainHits.Load() != 0 {
		t.Errorf("the foreign origin was contacted %d times", other.chainHits.Load())
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("output written despite the refusal (stat err = %v)", statErr)
	}
}

func TestDraftHydrateLocal_RefusesCleartextNonLoopbackPlatform(t *testing.T) {
	draftHydrateIsolateHome(t)
	dir, src := draftHydrateWriteSource(t, draftHydrateSentinelSource)
	out := filepath.Join(dir, "hydrated.json")

	// .invalid never resolves, so a request that escaped the guard would fail
	// with a DNS error rather than the https refusal asserted below.
	_, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out,
		"--platform-url", "http://platform.draft-hydrate.invalid", "--hydrate-local")
	if err == nil {
		t.Fatal("cleartext non-loopback platform accepted as a trust source")
	}
	if !strings.Contains(err.Error(), "must be https") {
		t.Errorf("error should name the https requirement, got: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("output written despite the refusal (stat err = %v)", statErr)
	}
}

func TestDraftHydrateLocal_LeavesAPolicyWithoutSentinelsByteExact(t *testing.T) {
	draftHydrateIsolateHome(t)
	p := newDraftHydratePlatform(t, nil)
	byo := draftHydrateIssue(t, "Corp Root", nil)
	source := `{"expires":"2030-01-01T00:00:00Z","roots":{"corp-root":{"certificate":"` +
		draftHydrateB64(byo.pem) + `"}},"steps":{"build":{"name":"build","functionaries":[{"type":"root","certConstraint":{"roots":["corp-root"]}}]}}}`
	dir, src := draftHydrateWriteSource(t, source)
	out := filepath.Join(dir, "hydrated.json")

	stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local")
	if err != nil {
		t.Fatalf("draft: %v\n%s", err, stdout)
	}
	got, _ := os.ReadFile(out) //nolint:gosec // test temp path
	if string(got) != source {
		t.Errorf("policy with no sentinels changed:\n got %s\nwant %s", got, source)
	}
	if n := p.discoveryHits.Load() + p.chainHits.Load(); n != 0 {
		t.Errorf("nothing to hydrate, yet the platform was contacted %d times", n)
	}
}

func TestDraftHydrateDefault_SendsSentinelsToThePlatformUntouched(t *testing.T) {
	// Opting out of local hydration is the default: the source goes to the
	// platform's hydrator byte-for-byte, sentinels intact, and discovery is not
	// consulted for trust material.
	p := newDraftHydratePlatform(t, nil)
	stubSession(t, p.URL)
	dir, src := draftHydrateWriteSource(t, draftHydrateSentinelSource)
	out := filepath.Join(dir, "hydrated.json")

	if stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL); err != nil {
		t.Fatalf("draft: %v\n%s", err, stdout)
	}
	if p.hydrateHits.Load() != 1 {
		t.Fatalf("platform hydration hits = %d, want 1", p.hydrateHits.Load())
	}
	sent, _ := p.gotHydrateSrc.Load().(string)
	if sent != draftHydrateSentinelSource {
		t.Errorf("source sent to the platform was altered:\n got %s\nwant %s", sent, draftHydrateSentinelSource)
	}
	if n := p.discoveryHits.Load() + p.chainHits.Load(); n != 0 {
		t.Errorf("default draft fetched local trust material %d times; it must leave that to the platform", n)
	}
}

func TestDraftHydrateLocal_RefusesWildcardMixedWithExplicitFulcioRoot(t *testing.T) {
	draftHydrateIsolateHome(t)
	p := newDraftHydratePlatform(t, nil)
	source := `{"expires":"2030-01-01T00:00:00Z","steps":{
	  "a":{"name":"a","functionaries":[{"type":"root","certConstraint":{"roots":["fulcio-root"]}}]},
	  "b":{"name":"b","functionaries":[{"type":"root","certConstraint":{"roots":["*"]}}]}}}`
	dir, src := draftHydrateWriteSource(t, source)
	out := filepath.Join(dir, "hydrated.json")

	_, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local")
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("wildcard + explicit fulcio-root must be refused (server parity), got: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("output written despite the refusal")
	}
}

func TestDraftHydrateLocal_KeepsAValidBYOCertAndRefusesGarbage(t *testing.T) {
	draftHydrateIsolateHome(t)
	p := newDraftHydratePlatform(t, nil)
	byo := draftHydrateIssue(t, "Author Supplied Root", nil)

	t.Run("valid kept", func(t *testing.T) {
		source := `{"expires":"2030-01-01T00:00:00Z","roots":{"fulcio-root":{"certificate":"` + draftHydrateB64(byo.pem) +
			`"}},"steps":{"build":{"name":"build","functionaries":[{"type":"root","certConstraint":{"roots":["fulcio-root"]}}]}}}`
		dir, src := draftHydrateWriteSource(t, source)
		out := filepath.Join(dir, "hydrated.json")
		if stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local"); err != nil {
			t.Fatalf("draft: %v\n%s", err, stdout)
		}
		got, _ := os.ReadFile(out) //nolint:gosec // test temp path
		if string(got) != source {
			t.Errorf("an author-supplied fulcio-root must be left alone:\n got %s\nwant %s", got, source)
		}
	})
	t.Run("garbage refused", func(t *testing.T) {
		source := `{"expires":"2030-01-01T00:00:00Z","roots":{"fulcio-root":{"certificate":"` + draftHydrateB64("not a cert") +
			`"}},"steps":{"build":{"name":"build","functionaries":[{"type":"root","certConstraint":{"roots":["fulcio-root"]}}]}}}`
		dir, src := draftHydrateWriteSource(t, source)
		out := filepath.Join(dir, "hydrated.json")
		_, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local")
		if err == nil || !strings.Contains(err.Error(), "not a valid X.509") {
			t.Fatalf("garbage under fulcio-root must be refused, got: %v", err)
		}
	})
}

func TestDraftHydrateLocal_RefusesATrustBundleThatChangedSinceItWasPinned(t *testing.T) {
	p := newDraftHydratePlatform(t, nil)
	stubSession(t, p.URL)
	if _, err := auth.SetTrustBundleSPKI(p.URL, strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("pin: %v", err)
	}
	dir, src := draftHydrateWriteSource(t, draftHydrateSentinelSource)
	out := filepath.Join(dir, "hydrated.json")

	_, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local")
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a changed pinned trust bundle must be refused, got: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("output written despite the refusal")
	}
}

func TestDraftHydrateLocal_AcceptsAMatchingPin(t *testing.T) {
	p := newDraftHydratePlatform(t, nil)
	stubSession(t, p.URL)
	sum := sha256.Sum256([]byte(p.trustBundlePEM()))
	if _, err := auth.SetTrustBundleSPKI(p.URL, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("pin: %v", err)
	}
	dir, src := draftHydrateWriteSource(t, draftHydrateSentinelSource)
	out := filepath.Join(dir, "hydrated.json")

	stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", p.URL, "--hydrate-local")
	if err != nil {
		t.Fatalf("draft: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "matches the pin") {
		t.Errorf("stdout should report the bundle matched its pin:\n%s", stdout)
	}
}

// draftHydrateB64 encodes PEM text the way a JSON []byte field carries it.
func draftHydrateB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
