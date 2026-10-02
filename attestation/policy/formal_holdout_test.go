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

package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/sigstore/fulcio/pkg/certificate"
)

// The holdout of the Lean model (formal/cilock-policy/CilockPolicy/Holdout.lean).
// Each case runs the REAL Functionary.Validate on a real policy's functionary
// and a GitHub Actions keyless certificate shape, and asserts the verdict the
// model computed before this test existed. A disagreement is either a model bug
// or an engine bug; neither may be fixed by editing the expectation.

func holdoutLeaf(t *testing.T, uri string, ext certificate.Extensions) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "holdout root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	exts, err := ext.Render()
	if err != nil {
		t.Fatal(err)
	}
	// Fulcio's GitHub shape: no subject CN, one URI SAN, no DNS/email/org.
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs: []*url.URL{u}, ExtraExtensions: exts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return ca, leaf
}

func holdoutValidate(t *testing.T, f Functionary, rootID string, uri string, ext certificate.Extensions, h HardeningOptions) bool {
	t.Helper()
	ca, leaf := holdoutLeaf(t, uri, ext)
	v, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prev := Hardening()
	SetHardening(h)
	defer SetHardening(prev)
	return f.Validate(v, map[string]TrustBundle{rootID: {Root: ca}}) == nil
}

// holdoutEnforce is the hardening the cilock CLI and Judge install, read from
// the engine rather than listed here: a hand-copied flag list silently missed
// EnforceAllowedUntracked, so the differential ran the engine with a
// check off that the model's "enforce" had on, and agreed with a stale model.
var holdoutEnforce = EnforcedHardening()

func ghExt(repo, buildConfig, ref, runner string) certificate.Extensions {
	return certificate.Extensions{
		Issuer: "https://token.actions.githubusercontent.com", SourceRepositoryURI: repo,
		BuildConfigURI: buildConfig, SourceRepositoryRef: ref, RunnerEnvironment: runner,
	}
}

func TestFormalHoldout_ReleasePolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "cilock", "release.policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pol Policy
	if err := json.Unmarshal(raw, &pol); err != nil {
		t.Fatal(err)
	}
	f := pol.Steps["release-build"].Functionaries[0]
	uri := "https://github.com/aflock-ai/rookery/.github/workflows/release.yml@refs/tags/v1.2.3"
	ext := ghExt("https://github.com/aflock-ai/rookery", uri, "refs/tags/v1.2.3", "github-hosted")
	// Holdout.lean release_prediction_after_9866: the shipped policy sets
	// dnsnames/emails/organizations to "*", so it is admitted under enforce
	// and under warn.
	if got := holdoutValidate(t, f, "platform-testifysec-fulcio", uri, ext, holdoutEnforce); !got {
		t.Errorf("enforce: model predicts ADMITTED (dnsnames/emails/organizations are \"*\"), engine refused")
	}
	if got := holdoutValidate(t, f, "platform-testifysec-fulcio", uri, ext, HardeningOptions{}); !got {
		t.Errorf("warn: model predicts ADMITTED, engine refused")
	}

	// Holdout.lean release_prediction: the policy as held out, before an earlier change,
	// with those lists empty, is refused under enforce (R3_181) and admitted
	// under warn.
	before := f
	before.CertConstraint.DNSNames, before.CertConstraint.Emails, before.CertConstraint.Organizations = nil, nil, nil
	if got := holdoutValidate(t, before, "platform-testifysec-fulcio", uri, ext, holdoutEnforce); got {
		t.Errorf("enforce, before an earlier change: model predicts REFUSED (empty dnsnames/emails/organizations, R3_181), engine admitted")
	}
	if got := holdoutValidate(t, before, "platform-testifysec-fulcio", uri, ext, HardeningOptions{}); !got {
		t.Errorf("warn, before an earlier change: model predicts ADMITTED, engine refused")
	}
}

func TestFormalHoldout_WeeklyDR(t *testing.T) {
	// Verbatim from testifysec/judge scripts/dr/verification.policy.json,
	// step weekly-dr-observation (not readable from this repository).
	wf := "https://github.com/testifysec/judge/.github/workflows/weekly-dr.yml@refs/heads/main"
	f := Functionary{Type: "root", CertConstraint: CertConstraint{
		CommonName: "*", URIs: []string{wf}, Roots: []string{"fulcio-root"},
		DNSNames: []string{"*"}, Emails: []string{"*"}, Organizations: []string{"*"},
		Extensions: certificate.Extensions{Issuer: "https://token.actions.githubusercontent.com",
			SourceRepositoryURI: "https://github.com/testifysec/judge", BuildConfigURI: wf},
	}}
	if !holdoutValidate(t, f, "fulcio-root", wf, ghExt("https://github.com/testifysec/judge", wf, "refs/heads/main", "github-hosted"), holdoutEnforce) {
		t.Errorf("main-branch run: model predicts ADMITTED, engine refused")
	}
	pr := "https://github.com/testifysec/judge/.github/workflows/weekly-dr.yml@refs/pull/1/merge"
	if holdoutValidate(t, f, "fulcio-root", pr, ghExt("https://github.com/testifysec/judge", pr, "refs/pull/1/merge", "github-hosted"), holdoutEnforce) {
		t.Errorf("pull-request run: model predicts REFUSED, engine admitted")
	}
}

func TestFormalHoldout_SelfHostMinimal(t *testing.T) {
	// Verbatim from testifysec/judge deploy/dist/self-host-minimal.policy.json, step clone.
	f := Functionary{Type: "root", CertConstraint: CertConstraint{
		CommonName: "*", DNSNames: []string{"*"}, Emails: []string{"*"}, Organizations: []string{"*"},
		URIs: []string{"*"}, Roots: []string{"platform-testifysec-fulcio"},
		Extensions: certificate.Extensions{Issuer: "https://token.actions.githubusercontent.com",
			SourceRepositoryURI: "https://github.com/testifysec/judge", SourceRepositoryRef: "refs/tags/self-host-minimal-v*",
			BuildConfigURI:    "https://github.com/testifysec/judge/.github/workflows/release-self-host-minimal.yml@*",
			RunnerEnvironment: "self-hosted"},
	}}
	base := "https://github.com/testifysec/judge/.github/workflows/release-self-host-minimal.yml@"
	cases := []struct {
		ref, runner string
		want        bool
	}{
		{"refs/tags/self-host-minimal-v1.0.0", "self-hosted", true},
		{"refs/tags/self-host-minimal-v1.0.0", "github-hosted", false},
		{"refs/heads/main", "self-hosted", false},
	}
	for _, c := range cases {
		got := holdoutValidate(t, f, "platform-testifysec-fulcio", base+c.ref,
			ghExt("https://github.com/testifysec/judge", base+c.ref, c.ref, c.runner), holdoutEnforce)
		if got != c.want {
			t.Errorf("%s on %s: model predicts %v, engine %v", c.ref, c.runner, c.want, got)
		}
	}
}
