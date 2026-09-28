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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/standards"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	alpsevidence "github.com/aflock-ai/rookery/plugins/attestors/alps-evidence"
	"github.com/sigstore/fulcio/pkg/certificate"
)

const provenanceWorkflowURI = "https://github.com/aflock-ai/cilock-action/.github/workflows/provenance.yml@refs/tags/v1"

// fulcioLeaf mints a self-signed leaf carrying the Fulcio extensions a
// GitHub Actions workflow token produces. Only the extensions are read.
func fulcioLeaf(t *testing.T, ext certificate.Extensions) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exts, err := ext.Render()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func collectionResult(cert *x509.Certificate, timestamped bool) []workflow.RunResult {
	sig := dsse.Signature{KeyID: "k", Signature: []byte("s")}
	if cert != nil {
		sig.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	if timestamped {
		sig.Timestamps = []dsse.SignatureTimestamp{{Type: dsse.TimestampRFC3161, Data: []byte("t")}}
	}
	return []workflow.RunResult{{SignedEnvelope: dsse.Envelope{Signatures: []dsse.Signature{sig}}}}
}

func envOf(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }

var slsaRan = []options.AttestorOutcome{{Name: "slsa", Status: options.AttestorStatusRan}}

func TestRunObservationsShapes(t *testing.T) {
	gha := map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
	hostedLeaf := fulcioLeaf(t, certificate.Extensions{
		Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "github-hosted",
		BuildSignerURI: "https://github.com/tenant/repo/.github/workflows/build.yml@refs/heads/main",
	})
	builderLeaf := fulcioLeaf(t, certificate.Extensions{
		Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "github-hosted", BuildSignerURI: provenanceWorkflowURI,
	})
	selfHostedLeaf := fulcioLeaf(t, certificate.Extensions{
		Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "self-hosted",
	})
	gitlabLeaf := fulcioLeaf(t, certificate.Extensions{Issuer: "https://gitlab.com", RunnerEnvironment: "gitlab-hosted"})
	cases := []struct {
		name       string
		summary    options.RunSummary
		results    []workflow.RunResult
		failed     bool
		env        map[string]string
		slsa, alps string
	}{
		{"local key", options.RunSummary{Signer: "file", Attestors: slsaRan}, collectionResult(nil, true), false, nil, "L1", "ALPS-0"},
		{"local key, slsa not selected", options.RunSummary{Signer: "file"}, collectionResult(nil, true), false, nil, "none", "ALPS-0"},
		{"inline gha keyless", options.RunSummary{Signer: "fulcio", WorkflowIdentity: true, Attestors: slsaRan}, collectionResult(hostedLeaf, true), false, gha, "L2", "ALPS-0"},
		{"provenance workflow", options.RunSummary{Signer: "fulcio", WorkflowIdentity: true, Attestors: slsaRan}, collectionResult(builderLeaf, true), false, gha, "L3", "ALPS-0"},
		// The leaf's runner-environment outranks the job environment: a
		// self-hosted leaf is not hosted even if the env var says so.
		{"self-hosted leaf, spoofed env", options.RunSummary{Signer: "fulcio", WorkflowIdentity: true, Attestors: slsaRan}, collectionResult(selfHostedLeaf, true), false, gha, "L1", "ALPS-0"},
		{"enrolled agent on a laptop", options.RunSummary{Signer: "fulcio", AgentPrincipal: "spiffe://p/agent/1", Attestors: slsaRan}, collectionResult(nil, true), false, nil, "L1", "ALPS-0"},
		{"no timestamp", options.RunSummary{Signer: "fulcio", WorkflowIdentity: true, Attestors: slsaRan}, collectionResult(hostedLeaf, false), false, gha, "L1", "ALPS-0"},
		// Public Sigstore issued the leaf, not the platform: a workflow name is
		// not a platform-issued principal, so ALPS stays at 0.
		{"gitlab.com keyless (public Sigstore)", options.RunSummary{Signer: "fulcio", Attestors: slsaRan}, collectionResult(gitlabLeaf, true), false, map[string]string{"GITLAB_CI": "true"}, "L2", "ALPS-0"},
		{"run failed", options.RunSummary{Signer: "fulcio", WorkflowIdentity: true, Attestors: slsaRan}, collectionResult(hostedLeaf, true), true, gha, "none", "unknown"},
		{"no envelope", options.RunSummary{Signer: "file", Attestors: slsaRan}, nil, false, nil, "none", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, ao := runObservations(&c.summary, c.results, c.failed, envOf(c.env))
			g := standards.ComputeSplit(o, ao, standards.ScopeRun, standards.AudienceHuman)
			if g.SLSABuild.Ceiling != c.slsa || g.ALPS.Ceiling != c.alps {
				t.Fatalf("ceilings %s/%s, want %s/%s (observations %+v)", g.SLSABuild.Ceiling, g.ALPS.Ceiling, c.slsa, c.alps, o)
			}
			// GitLab never gets the GitHub-only provenance workflow; it gets the
			// L3 limit instead (formal/slsa-tracks: L3 refuted on gitlab.com).
			if o.CIPlatform == standards.CIGitLab {
				for _, s := range g.NextSteps {
					if s.ID == "slsa-provenance-workflow" {
						t.Fatal("provenance.yml offered on GitLab")
					}
				}
				if len(g.SLSABuild.Unavailable) != 1 || g.SLSABuild.Unavailable[0].Level != "L3" {
					t.Fatalf("GitLab L3 limit missing: %+v", g.SLSABuild.Unavailable)
				}
			}
		})
	}
}

func TestRunAudience(t *testing.T) {
	orig := detectInvokingAgent
	t.Cleanup(func() { detectInvokingAgent = orig })
	walked := false
	detectInvokingAgent = func() bool { walked = true; return true }

	if got := runAudience(&options.RunSummary{AgentPrincipal: "spiffe://x"}, nil); got != standards.AudienceAgent {
		t.Fatalf("agent principal: %s", got)
	}
	notDetected := alpsevidence.New()
	notDetected.Status = alpsevidence.StatusNotDetected
	walked = false
	if got := runAudience(&options.RunSummary{}, []attestation.Attestor{notDetected}); got != standards.AudienceHuman || walked {
		t.Fatalf("alps-evidence not-detected must be final: audience %s, re-walked %v", got, walked)
	}
	detected := alpsevidence.New()
	detected.Status = alpsevidence.StatusDetected
	if got := runAudience(&options.RunSummary{}, []attestation.Attestor{detected}); got != standards.AudienceAgent {
		t.Fatalf("alps-evidence detected: %s", got)
	}
	if got := runAudience(&options.RunSummary{}, nil); got != standards.AudienceAgent || !walked {
		t.Fatalf("no alps-evidence attestor: audience %s, walked %v", got, walked)
	}
}

// TestRunSummaryCarriesGuidance: the run summary's human block and --json
// object both carry the guidance, and the JSON keeps verified_level null.
func TestRunSummaryCarriesGuidance(t *testing.T) {
	leaf := fulcioLeaf(t, certificate.Extensions{Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "github-hosted"})
	s := &options.RunSummary{Step: "build", Signer: "fulcio", WorkflowIdentity: true, Attestors: slsaRan}
	s.ComputeStandardsAssessment(false)
	so, ao := runObservations(s, collectionResult(leaf, true), false, envOf(map[string]string{"GITHUB_ACTIONS": "true"}))
	s.Standards = standards.ComputeSplit(so, ao, standards.ScopeRun, standards.AudienceAgent)

	var human bytes.Buffer
	s.WriteHuman(&human)
	for _, want := range []string{
		"standards: observed ceilings, NOT verified levels",
		"SLSA Build: ceiling L2 (inline in GitHub Actions",
		"to reach L3:",
		"Coming, not yet published: the isolated provenance workflow",
		"ALPS-3: requires cilockd (not yet available)",
	} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("human summary lacks %q:\n%s", want, human.String())
		}
	}
	var js bytes.Buffer
	if err := s.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var out struct {
		SLSABuildLevel *int `json:"slsa_build_level"`
		Standards      struct {
			Schema    string                     `json:"schema"`
			Audience  string                     `json:"audience"`
			SLSABuild map[string]json.RawMessage `json:"slsa_build"`
			ALPS      map[string]json.RawMessage `json:"alps"`
			NextSteps []standards.NextStep       `json:"next_steps"`
		} `json:"standards"`
	}
	if err := json.Unmarshal(js.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.SLSABuildLevel != nil {
		t.Fatalf("legacy slsa_build_level must stay unset, got %d", *out.SLSABuildLevel)
	}
	if out.Standards.Schema != standards.GuidanceSchema || out.Standards.Audience != standards.AudienceAgent {
		t.Fatalf("schema/audience: %+v", out.Standards)
	}
	for name, m := range map[string]map[string]json.RawMessage{"slsa_build": out.Standards.SLSABuild, "alps": out.Standards.ALPS} {
		if string(m["verified_level"]) != "null" {
			t.Fatalf("%s.verified_level = %s, want null", name, m["verified_level"])
		}
	}
	if string(out.Standards.SLSABuild["ceiling"]) != `"L2"` || len(out.Standards.NextSteps) == 0 {
		t.Fatalf("ceiling %s, %d next steps", out.Standards.SLSABuild["ceiling"], len(out.Standards.NextSteps))
	}
}

func passed(t *testing.T, cert *x509.Certificate, timestamped bool, types ...string) policy.PassedCollection {
	t.Helper()
	cvr := source.CollectionVerificationResult{}
	kid := "k"
	if cert != nil {
		v, err := cryptoutil.NewX509Verifier(cert, nil, nil, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		cvr.ValidFunctionaries = []cryptoutil.Verifier{v}
		if kid, err = v.KeyID(); err != nil {
			t.Fatal(err)
		}
	}
	if timestamped {
		cvr.VerifiedTimestampsByKeyID = map[string][]time.Time{kid: {time.Now()}}
	}
	for _, ty := range types {
		cvr.Collection.Attestations = append(cvr.Collection.Attestations, attestation.CollectionAttestation{Type: ty})
	}
	return policy.PassedCollection{Collection: cvr}
}

// TestVerifyObservations: verify reads only the verified leaf, timestamps and
// attestation types. It never consults this machine's environment, so a
// verifier on a laptop sees the same ceiling CI would.
func TestVerifyObservations(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	// The leaves chain to platformCA, the policy's platform Fulcio root.
	platformCA, caKey := testCA(t)
	hosted := leafUnder(t, platformCA, caKey, certificate.Extensions{Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "github-hosted"})
	builder := leafUnder(t, platformCA, caKey, certificate.Extensions{Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "github-hosted", BuildSignerURI: provenanceWorkflowURI})
	noRunner := leafUnder(t, platformCA, caKey, certificate.Extensions{Issuer: standards.GitHubActionsIssuer})
	// The same workflow identity under another root (public Sigstore).
	publicCA, publicKey := testCA(t)
	publicHosted := leafUnder(t, publicCA, publicKey, certificate.Extensions{Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "github-hosted"})
	const prov = "https://slsa.dev/provenance/v1.0"

	cases := []struct {
		name       string
		results    map[string]policy.StepResult
		slsa, alps string
	}{
		{"inline provenance", map[string]policy.StepResult{"build": {Passed: []policy.PassedCollection{passed(t, hosted, true, prov)}}}, "L2", "ALPS-0"},
		{"provenance workflow", map[string]policy.StepResult{"build": {Passed: []policy.PassedCollection{passed(t, builder, true, prov)}}}, "L3", "ALPS-0"},
		{"leaf without runner ext, env ignored", map[string]policy.StepResult{"build": {Passed: []policy.PassedCollection{passed(t, noRunner, true, prov)}}}, "L1", "ALPS-0"},
		{"key-signed", map[string]policy.StepResult{"build": {Passed: []policy.PassedCollection{passed(t, nil, false, prov)}}}, "L1", "ALPS-0"},
		{"best of two steps", map[string]policy.StepResult{
			"a": {Passed: []policy.PassedCollection{passed(t, nil, true)}},
			"b": {Passed: []policy.PassedCollection{passed(t, hosted, true, prov)}},
		}, "L2", "ALPS-0"},
		// The strongest SLSA and ALPS evidence come from different collections:
		// key-signed provenance (L1, ALPS-0) and a timestamped workflow
		// signature over no provenance (none, ALPS-1). Each standard reports
		// its own best, not the SLSA winner's ALPS.
		{"strongest slsa and alps in different collections", map[string]policy.StepResult{
			"prov":  {Passed: []policy.PassedCollection{passed(t, nil, false, prov)}},
			"agent": {Passed: []policy.PassedCollection{passed(t, hosted, true)}},
		}, "L1", "ALPS-0"},
		// A workflow leaf with no timestamp and a key whose signature is
		// timestamped, in one collection: the timestamp covers the key's
		// signature only, so the workflow signer is not timestamped.
		{"timestamp on another signer", map[string]policy.StepResult{
			"build": {Passed: []policy.PassedCollection{twoSigners(t, hosted, prov)}},
		}, "L1", "ALPS-0"},
		// A timestamped workflow certificate that does not chain to the
		// platform root: the workflow name is not platform issuance.
		{"workflow leaf under another root", map[string]policy.StepResult{
			"build": {Passed: []policy.PassedCollection{passed(t, publicHosted, true, prov)}},
		}, "L2", "ALPS-0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o, ao, ok := verifyObservations(c.results)
			if !ok {
				t.Fatal("no observations from a passed collection")
			}
			g := standards.ComputeSplit(o, ao, standards.ScopeVerify, standards.AudienceHuman)
			if g.SLSABuild.Ceiling != c.slsa || g.ALPS.Ceiling != c.alps {
				t.Fatalf("ceilings %s/%s, want %s/%s", g.SLSABuild.Ceiling, g.ALPS.Ceiling, c.slsa, c.alps)
			}
		})
	}
	if g := verifyGuidance(map[string]policy.StepResult{"x": {}}); g != nil {
		t.Fatalf("guidance for a verify that passed nothing: %+v", g)
	}
}

// twoSigners is a passed collection verified by a workflow leaf with no
// timestamp and by a key functionary whose signature is timestamped.
func twoSigners(t *testing.T, cert *x509.Certificate, types ...string) policy.PassedCollection {
	t.Helper()
	pc := passed(t, cert, false, types...)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kv := cryptoutil.NewECDSAVerifier(&key.PublicKey, crypto.SHA256)
	kid, err := kv.KeyID()
	if err != nil {
		t.Fatal(err)
	}
	pc.Collection.ValidFunctionaries = append(pc.Collection.ValidFunctionaries, kv)
	pc.Collection.VerifiedTimestampsByKeyID = map[string][]time.Time{kid: {time.Now()}}
	return pc
}

// TestRunObservationsCertificateNamesItsSigner: the run's workflow identity
// never overrides a certificate. An untimestamped workflow signature beside a
// timestamped human certificate stays at L1 / ALPS-0: the human leaf is not an
// issued principal and not the runner.
func TestRunObservationsCertificateNamesItsSigner(t *testing.T) {
	wf := fulcioLeaf(t, certificate.Extensions{Issuer: standards.GitHubActionsIssuer})
	res := collectionResult(wf, false)
	human := humanLeaf(t)
	res[0].SignedEnvelope.Signatures = append(res[0].SignedEnvelope.Signatures, dsse.Signature{
		KeyID: "human", Signature: []byte("s"),
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: human.Raw}),
		Timestamps:  []dsse.SignatureTimestamp{{Type: dsse.TimestampRFC3161, Data: []byte("t")}},
	})
	so, ao := runObservations(&options.RunSummary{Signer: "fulcio", WorkflowIdentity: true, Attestors: slsaRan}, res, false,
		envOf(map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}))
	g := standards.ComputeSplit(so, ao, standards.ScopeRun, standards.AudienceHuman)
	if g.SLSABuild.Ceiling != "L1" || g.ALPS.Ceiling != "ALPS-0" {
		t.Fatalf("ceilings %s/%s, want L1/ALPS-0: the run's identity overrode a human certificate", g.SLSABuild.Ceiling, g.ALPS.Ceiling)
	}
}

// humanLeaf is a Fulcio-shaped leaf for a person: an email SAN, no CI issuer.
func humanLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), EmailAddresses: []string{"dev@example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRunObservationsPerSignature: a timestamp on one signature never
// timestamps another. An untimestamped workflow signature beside a
// timestamped key signature stays at L1 / ALPS-0.
func TestRunObservationsPerSignature(t *testing.T) {
	leaf := fulcioLeaf(t, certificate.Extensions{Issuer: standards.GitHubActionsIssuer, RunnerEnvironment: "github-hosted"})
	res := collectionResult(leaf, false)
	res[0].SignedEnvelope.Signatures = append(res[0].SignedEnvelope.Signatures, dsse.Signature{
		KeyID: "other", Signature: []byte("s"),
		Timestamps: []dsse.SignatureTimestamp{{Type: dsse.TimestampRFC3161, Data: []byte("t")}},
	})
	// With and without the run's confirmed workflow identity: the key
	// signature inherits neither that identity nor the hosted-runner fallback.
	for _, wf := range []bool{false, true} {
		so, ao := runObservations(&options.RunSummary{Signer: "fulcio", WorkflowIdentity: wf, Attestors: slsaRan}, res, false,
			envOf(map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}))
		g := standards.ComputeSplit(so, ao, standards.ScopeRun, standards.AudienceHuman)
		if g.SLSABuild.Ceiling != "L1" || g.ALPS.Ceiling != "ALPS-0" {
			t.Fatalf("workflow identity %v: ceilings %s/%s, want L1/ALPS-0: another signature's timestamp or the run's identity was borrowed",
				wf, g.SLSABuild.Ceiling, g.ALPS.Ceiling)
		}
	}
}

// testCA is a self-signed certificate authority for chain tests.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(10), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// leafUnder is a Fulcio-shaped code-signing leaf issued by ca.
func leafUnder(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ext certificate.Extensions) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exts, err := ext.Render()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(11), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), ExtraExtensions: exts,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
