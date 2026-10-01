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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/slsa/l3"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/sigstore/fulcio/pkg/certificate"
)

const slsaTestPin = "0123456789abcdef0123456789abcdef01234567"

type slsaTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newSLSATestCA(t *testing.T) slsaTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "slsa test fulcio"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return slsaTestCA{cert: cert, key: key}
}

// signGitHub signs payload with a leaf carrying the Fulcio extensions GitHub's
// principal renders for a job with these claims, timestamped by a fake TSA.
func (ca slsaTestCA) signGitHub(t *testing.T, jobWorkflowRef, jobWorkflowSha, event, runner string, payload []byte) dsse.Envelope {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := certificate.Extensions{
		Issuer: l3.GitHubIssuer, BuildSignerURI: "https://github.com/" + jobWorkflowRef, BuildSignerDigest: jobWorkflowSha,
		RunnerEnvironment: runner, SourceRepositoryURI: "https://github.com/acme/app", SourceRepositoryDigest: strings.Repeat("1", 40),
		BuildTrigger: event, RunInvocationURI: "https://github.com/acme/app/actions/runs/7/attempts/1",
		BuildConfigURI: "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main",
	}.Render()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, ExtraExtensions: ext,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithCertificate(leaf))
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer),
		dsse.SignWithTimestampers(timestamp.FakeTimestamper{T: time.Now()}))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

type slsaTestFixture struct {
	dir, artifact, build, provenance string
	digest                           string
}

// newSLSAFixture writes an artifact, the build job's collection and the
// provenance workflow's SLSA v1 statement for it.
func newSLSAFixture(t *testing.T, ca slsaTestCA, provRef, provSha, event, runner string) slsaTestFixture {
	t.Helper()
	dir := t.TempDir()
	art := filepath.Join(dir, "app")
	if err := os.WriteFile(art, []byte("the built artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("the built artifact"))
	digest := hex.EncodeToString(sum[:])
	subjects := []map[string]any{{"name": "app", "digest": map[string]string{"sha256": digest}}}
	stmt := func(predicateType string, predicate any) []byte {
		b, err := json.Marshal(map[string]any{"_type": l3.StatementTypeV1, "subject": subjects, "predicateType": predicateType, "predicate": predicate})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	write := func(name string, env dsse.Envelope) string {
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	build := ca.signGitHub(t, "acme/app/.github/workflows/release.yml@refs/heads/main", strings.Repeat("1", 40), "push", "github-hosted",
		stmt(attestation.CollectionType, map[string]any{"name": "build"}))
	prov := ca.signGitHub(t, provRef, provSha, event, runner, stmt(l3.ProvenancePredicateType, map[string]any{
		"buildDefinition": map[string]any{
			"buildType": l3.BuildType,
			"externalParameters": map[string]any{"workflow": map[string]any{
				"repository": "https://github.com/acme/app", "path": ".github/workflows/release.yml", "ref": "refs/heads/main",
			}},
			"resolvedDependencies": []any{map[string]any{"uri": "git+https://github.com/acme/app", "digest": map[string]string{"gitCommit": strings.Repeat("1", 40)}}},
		},
		"runDetails": map[string]any{
			"builder":  map[string]any{"id": "https://github.com/" + provRef},
			"metadata": map[string]any{"invocationId": "https://github.com/acme/app/actions/runs/7/attempts/1"},
		},
	}))
	return slsaTestFixture{dir: dir, artifact: art, build: write("build.json", build), provenance: write("provenance.json", prov), digest: digest}
}

// withSLSATestTrust makes the platform root the test CA with a fake TSA.
func withSLSATestTrust(t *testing.T, ca slsaTestCA) {
	t.Helper()
	orig := slsaLevelTrusts
	slsaLevelTrusts = func(_ *options.VerifyOptions, roots []l3.Root) ([]l3.Trust, error) {
		out := make([]l3.Trust, 0, len(roots))
		for _, r := range roots {
			out = append(out, l3.Trust{Root: r, Options: []dsse.VerificationOption{
				dsse.VerifyWithRoots(ca.cert), dsse.VerifyWithTimestampVerifiers(timestamp.FakeTimestamper{T: time.Now()}),
			}})
		}
		return out, nil
	}
	t.Cleanup(func() { slsaLevelTrusts = orig })
}

func runVerifyArgs(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	cmd := VerifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(append([]string{"--platform-url", ""}, args...))
	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	os.Stdout = w
	err = cmd.Execute()
	_ = w.Close()
	os.Stdout = origStdout
	var captured bytes.Buffer
	_, _ = captured.ReadFrom(r)
	return captured.String() + out.String(), err
}

func TestVerifySLSALevel3AcceptsHonestProvenance(t *testing.T) {
	ca := newSLSATestCA(t)
	withSLSATestTrust(t, ca)
	f := newSLSAFixture(t, ca, l3.WorkflowPath+"@"+slsaTestPin, slsaTestPin, "push", "github-hosted")
	vsa := filepath.Join(f.dir, "vsa.json")
	out, err := runVerifyArgs(t, f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app",
		"-a", f.build, "-a", f.provenance, "--format", "json", "--vsa-outfile", vsa)
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, out)
	}
	var v VerifyVerdict
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		t.Fatalf("stdout is not one JSON verdict: %v\n%s", err, out)
	}
	if !v.Passed || v.SLSALevel != 3 || v.MatchedSubject != "sha256:"+f.digest {
		t.Fatalf("verdict %+v", v)
	}
	raw, err := os.ReadFile(vsa)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate l3.VSA `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.PredicateType != "https://slsa.dev/verification_summary/v1" || st.Predicate.VerificationResult != "PASSED" ||
		len(st.Predicate.VerifiedLevels) != 1 || st.Predicate.VerifiedLevels[0] != "SLSA_BUILD_LEVEL_3" ||
		len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] != f.digest || len(st.Predicate.InputAttestations) != 2 {
		t.Fatalf("VSA %s", raw)
	}
}

func TestVerifySLSALevel3RefusesAndSaysWhy(t *testing.T) {
	ca := newSLSATestCA(t)
	withSLSATestTrust(t, ca)
	for name, c := range map[string]struct {
		ref, sha, event, runner string
		want                    l3.Requirement
	}{
		"tag pin":             {l3.WorkflowPath + "@refs/tags/v1", slsaTestPin, "push", "github-hosted", l3.ReqSignerRef},
		"pull_request_target": {l3.WorkflowPath + "@" + slsaTestPin, slsaTestPin, "pull_request_target", "github-hosted", l3.ReqTrigger},
		"self-hosted":         {l3.WorkflowPath + "@" + slsaTestPin, slsaTestPin, "push", "self-hosted", l3.ReqHostedRunner},
		"other workflow":      {"acme/app/.github/workflows/release.yml@" + slsaTestPin, slsaTestPin, "push", "github-hosted", l3.ReqSignerWorkflow},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSLSAFixture(t, ca, c.ref, c.sha, c.event, c.runner)
			out, err := runVerifyArgs(t, f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app",
				"-a", f.build, "-a", f.provenance, "--format", "json")
			if err == nil {
				t.Fatalf("verify passed:\n%s", out)
			}
			var v VerifyVerdict
			if jerr := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); jerr != nil {
				t.Fatalf("stdout is not one JSON verdict: %v\n%s", jerr, out)
			}
			found := false
			for _, f := range v.SLSAFailures {
				found = found || f.Requirement == c.want
			}
			if v.Passed || v.SLSALevel != 0 || !found {
				t.Fatalf("verdict %+v; want a %s failure", v, c.want)
			}
		})
	}
}

// Requirement 7 through the CLI: the artifact named on the command line must
// be among the provenance's subjects.
// The audit's N6a case, end to end: provenance signed with a bare key (no
// Fulcio certificate, so no signer identity) that claims the isolated
// workflow's builder.id must exit non-zero, even with the key trusted.
func TestVerifySLSALevel3RefusesKeySignedFakeL3(t *testing.T) {
	ca := newSLSATestCA(t)
	f := newSLSAFixture(t, ca, l3.WorkflowPath+"@"+slsaTestPin, slsaTestPin, "push", "github-hosted")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoutil.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	var prov dsse.Envelope
	raw, err := os.ReadFile(f.provenance)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &prov); err != nil {
		t.Fatal(err)
	}
	fake, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(prov.Payload), dsse.SignWithSigners(signer))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(fake)
	if err != nil {
		t.Fatal(err)
	}
	fakePath := filepath.Join(f.dir, "fake-l3.json")
	if err := os.WriteFile(fakePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	orig := slsaLevelTrusts
	slsaLevelTrusts = func(_ *options.VerifyOptions, roots []l3.Root) ([]l3.Trust, error) {
		return []l3.Trust{{Root: l3.RootPlatform, Options: []dsse.VerificationOption{
			dsse.VerifyWithRoots(ca.cert), dsse.VerifyWithVerifiers(verifier),
			dsse.VerifyWithTimestampVerifiers(timestamp.FakeTimestamper{T: time.Now()}),
		}}}, nil
	}
	t.Cleanup(func() { slsaLevelTrusts = orig })
	_, err = runVerifyArgs(t, f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app",
		"-a", f.build, "-a", fakePath)
	if err == nil || !strings.Contains(err.Error(), string(l3.ReqProvenance)) {
		t.Fatalf("err = %v; want the key-signed fake refused as %s", err, l3.ReqProvenance)
	}
}

// A fork's self-consistent L3 evidence is refused for the expected repository.
func TestVerifySLSALevel3RefusesAnotherRepository(t *testing.T) {
	ca := newSLSATestCA(t)
	withSLSATestTrust(t, ca)
	f := newSLSAFixture(t, ca, l3.WorkflowPath+"@"+slsaTestPin, slsaTestPin, "push", "github-hosted")
	_, err := runVerifyArgs(t, f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/other",
		"-a", f.build, "-a", f.provenance)
	if err == nil || !strings.Contains(err.Error(), string(l3.ReqExpectedRepo)) {
		t.Fatalf("err = %v; want %s", err, l3.ReqExpectedRepo)
	}
}

func TestVerifySLSALevel3ArtifactMustBeCovered(t *testing.T) {
	ca := newSLSATestCA(t)
	withSLSATestTrust(t, ca)
	f := newSLSAFixture(t, ca, l3.WorkflowPath+"@"+slsaTestPin, slsaTestPin, "push", "github-hosted")
	_, err := runVerifyArgs(t, "--subjects", "sha256:"+strings.Repeat("b", 64), "--slsa-level", "3",
		"--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app", "-a", f.build, "-a", f.provenance)
	if err == nil || !strings.Contains(err.Error(), string(l3.ReqCallerSubjects)) {
		t.Fatalf("err = %v; want a %s refusal", err, l3.ReqCallerSubjects)
	}
}

func TestVerifySLSALevelUsageRefusals(t *testing.T) {
	ca := newSLSATestCA(t)
	withSLSATestTrust(t, ca)
	f := newSLSAFixture(t, ca, l3.WorkflowPath+"@"+slsaTestPin, slsaTestPin, "push", "github-hosted")
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"level 2":            {[]string{f.artifact, "--slsa-level", "2", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app", "-a", f.provenance}, "only level 3"},
		"no pin":             {[]string{f.artifact, "--slsa-level", "3", "-a", f.provenance}, "--slsa-builder-digest"},
		"no source repo":     {[]string{f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "-a", f.provenance}, "--slsa-source-repo"},
		"glob source repo":   {[]string{f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/*", "-a", f.provenance}, "<owner>/<name>"},
		"tag as pin":         {[]string{f.artifact, "--slsa-level", "3", "--slsa-builder-digest", "v1", "--slsa-source-repo", "acme/app", "-a", f.provenance}, "commit SHA"},
		"with a policy":      {[]string{f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app", "-a", f.provenance, "-p", "policy.json"}, "built-in"},
		"no evidence":        {[]string{f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app"}, "--attestations"},
		"no subject":         {[]string{"--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app", "-a", f.provenance}, "artifact"},
		"non-sha256 subject": {[]string{"--subjects", "sha1:abc", "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app", "-a", f.provenance}, "sha256"},
		"unknown root":       {[]string{f.artifact, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app", "-a", f.provenance, "--slsa-roots", "rekor"}, "unknown root"},
		"directory subject":  {[]string{"--directory-path", f.dir, "--slsa-level", "3", "--slsa-builder-digest", slsaTestPin, "--slsa-source-repo", "acme/app", "-a", f.provenance}, "directory"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runVerifyArgs(t, c.args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v; want it to mention %q", err, c.want)
			}
		})
	}
}

// The trust roots: platform from the policy-CA sources, public Sigstore only
// with its own roots and TSA, and never a Fulcio chain without a TSA.
func TestSLSALevelTrustsRequireRootsAndTimestamps(t *testing.T) {
	dir := t.TempDir()
	ca := newSLSATestCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	vo := options.VerifyOptions{NoEmbeddedTrust: true}
	if _, err := buildSLSALevelTrusts(&vo, []l3.Root{l3.RootPlatform}); err == nil || !strings.Contains(err.Error(), "--policy-ca-roots") {
		t.Fatalf("no platform root: err = %v", err)
	}
	vo.PolicyCARootPaths = []string{caPath}
	if _, err := buildSLSALevelTrusts(&vo, []l3.Root{l3.RootPlatform}); err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("no platform TSA: err = %v", err)
	}
	vo.PolicyTimestampServers = []string{caPath}
	trusts, err := buildSLSALevelTrusts(&vo, []l3.Root{l3.RootPlatform})
	if err != nil || len(trusts) != 1 || trusts[0].Root != l3.RootPlatform {
		t.Fatalf("platform trust: %v %v", trusts, err)
	}
	if _, err := buildSLSALevelTrusts(&vo, []l3.Root{l3.RootPublicSigstore}); err == nil || !strings.Contains(err.Error(), "--slsa-public-sigstore-ca-roots") {
		t.Fatalf("public Sigstore without roots: err = %v", err)
	}
	vo.SLSAPublicSigstoreCARootPaths = []string{caPath}
	if _, err := buildSLSALevelTrusts(&vo, []l3.Root{l3.RootPublicSigstore}); err == nil || !strings.Contains(err.Error(), "--slsa-public-sigstore-timestamp-servers") {
		t.Fatalf("public Sigstore without TSA: err = %v", err)
	}
	vo.SLSAPublicSigstoreTimestampServers = []string{caPath}
	trusts, err = buildSLSALevelTrusts(&vo, []l3.Root{l3.RootPlatform, l3.RootPublicSigstore})
	if err != nil || len(trusts) != 2 || trusts[1].Root != l3.RootPublicSigstore {
		t.Fatalf("both roots: %v %v", trusts, err)
	}
}
