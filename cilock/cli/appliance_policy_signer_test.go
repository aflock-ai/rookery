// jade:ring local

package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/require"
)

// The appliance release (testifysec/judge cd.yml, seed-appliance-bundle) bakes
// the policy signer in deploy/dist/appliance-policy-signer.json into the cilock
// it ships, then verifies every archive offline with that cilock. On v4.6.1
// (run 37671967734) every verify failed with "the signer identity matched no
// configured policy verifier" for the release's own signature, because the
// baked signer had commonname "" and uris ["*"]: a Fulcio GitHub Actions cert
// has an empty CommonName, and policysig relaxes an empty CN constraint only
// when a URI or email list pins identity concretely
// (attestation/policysig/policysig.go effectivePolicySignerCommonName), so the
// empty CN failed closed in attestation/policy/constraints.go
// checkCertConstraintGlob.
//
// These tests drive runVerify through the embedded-trust seam with the
// committed signer document, so the path under test is the shipped one:
// embedded trust -> applyEmbedded -> verify.go's policy-signer options ->
// policysig.

const applianceReleaseWorkflow = "https://github.com/testifysec/judge/.github/workflows/cd.yml"

// releaseIdentity is the Fulcio identity GitHub Actions gets for a workflow
// run: the SAN URI is the workflow at the ref, and the extensions carry the
// same facts. Each field mirrors the v4.6.1 signing certificate.
type releaseIdentity struct {
	repo     string // https://github.com/<owner>/<repo>
	workflow string // path under the repo, e.g. .github/workflows/cd.yml
	ref      string // refs/tags/v4.6.1
	issuer   string
}

func (id releaseIdentity) workflowURI() string {
	return id.repo + "/" + id.workflow + "@" + id.ref
}

func gaReleaseIdentity(ref string) releaseIdentity {
	return releaseIdentity{
		repo:     "https://github.com/testifysec/judge",
		workflow: ".github/workflows/cd.yml",
		ref:      ref,
		issuer:   "https://token.actions.githubusercontent.com",
	}
}

// readApplianceSigner loads the committed signer document the way
// seed-appliance.sh renders it: the comment key dropped, the roots added. Its
// policy_signers and policy_timestamp_roots go into the Trust verbatim; the
// decoder refuses unknown keys exactly as embeddedtrust.parse does.
func readApplianceSigner(t *testing.T, fulcioPEM, tsaPEM []byte) *embeddedtrust.Trust {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "dist", "appliance-policy-signer.json"))
	require.NoError(t, err)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &doc))
	delete(doc, "_comment")
	roots, err := json.Marshal([]embeddedtrust.Root{
		{Name: "testifysec-fulcio", Kind: embeddedtrust.KindFulcioRoot, PEM: string(fulcioPEM)},
		{Name: "testifysec-tsa", Kind: embeddedtrust.KindTSARoot, PEM: string(tsaPEM)},
	})
	require.NoError(t, err)
	doc["roots"] = roots
	body, err = json.Marshal(doc)
	require.NoError(t, err)
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var trust embeddedtrust.Trust
	require.NoError(t, dec.Decode(&trust))
	require.Len(t, trust.PolicySigners, 1)
	return &trust
}

// releaseLeaf issues a keyless leaf the way Fulcio does for a GitHub Actions
// token: empty subject, the workflow URI as the only SAN, the OIDC claims as
// 1.3.6.1.4.1.57264.1.* extensions.
func releaseLeaf(t *testing.T, id releaseIdentity, root *x509.Certificate, rootKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	exts, err := certificate.Extensions{
		Issuer:                              id.issuer,
		GithubWorkflowTrigger:               "push",
		GithubWorkflowRef:                   id.ref,
		BuildSignerURI:                      id.workflowURI(),
		RunnerEnvironment:                   "self-hosted",
		SourceRepositoryURI:                 id.repo,
		SourceRepositoryRef:                 id.ref,
		BuildConfigURI:                      id.workflowURI(),
		BuildTrigger:                        "push",
		RunInvocationURI:                    id.repo + "/actions/runs/37671967734/attempts/1",
		SourceRepositoryVisibilityAtSigning: "private",
	}.Render()
	require.NoError(t, err)
	san, err := url.Parse(id.workflowURI())
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{},
		NotBefore:       time.Now().Add(-time.Minute),
		NotAfter:        time.Now().Add(10 * time.Minute),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:            []*url.URL{san},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, root, &key.PublicKey, rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Empty(t, leaf.Subject.CommonName, "a Fulcio GitHub Actions leaf carries no CommonName")
	return leaf, key
}

// verifyAsShippedCilock signs a policy as id and runs `cilock verify` the way
// seed-appliance-bundle does: --policy, --attestations, --platform-url ”,
// archivista off, no --policy-* flag, so the embedded signer applies.
func verifyAsShippedCilock(t *testing.T, id releaseIdentity) error {
	t.Helper()
	sandboxVerifyEnv(t)
	root, rootKey, rootPEM := trustTestCert(t, "sigstore-intermediate", nil, nil)
	tsa := newTestTSA(t, time.Now(), nil, nil)
	srv := httptest.NewServer(tsa.handler(t, time.Time{}))
	t.Cleanup(srv.Close)
	trust := readApplianceSigner(t, rootPEM, certPEM(t, tsa.Root))
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return trust, nil })

	leaf, leafKey := releaseLeaf(t, id, root, rootKey)
	signer, err := cryptoutil.NewSigner(leafKey,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	require.NoError(t, err)

	dir := t.TempDir()
	sign := func(name, payloadType string, payload []byte) string {
		env, err := dsse.Sign(payloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer),
			dsse.SignWithTimestampers(timestamp.NewTimestamper(timestamp.TimestampWithUrl(srv.URL))))
		require.NoError(t, err)
		body, err := json.Marshal(env)
		require.NoError(t, err)
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, body, 0o600))
		return p
	}
	policyBody := []byte(`{"expires":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) +
		`","steps":{"appliance-build":{"name":"appliance-build","functionaries":[{"type":"root","certConstraint":{"commonname":"*","dnsnames":["*"],"emails":["*"],"organizations":["*"],"uris":["*"],"roots":["*"]}}],"attestations":[]}}}`)
	policyPath := sign("policy.json.signed", "https://witness.testifysec.com/policy/v0.1", policyBody)
	attPath := sign("build.attestation.json", "application/vnd.in-toto+json", []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[],"predicateType":"https://witness.dev/attestation-collection/v0.1","predicate":{"name":"appliance-build","attestations":[]}}`))
	artifact := filepath.Join(dir, "judge-api.tar.gz")
	require.NoError(t, os.WriteFile(artifact, []byte("archive"), 0o600))

	return runVerify(context.Background(), options.VerifyOptions{
		PolicyFilePath:       policyPath,
		AttestationFilePaths: []string{attPath},
		ArtifactFilePath:     artifact,
	}, nil, nil, false)
}

// signerIdentityRefused reports whether verify refused the policy signer's
// identity: the signature chained and was timestamped, and the cert matched no
// configured signer. That is the v4.6.1 error, and the only refusal the
// identity cases below may produce.
func signerIdentityRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "failed to verify policy signature") &&
		strings.Contains(err.Error(), "signer identity matched no configured policy verifier")
}

// TestApplianceSigner_AdmitsTheGAReleaseIdentity is the v4.6.1 failure: the
// release's own signature, cd.yml@refs/tags/vX.Y.Z on a GA tag, must clear
// the policy-signer check of the cilock that release ships. Past that check
// the run evaluates the policy's step against evidence this test deliberately
// does not supply, so the one acceptable error is the step verdict.
func TestApplianceSigner_AdmitsTheGAReleaseIdentity(t *testing.T) {
	for _, ref := range []string{"refs/tags/v4.6.1", "refs/tags/v4.6.2", "refs/tags/v10.0.0"} {
		t.Run(ref, func(t *testing.T) {
			err := verifyAsShippedCilock(t, gaReleaseIdentity(ref))
			require.False(t, signerIdentityRefused(err),
				"the appliance's own release signature was refused by its own cilock: %v", err)
			require.EqualError(t, err, "failed to verify policy: policy verification failed",
				"verify must get past the policy signature and fail only on the absent evidence")
		})
	}
}

// TestApplianceSigner_RefusesEveryOtherIdentity holds the pin on each
// dimension it admits: a cert that differs from the release identity in any
// one of workflow, ref, repository or issuer is refused. Each case changes
// the SAN and the extensions together, as Fulcio would.
func TestApplianceSigner_RefusesEveryOtherIdentity(t *testing.T) {
	ga := gaReleaseIdentity("refs/tags/v4.6.1")
	cases := map[string]releaseIdentity{
		"another workflow in the repo": {repo: ga.repo, workflow: ".github/workflows/ci.yml", ref: ga.ref, issuer: ga.issuer},
		"cd.yml on a branch":           {repo: ga.repo, workflow: ga.workflow, ref: "refs/heads/main", issuer: ga.issuer},
		"cd.yml on a non-v tag":        {repo: ga.repo, workflow: ga.workflow, ref: "refs/tags/hardener-v4.6.1", issuer: ga.issuer},
		"cd.yml in a fork":             {repo: "https://github.com/attacker/judge", workflow: ga.workflow, ref: ga.ref, issuer: ga.issuer},
		"another OIDC issuer":          {repo: ga.repo, workflow: ga.workflow, ref: ga.ref, issuer: "https://gitlab.com"},
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			err := verifyAsShippedCilock(t, id)
			require.True(t, signerIdentityRefused(err),
				"a policy signed by %s (%s) was not refused at the signer check: %v", id.workflowURI(), id.issuer, err)
		})
	}
}

// TestApplianceSigner_PinsTheURIDimension keeps the committed signer from
// regressing to a wildcard SAN: the URI list must name the release workflow,
// which is what lets policysig relax the CommonName a Fulcio leaf never has.
func TestApplianceSigner_PinsTheURIDimension(t *testing.T) {
	_, _, rootPEM := trustTestCert(t, "root", nil, nil)
	cc := readApplianceSigner(t, rootPEM, rootPEM).PolicySigners[0].CertConstraint
	require.NotEmpty(t, cc.URIs)
	for _, u := range cc.URIs {
		require.True(t, strings.HasPrefix(u, applianceReleaseWorkflow+"@"),
			"policy signer uri %q does not name the release workflow %s", u, applianceReleaseWorkflow)
	}
}
