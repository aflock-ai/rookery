package embeddedtrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfSignedPEM mints a throwaway self-signed cert so root parsing can be
// exercised without committing real CA material into the test.
func selfSignedPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParse_EmptyIsNil(t *testing.T) {
	for _, in := range []string{"", "  ", "{}", "  {}\n"} {
		got, err := parse([]byte(in))
		require.NoError(t, err)
		assert.Nil(t, got, "empty/`{}` trust must parse to nil (no embedded trust)")
	}
}

func TestParse_NoRootsNoSignersIsNil(t *testing.T) {
	got, err := parse([]byte(`{"policy_timestamp_roots":["x"]}`))
	require.NoError(t, err)
	assert.Nil(t, got, "a document with neither roots nor signers is treated as no embedded trust")
}

func TestParse_RejectsUnknownKeys(t *testing.T) {
	_, err := parse([]byte(`{"rootz":[]}`))
	require.Error(t, err, "unknown keys must fail loudly so a typo can't silently weaken trust")
}

func TestParse_ValidTrust(t *testing.T) {
	doc := fmt.Sprintf(`{
      "roots": [
        {"name":"f","kind":"FULCIO_ROOT","pem":%q},
        {"name":"t","kind":"TSA_ROOT","pem":%q}
      ],
      "policy_signers": [
        {"type":"root","certConstraint":{
          "commonname":"","dnsnames":[],"emails":[],"organizations":[],
          "uris":["*"],"roots":["f"],
          "extensions":{"Issuer":"https://token.actions.githubusercontent.com","SourceRepositoryURI":"https://github.com/testifysec/judge","BuildConfigURI":"https://github.com/testifysec/judge/.github/workflows/release-self-host-minimal.yml@*"}
        }}
      ],
      "policy_timestamp_roots": ["t"]
    }`, selfSignedPEM(t, "fulcio"), selfSignedPEM(t, "tsa"))

	tr, err := parse([]byte(doc))
	require.NoError(t, err)
	require.NotNil(t, tr)

	require.Len(t, tr.PolicySigners, 1)
	cc := tr.PolicySigners[0].CertConstraint
	assert.Equal(t, []string{"*"}, cc.URIs)
	assert.Equal(t, "https://github.com/testifysec/judge", cc.Extensions.SourceRepositoryURI)
	assert.Equal(t, "https://github.com/testifysec/judge/.github/workflows/release-self-host-minimal.yml@*", cc.Extensions.BuildConfigURI)

	fulcio, err := tr.FulcioRoots()
	require.NoError(t, err)
	require.Len(t, fulcio, 1)
	assert.Equal(t, "fulcio", fulcio[0].Subject.CommonName)

	tsa, err := tr.TSARoots()
	require.NoError(t, err)
	require.Len(t, tsa, 1)
	assert.Equal(t, "tsa", tsa[0].Subject.CommonName)
}

// TSARoots must honor the PolicyTSARoots name filter so a binary can ship
// multiple TSA bundles but anchor the policy signature on a specific one.
func TestTSARoots_NameFilter(t *testing.T) {
	doc := fmt.Sprintf(`{
      "roots": [
        {"name":"keep","kind":"TSA_ROOT","pem":%q},
        {"name":"drop","kind":"TSA_ROOT","pem":%q}
      ],
      "policy_signers": [{"type":"root","certConstraint":{"uris":["*"]}}],
      "policy_timestamp_roots": ["keep"]
    }`, selfSignedPEM(t, "keep-tsa"), selfSignedPEM(t, "drop-tsa"))

	tr, err := parse([]byte(doc))
	require.NoError(t, err)
	tsa, err := tr.TSARoots()
	require.NoError(t, err)
	require.Len(t, tsa, 1)
	assert.Equal(t, "keep-tsa", tsa[0].Subject.CommonName)
}

func TestFulcioRoots_BadPEMErrors(t *testing.T) {
	doc := `{"roots":[{"name":"bad","kind":"FULCIO_ROOT","pem":"not a cert"}],"policy_signers":[{"type":"root","certConstraint":{"uris":["*"]}}]}`
	tr, err := parse([]byte(doc))
	require.NoError(t, err)
	_, err = tr.FulcioRoots()
	require.Error(t, err, "an unparseable embedded root must error, not be silently dropped")
}

// The committed default embedded in the binary must be empty, so a stock build
// requires explicit --policy-* trust and only purpose-built binaries embed it.
func TestCommittedDefaultIsEmpty(t *testing.T) {
	got, err := Load()
	require.NoError(t, err)
	assert.Nil(t, got, "committed trust.json default must embed no trust")
}
