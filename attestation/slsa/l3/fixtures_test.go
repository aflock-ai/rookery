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

package l3

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/sigstore/fulcio/pkg/certificate"
)

type certificateExtensions = certificate.Extensions

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
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
	return testCA{cert: cert, key: key}
}

// githubExtensions are the Fulcio extensions GitHub's principal renders for a
// job (subtrees/fulcio/pkg/identity/github/principal.go Embed).
func githubExtensions(jobWorkflowRef, jobWorkflowSha, repo, sha, runID, attempt, event, runner string) certificate.Extensions {
	return certificate.Extensions{
		Issuer:                 GitHubIssuer,
		BuildSignerURI:         "https://github.com/" + jobWorkflowRef,
		BuildSignerDigest:      jobWorkflowSha,
		RunnerEnvironment:      runner,
		SourceRepositoryURI:    "https://github.com/" + repo,
		SourceRepositoryDigest: sha,
		BuildTrigger:           event,
		RunInvocationURI:       "https://github.com/" + repo + "/actions/runs/" + runID + "/attempts/" + attempt,
		BuildConfigURI:         "https://github.com/" + repo + "/" + callerWorkflowPath + "@" + callerWorkflowRef,
	}
}

// The caller workflow (workflow_ref) the fixtures' jobs run under.
const (
	callerWorkflowPath = ".github/workflows/release.yml"
	callerWorkflowRef  = "refs/heads/main"
)

func (ca testCA) leaf(t *testing.T, ext certificate.Extensions) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := ext.Render()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: rendered,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func (ca testCA) sign(t *testing.T, ext certificate.Extensions, payload []byte) dsse.Envelope {
	t.Helper()
	cert, key := ca.leaf(t, ext)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithCertificate(cert))
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (ca testCA) trust(root Root) Trust {
	return Trust{Root: root, Options: []dsse.VerificationOption{dsse.VerifyWithRoots(ca.cert), dsse.VerifyWithCurrentTimeFallback()}}
}

type testSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

func statementJSON(t *testing.T, predicateType string, subjects []testSubject, predicate any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"_type": StatementTypeV1, "subject": subjects, "predicateType": predicateType, "predicate": predicate,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func provenancePredicate(builderID, invocationID, repo, sha string) map[string]any {
	return map[string]any{
		"buildDefinition": map[string]any{
			"buildType": BuildType,
			"externalParameters": map[string]any{"workflow": map[string]any{
				"repository": "https://github.com/" + repo, "path": callerWorkflowPath, "ref": callerWorkflowRef,
			}},
			"resolvedDependencies": []any{
				map[string]any{"uri": "git+https://github.com/" + repo, "digest": map[string]string{"gitCommit": sha}},
			},
		},
		"runDetails": map[string]any{
			"builder":  map[string]any{"id": builderID},
			"metadata": map[string]any{"invocationId": invocationID},
		},
	}
}
