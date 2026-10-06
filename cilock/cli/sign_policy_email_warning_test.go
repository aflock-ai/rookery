// jade:ring local

// Copyright 2026 The Aflock Authors
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
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
)

type certOnlySigner struct {
	cryptoutil.Signer
	cert *x509.Certificate
}

func (s certOnlySigner) Certificate() *x509.Certificate     { return s.cert }
func (s certOnlySigner) Intermediates() []*x509.Certificate { return nil }
func (s certOnlySigner) Roots() []*x509.Certificate         { return nil }

const emailWarnPolicy = `{"expires":"2030-01-01T00:00:00Z","steps":{}}`

func TestWarnEmailSignedPolicy_EmailOnlyIdentityWarns(t *testing.T) {
	var w bytes.Buffer
	s := certOnlySigner{cert: &x509.Certificate{EmailAddresses: []string{"dev@example.com"}}}
	warnEmailSignedPolicy(&w, []byte(emailWarnPolicy), "", s)
	assert.Contains(t, w.String(), "--policy-emails dev@example.com")
}

func TestWarnEmailSignedPolicy_WorkflowIdentityIsSilent(t *testing.T) {
	var w bytes.Buffer
	u, _ := url.Parse("https://github.com/o/r/.github/workflows/a.yml@refs/heads/main")
	s := certOnlySigner{cert: &x509.Certificate{EmailAddresses: []string{"dev@example.com"}, URIs: []*url.URL{u}}}
	warnEmailSignedPolicy(&w, []byte(emailWarnPolicy), "", s)
	assert.Empty(t, w.String())
}

func TestWarnEmailSignedPolicy_NonPolicyAndNoCertAreSilent(t *testing.T) {
	var w bytes.Buffer
	s := certOnlySigner{cert: &x509.Certificate{EmailAddresses: []string{"dev@example.com"}}}
	warnEmailSignedPolicy(&w, []byte(`{"a":1}`), "", s)
	warnEmailSignedPolicy(&w, []byte(emailWarnPolicy), "", certOnlySigner{})
	assert.Empty(t, w.String())
}
