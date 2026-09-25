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

// #9818: every policy rookery ships (deploy/, examples/, and the JSON snippets
// in the docs) must admit a GitHub-shaped keyless leaf under the CLI's DEFAULT
// hardening. deploy/cilock/release.policy.json left dnsnames/emails/
// organizations unset; since #6463 made enforce the default, an unset SAN list
// refuses a leaf that has none of that SAN type, and a GitHub Actions Fulcio
// leaf has none. The release workflow's own publish gate would have refused
// its own binaries. This test walks the tree so a new shipped policy with the
// same shape fails here instead of in a release run.
//
// It mutates the process-global hardening options, so it must not call
// t.Parallel().

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/require"
)

const (
	githubIssuer      = "https://token.actions.githubusercontent.com"
	githubWorkflowURI = "https://github.com/example/repo/.github/workflows/release.yml@refs/tags/v1.0.0"
)

// shippedFunctionary is one X.509 functionary found in a shipped policy.
type shippedFunctionary struct {
	where string
	cc    policy.CertConstraint
}

var jsonFence = regexp.MustCompile("(?s)```json[^\\n]*\\n(.*?)```")

func TestShippedPoliciesAdmitGitHubKeylessLeafUnderEnforcedHardening(t *testing.T) {
	root := filepath.Join("..", "..") // subtrees/rookery
	found := collectShippedFunctionaries(t, root)

	// Non-vacuous: the release policy is the one that motivated this test and
	// must be among the functionaries checked.
	sawRelease := false
	for _, f := range found {
		if strings.HasPrefix(f.where, filepath.Join("deploy", "cilock", "release.policy.json")) {
			sawRelease = true
		}
	}
	require.True(t, sawRelease, "release.policy.json was not discovered; the walk is broken")

	resetHardeningAfter(t)
	policy.SetHardening(enforcedHardening())

	for _, f := range found {
		t.Run(f.where, func(t *testing.T) {
			verifier, bundles := githubShapedLeafFor(t, f.cc)
			fn := policy.Functionary{Type: "root", CertConstraint: f.cc}
			require.NoError(t, fn.Validate(verifier, bundles),
				"%s refuses a GitHub-shaped keyless leaf under the CLI's default (enforced) hardening; set every unconstrained SAN list to [\"*\"]", f.where)
		})
	}
}

// collectShippedFunctionaries finds every root-type functionary in the policy
// JSON files and the ```json doc snippets under root. Test fixtures are not
// shipped, so testdata/ is skipped.
func collectShippedFunctionaries(t *testing.T, root string) []shippedFunctionary {
	t.Helper()
	var out []shippedFunctionary
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			raw, readErr := os.ReadFile(path) //nolint:gosec // test walks its own source tree
			if readErr != nil {
				return readErr
			}
			out = append(out, functionariesInDoc(t, rel, raw)...)
		case ".md", ".mdx":
			raw, readErr := os.ReadFile(path) //nolint:gosec // test walks its own source tree
			if readErr != nil {
				return readErr
			}
			for i, m := range jsonFence.FindAllSubmatch(raw, -1) {
				out = append(out, functionariesInDoc(t, rel+"#json"+strconv.Itoa(i), m[1])...)
			}
		}
		return nil
	})
	require.NoError(t, err)
	return out
}

// functionariesInDoc recognises three shapes: a whole policy (steps), a
// functionary (certConstraint), and a bare cert constraint (commonname+roots).
// Anything else, including JSON that does not parse, is not a policy. Only the
// functionaries are decoded, so a doc snippet's placeholder root certificate
// or rego module does not hide its functionaries; a policy-shaped document
// whose functionaries do not decode fails the test rather than being skipped.
func functionariesInDoc(t *testing.T, where string, raw []byte) []shippedFunctionary {
	t.Helper()
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return nil
	}
	if steps, ok := probe["steps"]; ok {
		var p map[string]struct {
			Functionaries []policy.Functionary `json:"functionaries"`
		}
		require.NoError(t, json.Unmarshal(steps, &p), "%s looks like a policy but its steps do not decode", where)
		var out []shippedFunctionary
		for name, step := range p {
			for i, fn := range step.Functionaries {
				if fn.PublicKeyID != "" && !fn.CertConstraint.IsSet() {
					continue
				}
				out = append(out, shippedFunctionary{where: where + ":" + name + "[" + strconv.Itoa(i) + "]", cc: fn.CertConstraint})
			}
		}
		return out
	}
	if _, ok := probe["certConstraint"]; ok {
		var fn policy.Functionary
		if json.Unmarshal(raw, &fn) != nil || fn.PublicKeyID != "" {
			return nil
		}
		return []shippedFunctionary{{where: where, cc: fn.CertConstraint}}
	}
	_, hasCN := probe["commonname"]
	_, hasRoots := probe["roots"]
	if hasCN && hasRoots {
		var cc policy.CertConstraint
		if json.Unmarshal(raw, &cc) != nil {
			return nil
		}
		return []shippedFunctionary{{where: where, cc: cc}}
	}
	return nil
}

// githubShapedLeafFor issues a leaf shaped like a GitHub Actions Fulcio cert:
// empty subject, one URI SAN, Fulcio extensions, and no DNS, email or
// organization. Fields the constraint pins get a value that satisfies the pin,
// so the only thing under test is how the policy treats the fields it does not
// pin. Every root ID the constraint names is mapped to the test CA.
func githubShapedLeafFor(t *testing.T, cc policy.CertConstraint) (cryptoutil.Verifier, map[string]policy.TrustBundle) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if cc.CommonName != policy.AllowAllConstraint {
		leaf.Subject.CommonName = instantiateGlob(t, cc.CommonName)
	}
	leaf.DNSNames = pinnedValues(t, cc.DNSNames)
	leaf.EmailAddresses = pinnedValues(t, cc.Emails)
	leaf.Subject.Organization = pinnedValues(t, cc.Organizations)

	uris := pinnedValues(t, cc.URIs)
	if len(uris) == 0 {
		uris = []string{githubWorkflowURI} // a GitHub Fulcio leaf always has one
	}
	for _, u := range uris {
		parsed, parseErr := url.Parse(u)
		require.NoError(t, parseErr)
		leaf.URIs = append(leaf.URIs, parsed)
	}

	ext := instantiateExtensions(t, cc.Extensions)
	if ext.Issuer == "" {
		ext.Issuer = githubIssuer
	}
	rendered, err := ext.Render()
	require.NoError(t, err)
	leaf.ExtraExtensions = rendered

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	verifier, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	bundles := map[string]policy.TrustBundle{"test-root": {Root: ca}}
	for _, id := range cc.Roots {
		bundles[id] = policy.TrustBundle{Root: ca}
	}
	return verifier, bundles
}

// pinnedValues returns a satisfying value for each pinned entry of a SAN list,
// or nothing when the list is empty or allows all (the GitHub leaf's shape).
func pinnedValues(t *testing.T, constraints []string) []string {
	t.Helper()
	var out []string
	for _, c := range constraints {
		if c == policy.AllowAllConstraint {
			return nil
		}
		if c != "" {
			out = append(out, instantiateGlob(t, c))
		}
	}
	return out
}

func instantiateExtensions(t *testing.T, ext certificate.Extensions) certificate.Extensions {
	t.Helper()
	v := reflect.ValueOf(&ext).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.String && f.String() != "" {
			f.SetString(instantiateGlob(t, f.String()))
		}
	}
	return ext
}

// instantiateGlob returns one string the glob pattern matches. Shipped
// policies use only '*', '?' and '{a,b}'; a character class fails the test so
// the helper is extended deliberately rather than guessing.
func instantiateGlob(t *testing.T, pattern string) string {
	t.Helper()
	require.NotContains(t, pattern, "[", "instantiateGlob does not handle character classes: %q", pattern)
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; c {
		case '*', '?':
			b.WriteByte('x')
		case '{':
			end := strings.IndexByte(pattern[i:], '}')
			require.Positive(t, end, "unterminated alternation in %q", pattern)
			alt := pattern[i+1 : i+end]
			if comma := strings.IndexByte(alt, ','); comma >= 0 {
				alt = alt[:comma]
			}
			b.WriteString(alt)
			i += end
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
