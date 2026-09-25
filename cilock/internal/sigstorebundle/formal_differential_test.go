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

package sigstorebundle

// formal:differential
//
// Binds the Lean model of `cilock verify-bundle` (formal/sigstore,
// Sigstore/Bundle.lean, #9916) to this package.
//
//   - derive: every trusted root × timestamps present × inclusion promise ×
//     expected identity. Derive must return the model's policy or refuse
//     where the model refuses.
//   - e2e: bundles built on sigstore-go's VirtualSigstore (a Fulcio CA, TSA,
//     Rekor and CT log), with the trusted root masked to each profile and the
//     evidence stripped or corrupted. VerifyCertificate must reach the
//     procedure's verdict (SpecAccept). The test CA embeds no SCTs, so every
//     root that distributes CT logs must refuse.
//
// The vectors live in the Judge monorepo (formal/sigstore/vectors/bundle.json),
// so this test skips when rookery is built on its own, unless
// JADE_FORMAL_DIFFERENTIAL=1, which makes their absence a failure.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"
)

const formalBundleVectors = "../../../../../formal/sigstore/vectors/bundle.json"

const (
	formalSAN    = "https://github.com/acme/widget/.github/workflows/release.yml@refs/heads/main"
	formalIssuer = "https://token.actions.githubusercontent.com"
)

type formalRoot struct {
	TSA  bool `json:"tsa"`
	Tlog bool `json:"tlog"`
	CT   bool `json:"ct"`
}

type formalPolicy struct {
	SCT                  bool `json:"sct"`
	Tlog                 bool `json:"tlog"`
	SignedTimestamps     bool `json:"signed_timestamps"`
	IntegratedTimestamps bool `json:"integrated_timestamps"`
}

type formalVectors struct {
	Derive []struct {
		Root          formalRoot    `json:"root"`
		HasTimestamps bool          `json:"has_timestamps"`
		HasPromise    bool          `json:"has_promise"`
		Want          string        `json:"want"`
		Policy        *formalPolicy `json:"policy"`
	} `json:"derive"`
	E2E []struct {
		Root      formalRoot `json:"root"`
		Rekor     string     `json:"rekor"`
		Timestamp string     `json:"timestamp"`
		Tlog      bool       `json:"tlog"`
		Fault     string     `json:"fault"`
		Accept    bool       `json:"accept"`
	} `json:"e2e"`
}

func loadFormalVectors(t *testing.T) formalVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(formalBundleVectors))
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var v formalVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Derive)
	require.NotEmpty(t, v.E2E)
	return v
}

func formalWant(name string) (string, string) {
	switch name {
	case "empty-san":
		return "", formalIssuer
	case "empty-issuer":
		return formalSAN, ""
	default:
		return formalSAN, formalIssuer
	}
}

func TestFormalDifferentialDerive(t *testing.T) {
	v := loadFormalVectors(t)
	var policies, refusals int
	for i, c := range v.Derive {
		san, iss := formalWant(c.Want)
		p, err := Derive(Trust{TSA: c.Root.TSA, Tlog: c.Root.Tlog, CT: c.Root.CT},
			Evidence{Timestamps: c.HasTimestamps, Promise: c.HasPromise}, san, iss)
		if c.Policy == nil {
			require.Error(t, err, "case %d %+v: model refuses, Derive returned %+v", i, c, p)
			refusals++
			continue
		}
		require.NoError(t, err, "case %d %+v", i, c)
		require.Equal(t, Policy(*c.Policy), p, "case %d %+v", i, c)
		policies++
	}
	t.Logf("formal:differential: derive cases=%d policies=%d refusals=%d", len(v.Derive), policies, refusals)
	require.Positive(t, policies)
	require.Positive(t, refusals)
}

// maskedTrust hides the parts of a trusted root a profile does not distribute.
type maskedTrust struct {
	root.TrustedMaterial
	r formalRoot
}

func (m maskedTrust) TimestampingAuthorities() []root.TimestampingAuthority {
	if !m.r.TSA {
		return nil
	}
	return m.TrustedMaterial.TimestampingAuthorities()
}

func (m maskedTrust) RekorLogs() map[string]*root.TransparencyLog {
	if !m.r.Tlog {
		return nil
	}
	return m.TrustedMaterial.RekorLogs()
}

func (m maskedTrust) CTLogs() map[string]*root.TransparencyLog {
	if !m.r.CT {
		return nil
	}
	return m.TrustedMaterial.CTLogs()
}

// shapedEntity strips or corrupts the evidence of a test entity.
type shapedEntity struct {
	*ca.TestEntity
	timestamp string
	tlog      bool
}

func (s shapedEntity) Timestamps() ([][]byte, error) {
	ts, err := s.TestEntity.Timestamps()
	if err != nil {
		return nil, err
	}
	switch s.timestamp {
	case "absent":
		return nil, nil
	case "invalid":
		out := make([][]byte, len(ts))
		for i, t := range ts {
			b := bytes.Clone(t)
			b[len(b)-1] ^= 0xff // break the TSA's signature
			out[i] = b
		}
		return out, nil
	}
	return ts, nil
}

func (s shapedEntity) TlogEntries() ([]*tlog.Entry, error) {
	if !s.tlog {
		return nil, nil
	}
	return s.TestEntity.TlogEntries()
}

func TestFormalDifferentialVerifyBundle(t *testing.T) {
	v := loadFormalVectors(t)
	vs, err := ca.NewVirtualSigstore()
	require.NoError(t, err)

	artifact := []byte("formal/sigstore artifact")
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"` +
		sha256Hex(artifact) + `"}}],"predicateType":"https://example.com/p","predicate":{}}`)

	var accepted, refused int
	for i, c := range v.E2E {
		var entity *ca.TestEntity
		var artifactPolicy verify.ArtifactPolicyOption
		wrong := []byte("some other artifact")
		if c.Rekor == "v1" {
			entity, err = vs.SignAtTime(formalSAN, formalIssuer, artifact, time.Now().Add(2*time.Second))
			require.NoError(t, err)
			verified := artifact
			if c.Fault == "wrong-artifact" {
				verified = wrong
			}
			artifactPolicy = verify.WithArtifact(bytes.NewReader(verified))
		} else {
			entity, err = vs.AttestAtTimeHashedRekordV2(formalSAN, formalIssuer, statement, time.Now().Add(2*time.Second))
			require.NoError(t, err)
			d := artifactDigest(artifact)
			if c.Fault == "wrong-artifact" {
				d = artifactDigest(wrong)
			}
			artifactPolicy = verify.WithArtifactDigest("sha256", d)
		}
		san, iss := formalSAN, formalIssuer
		switch c.Fault {
		case "wrong-san":
			san = "https://github.com/acme/other/.github/workflows/release.yml@refs/heads/main"
		case "wrong-issuer":
			iss = "https://gitlab.com"
		case "empty-san":
			san = ""
		}
		_, err := VerifyCertificate(shapedEntity{entity, c.Timestamp, c.Tlog}, maskedTrust{vs, c.Root}, artifactPolicy, san, iss)
		got := err == nil
		require.Equal(t, c.Accept, got, "e2e case %d %+v: err=%v", i, c, err)
		if got {
			accepted++
		} else {
			refused++
		}
	}
	t.Logf("formal:differential: e2e cases=%d accepted=%d refused=%d", len(v.E2E), accepted, refused)
	require.Positive(t, accepted)
	require.Positive(t, refused)
}
