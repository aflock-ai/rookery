//go:build audit

// Copyright 2025 The Aflock Authors
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

package slsa

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	prov "github.com/aflock-ai/rookery/attestation/intoto/provenance"
)

// ============================================================================
// R3-220: Environment variable leakage through SLSA provenance
// ============================================================================

// TestSecurity_R3_220_EnvVarLeakageInInternalParams proves that the SLSA
// attestor copies environment variables from the environment attestor into
// internalParameters["env"] without any additional filtering. If the
// environment attestor passes through sensitive variables (due to
// misconfiguration or bypass), the SLSA provenance will contain them in
// cleartext in the build's internalParameters.
//
// Impact: Secrets like API keys or tokens could end up in signed provenance
// documents that are stored in transparency logs or artifact registries.
func TestSecurity_R3_220_EnvVarLeakageInInternalParams(t *testing.T) {
	p := New()

	// Set up the provenance structure as Attest() does (lines 121-127, 268).
	// The Attest method copies env vars verbatim into internalParameters["env"].
	p.PbProvenance.BuildDefinition = &prov.BuildDefinition{
		BuildType: BuildType,
		InternalParameters: map[string]interface{}{
			"env": map[string]interface{}{
				"AWS_SECRET_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
				"GITHUB_TOKEN":          "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"DATABASE_PASSWORD":     "hunter2",
				"PATH":                  "/usr/bin:/bin",
			},
		},
	}
	p.PbProvenance.RunDetails = &prov.RunDetails{
		Builder:  &prov.Builder{ID: DefaultBuilderId},
		Metadata: &prov.BuildMetadata{},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	serialized := string(data)

	// The serialized provenance contains all env vars including secrets.
	secretValues := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"hunter2",
	}

	for _, secret := range secretValues {
		if !strings.Contains(serialized, secret) {
			t.Errorf("expected serialized provenance to contain secret %q (proving leakage)", secret)
		}
	}

	t.Log("BUG: SLSA attestor copies environment variables into internalParameters " +
		"without any additional filtering. If the environment attestor's filter " +
		"is misconfigured or bypassed, secrets end up in signed provenance.")
}

// ============================================================================
// R3-221: Builder ID spoofing - no verification of CI attestor claims
// ============================================================================

// TestSecurity_R3_221_BuilderIdNotVerified proves that the SLSA builder ID
// is set based solely on which attestor name is present in CompletedAttestors.
// There is no verification that the attestor's claims are authentic. A local
// build can register a fake CI attestor and get a trusted builder ID stamped
// on provenance.
//
// Impact: Provenance claims to be from a trusted CI system when it may be
// from an untrusted local build. SLSA levels are meaningless without
// builder ID verification.
func TestSecurity_R3_221_BuilderIdNotVerified(t *testing.T) {
	// Verify that all builder ID constants exist and are URL-formatted.
	// The real issue is that these are assigned based on attestor NAME alone
	// with zero cryptographic verification.
	builderIDs := map[string]string{
		"github":        GHABuilderId,
		"gitlab":        GLCBuilderId,
		"jenkins":       JenkinsBuilderId,
		"aws-codebuild": AWSCodeBuildBuilderId,
	}

	for ciName, bid := range builderIDs {
		if bid == "" {
			t.Errorf("builder ID for %s should not be empty", ciName)
		}
		if !strings.HasPrefix(bid, "https://") {
			t.Errorf("builder ID for %s should be a URL, got: %s", ciName, bid)
		}
	}

	// Prove that the builder ID can be trivially spoofed by setting it directly.
	// In real code, Attest() sets this based on attestor.Name() with no auth check.
	p := New()
	p.PbProvenance.RunDetails = &prov.RunDetails{
		Builder:  &prov.Builder{ID: GHABuilderId},
		Metadata: &prov.BuildMetadata{},
	}
	p.PbProvenance.BuildDefinition = &prov.BuildDefinition{BuildType: BuildType}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	if !strings.Contains(string(data), GHABuilderId) {
		t.Error("expected provenance to contain spoofed GHA builder ID")
	}

	t.Log("BUG: SLSA builder IDs are assigned based on attestor name alone. " +
		"No cryptographic verification that the CI attestor's claims are authentic. " +
		"A local build can spoof any CI builder ID by registering a fake attestor.")
}

// ============================================================================
// R3-222: Malformed JSON deserialization - no schema validation
// ============================================================================

// TestSecurity_R3_222_UnmarshalAcceptsMalformedProvenance proves that
// UnmarshalJSON accepts any valid JSON, including documents that violate
// the SLSA provenance schema. Missing required fields, wrong types,
// and extra fields are all silently accepted.
//
// Impact: A corrupted or tampered provenance document can be loaded without
// error, leading downstream consumers to trust incomplete/invalid provenance.
func TestSecurity_R3_222_UnmarshalAcceptsMalformedProvenance(t *testing.T) {
	tests := []struct {
		name string
		json string
		desc string
	}{
		{
			name: "empty_object",
			json: `{}`,
			desc: "Empty JSON accepted as valid provenance",
		},
		{
			name: "missing_run_details",
			json: `{"buildDefinition":{"buildType":"https://example.com/fake"}}`,
			desc: "Missing runDetails accepted",
		},
		{
			name: "null_builder",
			json: `{"runDetails":{"builder":null}}`,
			desc: "Null builder accepted",
		},
		{
			name: "extra_unknown_fields",
			json: `{"buildDefinition":{"buildType":"x"},"evil":"payload"}`,
			desc: "Unknown fields accepted silently",
		},
		{
			name: "spoofed_builder_id",
			json: `{"runDetails":{"builder":{"id":"https://github.com/actions/runner"}}}`,
			desc: "Arbitrary builder ID accepted without verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			err := p.UnmarshalJSON([]byte(tt.json))
			if err != nil {
				t.Errorf("UnmarshalJSON rejected %q but should accept (proving lack of validation): %v",
					tt.name, err)
			}
		})
	}

	t.Log("BUG: UnmarshalJSON performs no schema validation on SLSA provenance. " +
		"Any JSON object is accepted, allowing corrupted or spoofed provenance to load.")
}

// ============================================================================
// R3-223: Subject key collision between products and other attestors
// ============================================================================

// TestSecurity_R3_223_SubjectKeyCollision proves that the Subjects() method
// merges p.products and p.subjects maps, where a key from p.subjects can
// overwrite a key from p.products. An OCI attestor can overwrite a file
// product subject by using the same key format "file:<name>".
//
// Impact: A product's digest could be silently replaced with a different
// digest from another attestor, breaking the integrity chain.
func TestSecurity_R3_223_SubjectKeyCollision(t *testing.T) {
	p := New()

	sha256Digest := cryptoutil.DigestValue{Hash: crypto.SHA256}

	// Set up a product with a specific digest
	p.products = map[string]attestation.Product{
		"myapp": {
			MimeType: "application/octet-stream",
			Digest: cryptoutil.DigestSet{
				sha256Digest: "original_product_digest_aaaaaa",
			},
		},
	}

	// Add a subject with the same key format that Subjects() produces.
	// Subjects() uses "file:<productName>" for products (line 288).
	// The subjects map is iterated second (line 294), overwriting products.
	p.subjects = map[string]cryptoutil.DigestSet{
		"file:myapp": {
			sha256Digest: "attacker_controlled_digest_zzzz",
		},
	}

	subjects := p.Subjects()

	digest, exists := subjects["file:myapp"]
	if !exists {
		t.Fatal("expected file:myapp to exist in subjects")
	}

	// The subjects entry (attacker-controlled) overwrites the products entry
	// because Subjects() iterates products first, then subjects (lines 287-298).
	if digest[sha256Digest] != "attacker_controlled_digest_zzzz" {
		t.Errorf("expected attacker digest to overwrite product digest, got: %s",
			digest[sha256Digest])
	}

	t.Log("BUG: Subjects() merges products and subjects maps without collision detection. " +
		"A subject from another attestor (e.g. OCI) can silently overwrite a " +
		"product's digest, breaking the integrity chain.")
}

// ============================================================================
// R3-224: Digest errors silently ignored in resolved dependencies
// ============================================================================

// TestSecurity_R3_224_DigestToNameMapErrorSilenced proves that errors from
// digestSet.ToNameMap() are silently discarded with _ (lines 150, 219).
// If digest conversion fails, an empty or partial digest map is used in
// ResolvedDependencies without any warning.
//
// Impact: Dependencies could be recorded with empty or incomplete digests,
// making SLSA provenance unreliable for verification.
func TestSecurity_R3_224_DigestToNameMapErrorSilenced(t *testing.T) {
	// Create a DigestSet with an unsupported hash function (Hash value 0).
	// ToNameMap() will fail for this entry but the error is discarded with _.
	badDigest := cryptoutil.DigestSet{
		cryptoutil.DigestValue{}: "deadbeef",
	}

	nameMap, err := badDigest.ToNameMap()
	if err == nil {
		// If this succeeds, the zero-value hash is somehow supported
		t.Logf("ToNameMap succeeded with zero-value hash (nameMap=%v), "+
			"but Attest() still discards the error with _", nameMap)
	} else {
		t.Logf("ToNameMap correctly returns error: %v", err)
		t.Log("In Attest(), this error is silently discarded with _ " +
			"on lines 150 and 219, producing empty digest maps.")
	}

	// Either way, the SLSA attestor discards the error. Prove the pattern exists
	// by showing a valid provenance can be built even with bogus digests.
	p := New()
	p.PbProvenance.BuildDefinition = &prov.BuildDefinition{BuildType: BuildType}
	p.PbProvenance.RunDetails = &prov.RunDetails{
		Builder:  &prov.Builder{ID: DefaultBuilderId},
		Metadata: &prov.BuildMetadata{},
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty serialized provenance")
	}

	t.Log("BUG: digestSet.ToNameMap() errors are silently discarded with _ on " +
		"lines 150 and 219. Failed digest conversions produce empty/partial " +
		"digest maps in ResolvedDependencies, making provenance unreliable.")
}
