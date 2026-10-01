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

package policy

// Differential test: checkSLSAProvenance against the Lean model
// (formal/ci-provenance, CiProvenance/BuilderIdentity.lean) through the
// ciprov-eval oracle's builderIdentity case.
//
// Each case is a set of predicate type names, a provenance body and the Build
// Signer URIs of the satisfying signers. Bodies cover every decode shape (an
// absent, null or wrongly typed runDetails, builder or id, and keys spelled in
// another case, alone or beside the exact key, which are refused as
// ambiguous) and builder ids that claim a
// workflow identity or do not, in either case; type sets include the
// pre-#9827 spelling, which must be refused by name. The verdicts and the
// named reason (legacy-type, malformed, unbacked) must agree, and every
// reason must occur.
//
// Skips when the oracle is not built (Lean is not provisioned on CI).
//
// formal:differential ci-provenance TestFormalDifferentialSLSABuilderIdentity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// ciProvenanceModel is the Lean project the oracle is built from; a path
// literal on purpose, read by `jade check formal-differential-inputs`.
const ciProvenanceModel = "../../formal/ci-provenance"

func ciprovOracle(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(ciProvenanceModel)
	require.NoError(t, err)
	// Always run the incremental build: lake rebuilds only what changed, and
	// reusing an existing binary would compare the code against whatever
	// model was built last rather than the model in the tree.
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("`lake` not on PATH, so the Lean oracle cannot be rebuilt from the current model; install elan")
	}
	build := exec.Command(lake, "build", "ciprov-eval")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build ciprov-eval: %v\n%s", err, out)
	}
	return filepath.Join(dir, ".lake", "build", "bin", "ciprov-eval")
}

type builderIdentityCase struct {
	Fn      string          `json:"fn"`
	Types   []string        `json:"types"`
	Body    json.RawMessage `json:"body"`
	Signers []string        `json:"signers"`
}

func TestFormalDifferentialSLSABuilderIdentity(t *testing.T) {
	bin := ciprovOracle(t)
	r := rand.New(rand.NewPCG(9827, 10013))

	ids := []string{
		provenanceWorkflowBuilderID,
		"https://GITHUB.com/aflock-ai/cilock-action/.GitHub/Workflows/provenance.yml@refs/tags/v1",
		"https://ghe.example.com/org/repo/.github/workflows/provenance.yml@refs/tags/v1",
		"https://github.com/tenant/app/.github/workflows/ci.yml@refs/heads/main",
		"https://aflock.ai/cilock/inline/github-actions@v1",
		"https://aflock.ai/attestation-default-builder@v0.1",
		"x/.github/workflows/",
		"/.github/workflow/",
		"",
	}
	uris := []string{provenanceWorkflowBuilderID, ids[1], ids[3], ""}
	verifiers := map[string]cryptoutil.Verifier{}
	for _, u := range uris {
		verifiers[u] = fulcioVerifier(t, u)
	}
	keyOnly, _ := newECDSAVerifier(t)
	typeSets := [][]string{
		{slsaProvenanceV1PredicateType}, {legacySLSAProvenanceV10Type},
		{"https://aflock.ai/attestations/git/v0.1"}, {"https://aflock.ai/attestations/git/v0.1", legacySLSAProvenanceV10Type},
		{""},
	}

	str := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	// spell picks the exact key most of the time and a case variant otherwise.
	// alias sometimes adds a second member spelled differently (never the same
	// spelling: Json.parse would keep only one), which is the collision Go's
	// case-insensitive struct decode used to resolve differently from Rego.
	spell := func(spellings []string) string {
		if r.IntN(5) != 0 {
			return spellings[0]
		}
		return spellings[1+r.IntN(len(spellings)-1)]
	}
	alias := func(spellings []string, used, val string) string {
		if r.IntN(8) != 0 {
			return ""
		}
		other := spellings[r.IntN(len(spellings))]
		if other == used {
			return ""
		}
		return `,"` + other + `":` + val
	}
	idSpellings := []string{"id", "ID", "Id"}
	bSpellings := []string{"builder", "Builder", "BUILDER"}
	rdSpellings := []string{"runDetails", "RunDetails", "rundetails"}
	body := func() string {
		idStr := func() string { return str(ids[r.IntN(len(ids))]) }
		id := idStr()
		idVal := []string{id, id, id, "null", "5", "[" + id + "]"}[r.IntN(6)]
		idKey := spell(idSpellings)
		builderObj := `{"` + idKey + `":` + idVal + alias(idSpellings, idKey, idStr()) + `}`
		builder := []string{builderObj, builderObj, `{}`, `null`, `"b"`, `[]`}[r.IntN(6)]
		bKey := spell(bSpellings)
		rdObj := `{"` + bKey + `":` + builder + alias(bSpellings, bKey, `{"id":`+idStr()+`}`) + `}`
		rd := []string{rdObj, rdObj, rdObj, `{}`, `null`, `"nope"`, `7`}[r.IntN(7)]
		rdKey := spell(rdSpellings)
		switch r.IntN(10) {
		case 0:
			return `{"buildDefinition":{}}`
		case 1:
			return `[]`
		default:
			return `{"buildDefinition":{"buildType":"b"},"` + rdKey + `":` + rd + alias(rdSpellings, rdKey, `{"builder":{"id":`+idStr()+`}}`) + `}`
		}
	}

	type goCase struct {
		c       builderIdentityCase
		signers []cryptoutil.Verifier
	}
	var cases []goCase
	for i := 0; i < 3000; i++ {
		var signerURIs []string
		var signers []cryptoutil.Verifier
		for range r.IntN(3) {
			if r.IntN(4) == 0 {
				signers = append(signers, keyOnly)
				signerURIs = append(signerURIs, "")
				continue
			}
			u := uris[r.IntN(len(uris))]
			signers = append(signers, verifiers[u])
			signerURIs = append(signerURIs, u)
		}
		if signerURIs == nil {
			signerURIs = []string{}
		}
		cases = append(cases, goCase{
			c:       builderIdentityCase{Fn: "builderIdentity", Types: typeSets[r.IntN(len(typeSets))], Body: json.RawMessage(body()), Signers: signerURIs},
			signers: signers,
		})
	}

	var in bytes.Buffer
	for _, gc := range cases {
		b, err := json.Marshal(gc.c)
		require.NoError(t, err)
		in.Write(b)
		in.WriteByte('\n')
	}
	cmd := exec.Command(bin)
	cmd.Stdin = &in
	out, err := cmd.Output()
	require.NoError(t, err, "ciprov-eval")
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var lean []bool
	var leanReason []string
	for sc.Scan() {
		var res struct {
			OK     *bool  `json:"ok"`
			Reason string `json:"reason"`
			Error  string `json:"error"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &res), sc.Text())
		require.Empty(t, res.Error, "oracle error")
		require.NotNil(t, res.OK, sc.Text())
		lean = append(lean, *res.OK)
		leanReason = append(leanReason, res.Reason)
	}
	require.Len(t, lean, len(cases), "the oracle must answer every case")

	mismatches, provOK, provRefused := 0, 0, 0
	reasons := map[string]int{}
	for i, gc := range cases {
		err := checkSLSAProvenance(attestation.NewRawAttestation(gc.c.Types[0], gc.c.Body), gc.signers, gc.c.Types...)
		goOK := err == nil
		goReason := goRefusalName(err)
		reasons[goReason]++
		if goOK != lean[i] || goReason != leanReason[i] {
			mismatches++
			if mismatches <= 8 {
				b, _ := json.Marshal(gc.c)
				t.Errorf("go ok=%v reason=%q lean ok=%v reason=%q (%v): %s", goOK, goReason, lean[i], leanReason[i], err, b)
			}
		}
		if isSLSAProvenanceType(gc.c.Types) && goReason != "legacy-type" {
			if goOK {
				provOK++
			} else {
				provRefused++
			}
		}
	}
	require.Positive(t, provOK, "no provenance case was admitted")
	require.Positive(t, provRefused, "no provenance case was refused")
	for _, r := range []string{"legacy-type", "malformed", "ambiguous-key", "unbacked"} {
		require.Positive(t, reasons[r], "no case was refused as %s", r)
	}
	t.Logf("%d cases, %d mismatches; provenance admitted %d, refused %d; reasons %v", len(cases), mismatches, provOK, provRefused, reasons)
}

// goRefusalName names checkSLSAProvenance's refusal the way the model does.
func goRefusalName(err error) string {
	var legacyErr ErrSLSALegacyProvenanceType
	var unbacked ErrSLSABuilderIdentityUnbacked
	var ambiguous ErrSLSABuilderKeyAmbiguous
	switch {
	case err == nil:
		return ""
	case errors.As(err, &legacyErr):
		return "legacy-type"
	case errors.As(err, &unbacked):
		return "unbacked"
	case errors.As(err, &ambiguous):
		return "ambiguous-key"
	default:
		return "malformed"
	}
}

func isSLSAProvenanceType(types []string) bool {
	for _, pt := range types {
		if pt == slsaProvenanceV1Type {
			return true
		}
	}
	return false
}
