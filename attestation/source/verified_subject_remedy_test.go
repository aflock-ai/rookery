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

package source

import (
	"context"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #7710: a sibling step that attests a different file than the requested
// artifact (an SBOM, a scan's SARIF) is rejected by the substitution guard,
// and the rejection said only "collection subject does not match". The
// remedy, passing that file's digest with --subjects, was found by reading
// this file. The rejection now names the digests the signed collection does
// carry and the flag, while the guard itself stays fail-closed.
func TestVerifiedSource_SubjectMismatchNamesSignedSubjectsAndRemedy(t *testing.T) {
	ce, verifier := signedCollectionForSubject(t, "ref1", "sbom-capture", "sha256", attestedDigest)
	vs := NewVerifiedSource(&lyingSourcer{env: ce}, dsse.VerifyWithVerifiers(verifier))

	results, err := vs.Search(context.Background(), "sbom-capture", []string{requestedDigest}, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]
	require.Empty(t, r.Verifiers, "the guard must still reject")
	require.Len(t, r.Errors, 1)

	msg := r.Errors[0].Error()
	// The prefix is the contract other code matches on (judge-api's
	// nocommitevidence classifies rejections by it).
	assert.True(t, strings.HasPrefix(msg, "collection subject does not match requested artifact digest(s)"), msg)
	assert.Contains(t, msg, "sha256:"+attestedDigest, "the rejection must name a digest the signed collection carries")
	assert.Contains(t, msg, "--subjects", "the rejection must name the remedy")
	assert.NotContains(t, msg, requestedDigest, "only signed subjects are listed, never the requested digest")
}

// A subject name is signed but still author-chosen text: it is quoted, so a
// newline or terminal escape in it cannot forge a line of the verdict, and a
// long subject list is cut to a sample that says how many it left out.
func TestSignedSubjectSampleIsQuotedAndBounded(t *testing.T) {
	ce, _ := signedCollectionForSubject(t, "ref1", "s", "sha256", attestedDigest)
	got := signedSubjectSample(ce.Envelope.Payload)
	assert.Equal(t, `sha256:`+attestedDigest+` ("artifact")`, got)

	assert.Equal(t, "(none)", signedSubjectSample([]byte(`{"subject":[]}`)))
	assert.Equal(t, "(unreadable)", signedSubjectSample([]byte(`not json`)))

	var b strings.Builder
	b.WriteString(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"x","predicate":{},"subject":[`)
	for i := range 8 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name":"evil\nline` + string(rune('a'+i)) + `","digest":{"sha256":"` + strings.Repeat(string(rune('a'+i)), 64) + `"}}`)
	}
	b.WriteString("]}")
	many := signedSubjectSample([]byte(b.String()))
	assert.NotContains(t, many, "\n", "a subject name must not be able to break the line")
	assert.Contains(t, many, `\n`)
	assert.Contains(t, many, "and 3 more")
}
