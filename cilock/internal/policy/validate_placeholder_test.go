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

package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
)

// The onboarding simulator measured `Root 'fulcio-root': missing certificate
// data` as the top friction item: 13 hits in 7 runs, 15 failed validates and
// 10 retries, on drafts that were correct. `cilock policy template` writes
// that root empty on purpose; the platform fills it when a human signs. These
// tests pin the narrow rule that lets an unsigned draft pass while every real
// trust problem stays an error.

// placeholderDraft is the trust block `cilock policy template` writes, around
// an otherwise valid step whose root functionary names the placeholder root.
func placeholderDraft(roots, tsas string) string {
	return `{
  "expires": "2030-01-01T00:00:00Z",
  "roots": ` + roots + `,
  "timestampauthorities": ` + tsas + `,
  "steps": {
    "build": {
      "name": "build",
      "functionaries": [
        { "type": "root", "certConstraint": { "roots": ["fulcio-root"], "commonname": "*",
          "dnsnames": ["*"], "emails": ["*"], "organizations": ["*"],
          "uris": ["spiffe://example.test/tenant/t1/agent/*"] } }
      ],
      "attestations": [ { "type": "https://aflock.ai/attestations/command-run/v0.1" } ]
    }
  }
}`
}

const (
	templateRoots = `{"fulcio-root": {"certificate": ""}}`
	templateTSAs  = `{"platform-tsa": {"certificate": ""}}`
)

func TestPlaceholder_TemplateDraftIsValidAndNamesItsPlaceholders(t *testing.T) {
	res := validateRaw(t, placeholderDraft(templateRoots, templateTSAs))
	if !res.Valid || len(res.Errors) != 0 {
		t.Fatalf("a template draft whose only gap is the platform placeholders must validate; errors: %q", res.Errors)
	}
	want := []string{"roots.fulcio-root", "timestampauthorities.platform-tsa"}
	if strings.Join(res.Placeholders, ",") != strings.Join(want, ",") {
		t.Fatalf("Placeholders = %q, want %q", res.Placeholders, want)
	}
	if res.Signature != SignatureUnsigned {
		t.Fatalf("signature = %q, want %q", res.Signature, SignatureUnsigned)
	}
}

// Everything that is not the exact placeholder the template writes is still
// an error: a different name, a missing or null certificate, extra members,
// or an unreferenced-but-empty non-platform root.
func TestPlaceholder_OnlyTheExactPlaceholderIsTolerated(t *testing.T) {
	for name, tc := range map[string]struct{ roots, want string }{
		"another root name, empty": {
			`{"fulcio-root": {"certificate": ""}, "my-root": {"certificate": ""}}`,
			"Root 'my-root': missing certificate data",
		},
		"placeholder name, certificate member missing": {
			`{"fulcio-root": {}}`,
			"Root 'fulcio-root': missing certificate data",
		},
		"placeholder name, certificate null": {
			`{"fulcio-root": {"certificate": null}}`,
			"Root 'fulcio-root': missing certificate data",
		},
		"placeholder name, extra member": {
			`{"fulcio-root": {"certificate": "", "intermediates": []}}`,
			"Root 'fulcio-root': missing certificate data",
		},
		"placeholder name, not base64": {
			`{"fulcio-root": {"certificate": "!!!"}}`,
			"Root 'fulcio-root': certificate is not valid base64",
		},
	} {
		t.Run(name, func(t *testing.T) {
			res := validateRaw(t, placeholderDraft(tc.roots, templateTSAs))
			if res.Valid {
				t.Fatalf("must stay invalid; placeholders %q", res.Placeholders)
			}
			if !containsSubstr(res.Errors, tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, res.Errors)
			}
		})
	}
}

func TestPlaceholder_MalformedRootIsStillAnError(t *testing.T) {
	res := validateRaw(t, placeholderDraft(`{"fulcio-root": ""}`, templateTSAs))
	if res.Valid {
		t.Fatalf("a root that is a string, not an object, must be refused; placeholders %q", res.Placeholders)
	}
}

func TestPlaceholder_MissingRootReferenceIsStillAnError(t *testing.T) {
	doc := strings.Replace(placeholderDraft(templateRoots, templateTSAs), `"roots": ["fulcio-root"]`, `"roots": ["other-root"]`, 1)
	res := validateRaw(t, doc)
	if res.Valid || !containsSubstr(res.Errors, "references undefined root 'other-root'") {
		t.Fatalf("an undefined root reference must stay an error, got valid=%v errors=%q", res.Valid, res.Errors)
	}
}

func TestPlaceholder_OtherErrorsStillFailTheDraft(t *testing.T) {
	doc := strings.Replace(placeholderDraft(templateRoots, templateTSAs), `"expires": "2030-01-01T00:00:00Z"`, `"expires": "tomorrow"`, 1)
	res := validateRaw(t, doc)
	if res.Valid {
		t.Fatal("an invalid expires must fail the draft even when the only root gap is a placeholder")
	}
	if containsSubstr(res.Errors, "fulcio-root") {
		t.Fatalf("the placeholder must not be reported as an error alongside the real one: %q", res.Errors)
	}
}

// --strict (the release form) refuses a placeholder: the draft is not the
// policy a human signs.
func TestPlaceholder_RequireFilledTrustRefusesPlaceholders(t *testing.T) {
	res := validateRaw(t, placeholderDraft(templateRoots, templateTSAs))
	res.RequireFilledTrust()
	if res.Valid {
		t.Fatal("RequireFilledTrust must fail a draft that still holds platform placeholders")
	}
	for _, want := range []string{"Root 'fulcio-root': missing certificate data", "Timestamp authority 'platform-tsa': missing certificate data"} {
		if !containsSubstr(res.Errors, want) {
			t.Errorf("want %q in %q", want, res.Errors)
		}
	}
}

// The tolerance is for the unsigned raw draft only. The signed form (a DSSE
// envelope) is what a verifier consumes, and an empty root there can never
// admit a signer, so it stays an error.
func TestPlaceholder_EnvelopeIsNeverTolerated(t *testing.T) {
	env := dsse.Envelope{
		PayloadType: ExpectedPolicyTypeAflock,
		Payload:     []byte(placeholderDraft(templateRoots, templateTSAs)),
	}
	res := ValidatePolicy(context.Background(), env, nil)
	if res.Valid || !containsSubstr(res.Errors, "Root 'fulcio-root': missing certificate data") {
		t.Fatalf("a DSSE envelope with an empty fulcio-root must be refused, got valid=%v errors=%q", res.Valid, res.Errors)
	}
	if len(res.Placeholders) != 0 {
		t.Fatalf("an envelope reports no placeholders, got %q", res.Placeholders)
	}
}

// Filling the root clears the placeholder: nothing is reported.
func TestPlaceholder_FilledRootIsNotAPlaceholder(t *testing.T) {
	filled := `{"fulcio-root": {"certificate": "` + base64.StdEncoding.EncodeToString([]byte("pem")) + `"}}`
	res := validateRaw(t, placeholderDraft(filled, `{"platform-tsa": {"certificate": "Zm9v"}}`))
	if !res.Valid || len(res.Placeholders) != 0 {
		t.Fatalf("a filled draft has no placeholders: valid=%v errors=%q placeholders=%q", res.Valid, res.Errors, res.Placeholders)
	}
}

func TestPlaceholder_JSONCarriesPlaceholders(t *testing.T) {
	res := validateRaw(t, placeholderDraft(templateRoots, templateTSAs))
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"placeholders":["roots.fulcio-root","timestampauthorities.platform-tsa"]`) {
		t.Fatalf("JSON output must list the placeholders, got %s", b)
	}
}

func containsSubstr(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}
