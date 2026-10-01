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

package policy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	attpolicy "github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/canonicaljson"
	"github.com/open-policy-agent/opa/ast"
)

const (
	ExpectedPolicyType       = "https://witness.testifysec.com/policy/v0.1"
	ExpectedPolicyTypeAflock = "https://aflock.ai/policy/v0.1"
	// ExpectedPolicyTypeAflockV02 is the type of a policy whose steps may
	// declare about (attestation/policy.PolicyPredicateV02).
	ExpectedPolicyTypeAflockV02 = "https://aflock.ai/policy/v0.2"
	functionaryTypePublicKey    = "publickey"
	// stepAboutSource is the one accepted value of a step's about.
	stepAboutSource = "source"
)

// Signature status values reported in ValidationResult.Signature.
const (
	// SignatureUnsigned: raw policy JSON, or a DSSE envelope with no signatures.
	SignatureUnsigned = "unsigned"
	// SignaturePresent: the envelope carries at least one signature that was
	// not checked (no verifier supplied).
	SignaturePresent = "present"
	// SignatureVerified: the envelope's signature verified against the
	// supplied key.
	SignatureVerified = "verified"
)

type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	// Signature is the signature-assurance status of the input, as a fact a
	// consumer can branch on rather than a warning string to grep for. A raw
	// policy is "unsigned" and that is the normal validate-then-sign input,
	// so it is reported here and not as a warning (#9311); an envelope that
	// carries no signatures is also "unsigned" and does warn, because the
	// signed form was presented without the signature.
	Signature string `json:"signature"`
}

type policyDocument struct {
	Expires              string                         `json:"expires"`
	Steps                map[string]policyStep          `json:"steps"`
	PublicKeys           map[string]publicKeyEntry      `json:"publickeys,omitempty"`
	Roots                map[string]rootEntry           `json:"roots,omitempty"`
	TimestampAuthorities map[string]timestampAuthority  `json:"timestampauthorities,omitempty"`
	ExternalAttestations map[string]externalAttestation `json:"externalAttestations,omitempty"`
}

// externalAttestation is the part of a policy external attestation that
// validation reads. Required is a pointer because an ABSENT key means required
// (attestation/policy ExternalAttestation.UnmarshalJSON).
type externalAttestation struct {
	Name          string        `json:"name"`
	PredicateType string        `json:"predicateType"`
	Functionaries []functionary `json:"functionaries"`
	Required      *bool         `json:"required,omitempty"`
	CommitSubject string        `json:"commitSubject,omitempty"`
}

func (e externalAttestation) required() bool {
	return e.Required == nil || *e.Required
}

type policyStep struct {
	Name             string        `json:"name"`
	Functionaries    []functionary `json:"functionaries"`
	Attestations     []attestation `json:"attestations"`
	ArtifactsFrom    []string      `json:"artifactsFrom,omitempty"`
	AttestationsFrom []string      `json:"attestationsFrom,omitempty"`
	About            string        `json:"about,omitempty"`
}

type functionary struct {
	Type           string          `json:"type"`
	PublicKeyID    string          `json:"publickeyid,omitempty"`
	CertConstraint *certConstraint `json:"certConstraint,omitempty"`
}

type certConstraint struct {
	CommonName    string   `json:"commonname,omitempty"`
	DNSNames      []string `json:"dnsnames,omitempty"`
	Emails        []string `json:"emails,omitempty"`
	Organizations []string `json:"organizations,omitempty"`
	URIs          []string `json:"uris,omitempty"`
	Roots         []string `json:"roots,omitempty"`
}

type attestation struct {
	Type         string       `json:"type"`
	RegoPolicies []regoPolicy `json:"regopolicies,omitempty"`
}

type regoPolicy struct {
	Name   string `json:"name"`
	Module string `json:"module"`
}

type publicKeyEntry struct {
	KeyID string `json:"keyid"`
	Key   string `json:"key"`
}

type rootEntry struct {
	Certificate string `json:"certificate"`
}

type timestampAuthority struct {
	Certificate string `json:"certificate"`
}

func ValidatePolicy(ctx context.Context, envelope dsse.Envelope, verifier cryptoutil.Verifier) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Errors:    []string{},
		Warnings:  []string{},
		Signature: SignaturePresent,
	}
	if len(envelope.Signatures) == 0 {
		result.Signature = SignatureUnsigned
	}

	validateEnvelopeStructure(&envelope, result)

	var policy policyDocument
	if err := json.Unmarshal(envelope.Payload, &policy); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to unmarshal policy payload: %v", err))
		result.Valid = false
		return result
	}

	validateFillSlots(envelope.Payload, result)
	validatePolicyContent(&policy, result)
	validateStepAbout(&policy, envelope.PayloadType, true, result)
	validateV02Decodes(envelope, result)

	if verifier != nil {
		validateSignature(ctx, &envelope, verifier, result)
	}

	return result
}

func ValidateRawPolicy(ctx context.Context, policyJSON []byte) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Errors:    []string{},
		Warnings:  []string{},
		Signature: SignatureUnsigned,
	}

	// No "not wrapped in a DSSE envelope" warning here: a raw policy is the
	// documented validate-then-sign input, so the warning fired on every
	// correct use (#9311). The fact is carried by Signature instead. A
	// signature is expected only when the caller says so (-k,
	// --require-signed) or the input is already an envelope; the CLI enforces
	// the former and ValidatePolicy warns on the latter.

	var policy policyDocument
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to unmarshal policy JSON: %v", err))
		result.Valid = false
		return result
	}

	validateFillSlots(policyJSON, result)
	validatePolicyContent(&policy, result)
	validateStepAbout(&policy, "", false, result)

	return result
}

// FillSlotMarker opens every place in a `cilock policy template` draft the
// author still has to fill. A slot is only this string prefix: a hand-written
// draft that uses it is treated the same way.
const FillSlotMarker = "__FILL__"

// validateFillSlots reports every string in the policy that is still an
// unfilled template slot, by JSON path, with the slot's own instruction. A
// slot in a rego module field is also invalid base64; naming it as a slot is
// the actionable form of that error.
func validateFillSlots(policyJSON []byte, result *ValidationResult) {
	// A repeated key resolves differently here and in the typed decode (which
	// merges a second "steps" into the first), so a slot could hide from both
	// this scan and the Rego check that skips slotted modules.
	if err := canonicaljson.RejectDuplicateKeys(policyJSON); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("could not read the policy to look for unfilled template slots: %v", err))
		result.Valid = false
		return
	}
	// UseNumber: a number is never a slot, but decoding one into a float64
	// fails on a literal the typed decode ignored (an unknown "x":1e1000), and
	// a draft whose slots could not be read is not a draft with no slots.
	dec := json.NewDecoder(bytes.NewReader(policyJSON))
	dec.UseNumber()
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("could not read the policy to look for unfilled template slots: %v", err))
		result.Valid = false
		return
	}
	var walk func(path string, v interface{})
	walk = func(path string, v interface{}) {
		switch x := v.(type) {
		case map[string]interface{}:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				next := k
				if path != "" {
					next = path + "." + k
				}
				walk(next, x[k])
			}
		case []interface{}:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		case string:
			if strings.HasPrefix(x, FillSlotMarker) {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: unfilled template slot: %s", path, x))
				result.Valid = false
			}
		}
	}
	walk("", doc)
}

func validatePolicyContent(policy *policyDocument, result *ValidationResult) {
	validatePolicySchema(policy, result)
	validateExpiration(policy, result)
	validateSteps(policy, result)
	validateExternalAttestations(policy, result)
	validatePublicKeys(policy, result)
	validateRoots(policy, result)
	validateRegoPolicies(policy, result)
	validateKeyReferences(policy, result)
}

func validateEnvelopeStructure(envelope *dsse.Envelope, result *ValidationResult) {
	switch envelope.PayloadType {
	case ExpectedPolicyType, ExpectedPolicyTypeAflock, ExpectedPolicyTypeAflockV02:
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("Unexpected PayloadType: expected %s, %s or %s, got %s",
			ExpectedPolicyType, ExpectedPolicyTypeAflock, ExpectedPolicyTypeAflockV02, envelope.PayloadType))
	}

	if len(envelope.Payload) == 0 {
		result.Errors = append(result.Errors, "DSSE envelope payload is empty")
		result.Valid = false
	}

	if len(envelope.Signatures) == 0 {
		result.Warnings = append(result.Warnings, "Policy is not signed - no signatures found in DSSE envelope")
	}
}

// validateV02Decodes applies the verifier's own decoder to a v0.2 envelope.
// The verify path decodes v0.2 strictly (attestation/policy
// DecodePolicyEnvelope), so a member the Policy type does not know fails every
// verify; this reports it where the author can fix it. v0.1 decodes leniently
// there, so it is not checked here.
func validateV02Decodes(envelope dsse.Envelope, result *ValidationResult) {
	if envelope.PayloadType != ExpectedPolicyTypeAflockV02 {
		return
	}
	if _, err := attpolicy.DecodePolicyEnvelope(envelope.PayloadType, envelope.Payload); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("the verifier refuses this %s policy: %v", ExpectedPolicyTypeAflockV02, err))
		result.Valid = false
	}
}

// validateStepAbout applies the authoring rule for a step's about: source is
// the only value, and a policy that declares it must be signed as exactly v0.2
// (under either v0.1 spelling, or any other type, it is refused). typed
// is false for a raw policy, which has no type until it is signed; signing
// chooses v0.2 for it, so only the value is checked there.
func validateStepAbout(policy *policyDocument, payloadType string, typed bool, result *ValidationResult) {
	names := make([]string, 0, len(policy.Steps))
	for name := range policy.Steps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		about := policy.Steps[name].About
		if about == "" {
			continue
		}
		if about != stepAboutSource {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': about-unknown-value: about %q is not supported (the only value is %q)", name, about, stepAboutSource))
			result.Valid = false
		}
		if typed && payloadType != ExpectedPolicyTypeAflockV02 {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': about-needs-policy-v0.2: a step that declares about needs PayloadType %s, got %s; re-sign the policy without -t so cilock chooses it", name, ExpectedPolicyTypeAflockV02, payloadType))
			result.Valid = false
		}
	}
}

func validatePolicySchema(policy *policyDocument, result *ValidationResult) {
	if policy.Expires == "" {
		result.Errors = append(result.Errors, "Policy missing required field: expires")
		result.Valid = false
	}

	// A policy whose whole gate is an external attestation (a VSA) has no
	// steps; the verifier accepts that shape. It must still require something:
	// optional externals alone verify nothing, and the verifier fails such a
	// policy closed (GHSA-rgp5-33mp-jhfm), so it is refused here too.
	if len(policy.Steps) == 0 && !hasRequiredExternal(policy) {
		result.Errors = append(result.Errors, "Policy must define at least one step or one required external attestation")
		result.Valid = false
	}

	if len(policy.PublicKeys) == 0 && len(policy.Roots) == 0 {
		result.Errors = append(result.Errors, "Policy must define at least one public key or root certificate")
		result.Valid = false
	}
}

func hasRequiredExternal(policy *policyDocument) bool {
	for _, ext := range policy.ExternalAttestations {
		if ext.required() {
			return true
		}
	}
	return false
}

// validateExternalAttestations checks what the verifier would otherwise
// refuse, or silently never satisfy, on each external attestation: a missing
// predicate type, no functionary (no signer can ever match, so the external
// can never pass), and a malformed or misapplied commitSubject.
func validateExternalAttestations(policy *policyDocument, result *ValidationResult) {
	names := make([]string, 0, len(policy.ExternalAttestations))
	for name := range policy.ExternalAttestations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ext := policy.ExternalAttestations[name]
		if ext.PredicateType == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("External attestation '%s': missing predicateType", name))
			result.Valid = false
		}
		if len(ext.Functionaries) == 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("External attestation '%s': must define at least one functionary", name))
			result.Valid = false
		}
		if ext.CommitSubject == "" {
			continue
		}
		probe := attpolicy.ExternalAttestation{PredicateType: ext.PredicateType, CommitSubject: ext.CommitSubject}
		if err := probe.ValidateCommitSubject(); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("External attestation '%s': invalid commitSubject: %v", name, err))
			result.Valid = false
		}
	}
}

func validateExpiration(policy *policyDocument, result *ValidationResult) {
	if policy.Expires == "" {
		return
	}

	expiresTime, err := time.Parse(time.RFC3339, policy.Expires)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid expires timestamp format: %v (expected RFC3339)", err))
		result.Valid = false
		return
	}

	if time.Now().After(expiresTime) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Policy has expired (expires: %s)", policy.Expires))
	}
}

func validateSteps(policy *policyDocument, result *ValidationResult) { //nolint:gocognit,gocyclo
	for stepName, step := range policy.Steps {
		if step.Name != stepName {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': name field '%s' does not match key", stepName, step.Name))
			result.Valid = false
		}

		if len(step.Functionaries) == 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': must define at least one functionary", stepName))
			result.Valid = false
		}

		if len(step.Attestations) == 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': must define at least one attestation", stepName))
			result.Valid = false
		}

		for i, functionary := range step.Functionaries {
			if functionary.Type != functionaryTypePublicKey && functionary.Type != "root" {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: invalid type '%s' (must be 'publickey' or 'root')", stepName, i, functionary.Type))
				result.Valid = false
			}

			if functionary.Type == functionaryTypePublicKey && functionary.PublicKeyID == "" {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: publickey type must have publickeyid", stepName, i))
				result.Valid = false
			}

			// A 'root' functionary matches an x509 (Fulcio) signer via its
			// certConstraint. With no trusted roots it can NEVER match any cert
			// (Functionary.Validate rejects "no trusted roots provided"), so it is
			// a dead policy — catch it here instead of at verify time. Each listed
			// root must also resolve to the policy's roots map (the '*' AllowAll
			// sentinel excepted), mirroring the publickeyid cross-check below.
			if functionary.Type == "root" { //nolint:nestif // require non-empty certConstraint.roots, then cross-check each against the policy's roots map — two shallow guarded branches.
				if functionary.CertConstraint == nil || len(functionary.CertConstraint.Roots) == 0 {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: root functionary must list at least one trusted root in certConstraint.roots (or \"*\" to allow any defined root)", stepName, i))
					result.Valid = false
				} else {
					for _, rootRef := range functionary.CertConstraint.Roots {
						if rootRef == "*" {
							continue
						}
						if _, ok := policy.Roots[rootRef]; !ok {
							result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: certConstraint references undefined root '%s' — define it in the policy's roots map or use \"*\"", stepName, i, rootRef))
							result.Valid = false
						}
					}
				}
				validateRootFunctionaryConstraints(stepName, i, functionary.CertConstraint, result)
			}
		}

		for i, attestation := range step.Attestations {
			if attestation.Type == "" {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d: missing type field", stepName, i))
				result.Valid = false
			}
		}

		// Validate attestationsFrom references
		for _, ref := range step.AttestationsFrom {
			if _, ok := policy.Steps[ref]; !ok {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': attestationsFrom references undefined step '%s'", stepName, ref))
				result.Valid = false
			}
			if ref == stepName {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': attestationsFrom cannot reference itself", stepName))
				result.Valid = false
			}
		}

		// Validate artifactsFrom references
		for _, ref := range step.ArtifactsFrom {
			if _, ok := policy.Steps[ref]; !ok {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': artifactsFrom references undefined step '%s'", stepName, ref))
				result.Valid = false
			}
			if ref == stepName {
				result.Errors = append(result.Errors, fmt.Sprintf("Step '%s': artifactsFrom cannot reference itself", stepName))
				result.Valid = false
			}
		}
	}

	validateDependencyCycles(policy, result)
}

// validateDependencyCycles refuses a cycle in attestationsFrom, in
// artifactsFrom, or in their union. Each relation can be acyclic while the
// union is not, and the engine refuses a cycle in the union
// (attestation/policy Policy.Validate, #9813). The union is checked only when
// neither relation has a cycle of its own, so one cycle is reported once.
func validateDependencyCycles(policy *policyDocument, result *ValidationResult) {
	errsBefore := len(result.Errors)
	validateNoCircularDeps(policy, result, "attestationsFrom", func(s policyStep) []string { return s.AttestationsFrom })
	validateNoCircularDeps(policy, result, "artifactsFrom", func(s policyStep) []string { return s.ArtifactsFrom })
	if len(result.Errors) != errsBefore {
		return
	}
	if cycle := findCombinedCycle(policy); cycle != "" {
		result.Errors = append(result.Errors, "Circular dependency across attestationsFrom and artifactsFrom detected: "+cycle)
		result.Valid = false
	}
}

type dependencyEdge struct{ to, kind string }

// dependencyEdges lists a step's edges over both relations,
// attestationsFrom first.
func dependencyEdges(s policyStep) []dependencyEdge {
	out := make([]dependencyEdge, 0, len(s.AttestationsFrom)+len(s.ArtifactsFrom))
	for _, d := range s.AttestationsFrom {
		out = append(out, dependencyEdge{d, "attestationsFrom"})
	}
	for _, d := range s.ArtifactsFrom {
		out = append(out, dependencyEdge{d, "artifactsFrom"})
	}
	return out
}

// combinedCycleFinder is a DFS over attestationsFrom ∪ artifactsFrom.
// kinds[i] is the relation of the edge path[i] -> path[i+1].
type combinedCycleFinder struct {
	steps map[string]policyStep
	state map[string]int // 0 unvisited, 1 on the current path, 2 done
	path  []string
	kinds []string
}

// findCombinedCycle returns the first cycle in name order, rendered with the
// relation of every hop (`a -[artifactsFrom]-> b -[attestationsFrom]-> a`),
// or "" when the union is acyclic. Such a cycle lets a step's artifact pruning
// depend on a Rego verdict whose input depends on that pruning, which the
// engine has no convergence bound for.
func findCombinedCycle(policy *policyDocument) string {
	f := &combinedCycleFinder{steps: policy.Steps, state: map[string]int{}}
	names := make([]string, 0, len(policy.Steps))
	for name := range policy.Steps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if f.state[name] != 0 {
			continue
		}
		if cycle := f.visit(name); cycle != "" {
			return cycle
		}
	}
	return ""
}

func (f *combinedCycleFinder) visit(name string) string {
	f.state[name] = 1
	f.path = append(f.path, name)
	for _, e := range dependencyEdges(f.steps[name]) {
		if _, ok := f.steps[e.to]; !ok {
			continue // undefined references are reported separately
		}
		if f.state[e.to] == 1 {
			return f.render(e)
		}
		if f.state[e.to] == 0 {
			f.kinds = append(f.kinds, e.kind)
			if cycle := f.visit(e.to); cycle != "" {
				return cycle
			}
			f.kinds = f.kinds[:len(f.kinds)-1]
		}
	}
	f.state[name] = 2
	f.path = f.path[:len(f.path)-1]
	return ""
}

// render formats the cycle closed by edge back, which points at a step on the
// current path.
func (f *combinedCycleFinder) render(back dependencyEdge) string {
	start := 0
	for i, n := range f.path {
		if n == back.to {
			start = i
			break
		}
	}
	hops := append(append([]string(nil), f.kinds[start:]...), back.kind)
	nodes := append(append([]string(nil), f.path[start+1:]...), back.to)
	var b strings.Builder
	b.WriteString(f.path[start])
	for i, rel := range hops {
		fmt.Fprintf(&b, " -[%s]-> %s", rel, nodes[i])
	}
	return b.String()
}

func validateRootFunctionaryConstraints(stepName string, index int, constraint *certConstraint, result *ValidationResult) {
	if constraint == nil || strings.TrimSpace(constraint.CommonName) == "" {
		result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: root functionary certConstraint.commonname must not be empty; an empty commonname fails closed in every policy-hardening mode", stepName, index))
		result.Valid = false
	}
	fields := []struct {
		name  string
		empty bool
	}{
		{name: "dnsnames", empty: constraint == nil || len(constraint.DNSNames) == 0},
		{name: "emails", empty: constraint == nil || len(constraint.Emails) == 0},
		{name: "organizations", empty: constraint == nil || len(constraint.Organizations) == 0},
	}
	for _, field := range fields {
		if field.empty {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Step '%s', functionary %d: certConstraint.%s is empty and fails closed under --policy-hardening enforce", stepName, index, field.name))
		}
	}
	if constraint == nil {
		return
	}
	for _, uri := range constraint.URIs {
		if uriAdmitsEveryTenant(uri) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Step '%s', functionary %d: certConstraint.uris entry %q admits every tenant; scope it to /tenant/<id>/ before using --policy-hardening enforce", stepName, index, uri))
		}
	}
}

// uriAdmitsEveryTenant reports whether a URI constraint matches agents of
// any tenant: a bare star, a SPIFFE glob with no tenant segment, or a tenant
// segment that is itself empty or a glob (`/tenant/*/agent/*`).
func uriAdmitsEveryTenant(uri string) bool {
	if uri == "*" {
		return true
	}
	if !strings.HasPrefix(strings.ToLower(uri), "spiffe://") {
		return false
	}
	_, after, found := strings.Cut(uri, "/tenant/")
	if !found {
		return strings.HasSuffix(uri, "/*")
	}
	tenant, _, _ := strings.Cut(after, "/")
	return tenant == "" || strings.ContainsAny(tenant, "*?[")
}

func validatePublicKeys(policy *policyDocument, result *ValidationResult) {
	for keyID, keyEntry := range policy.PublicKeys {
		if keyEntry.KeyID != keyID {
			result.Errors = append(result.Errors, fmt.Sprintf("Public key '%s': keyid field '%s' does not match map key", keyID, keyEntry.KeyID))
			result.Valid = false
		}

		if keyEntry.Key != "" {
			if _, err := base64.StdEncoding.DecodeString(keyEntry.Key); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Public key '%s': key is not valid base64: %v", keyID, err))
				result.Valid = false
			}
		}
	}
}

func validateRoots(policy *policyDocument, result *ValidationResult) {
	for rootID, rootEntry := range policy.Roots {
		if rootEntry.Certificate == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("Root '%s': missing certificate data", rootID))
			result.Valid = false
			continue
		}

		if _, err := base64.StdEncoding.DecodeString(rootEntry.Certificate); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Root '%s': certificate is not valid base64: %v", rootID, err))
			result.Valid = false
		}
	}
}

func validateRegoPolicies(policy *policyDocument, result *ValidationResult) { //nolint:gocognit
	for stepName, step := range policy.Steps {
		for attIdx, att := range step.Attestations {
			parsedModules := make([]attpolicy.RegoPolicy, 0, len(att.RegoPolicies))
			for regoIdx, regoPol := range att.RegoPolicies {
				if regoPol.Name == "" {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy %d: missing name", stepName, attIdx, regoIdx))
					result.Valid = false
				}

				if regoPol.Module == "" {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy %d: missing module", stepName, attIdx, regoIdx))
					result.Valid = false
					continue
				}

				if strings.HasPrefix(regoPol.Module, FillSlotMarker) {
					// Named once, by path, in validateFillSlots.
					continue
				}

				moduleBytes, err := base64.StdEncoding.DecodeString(regoPol.Module)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy '%s': module is not valid base64: %v", stepName, attIdx, regoPol.Name, err))
					result.Valid = false
					continue
				}

				if err := validateRegoSyntax(string(moduleBytes), regoPol.Name); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d, rego policy '%s': invalid Rego syntax: %v", stepName, attIdx, regoPol.Name, err))
					result.Valid = false
					continue
				}

				lintWrappedPredicateReads(stepName, attIdx, att.Type, regoPol.Name, moduleBytes, result)
				parsedModules = append(parsedModules, attpolicy.RegoPolicy{Name: regoPol.Name, Module: moduleBytes})
			}
			if len(parsedModules) == len(att.RegoPolicies) {
				// Deny-only engine: an allow no deny depends on gates nothing,
				// and the verifier refuses it (#9820 E3).
				if err := attpolicy.CheckRegoAllowUsed(parsedModules); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', attestation %d: %v", stepName, attIdx, err))
					result.Valid = false
				}
				lintFailOpenNegations(stepName, attIdx, parsedModules, result)
				probeEmptyPredicate(stepName, attIdx, att.Type, parsedModules, result)
			}
		}
	}
}

// lintFailOpenNegations reports, as warnings, each negation whose input read
// the OPA compiler hoists out of the `not` where that makes deny fire less,
// so the deny never fires when the field is missing. The attestation's
// modules are linted together, as the verifier loads them. The verifier runs
// the same lint (attestation/policy regolint.go) and refuses an admit when a
// finding's field is missing from the evidence (regostrict.go, #9820).
// Validation has no evidence to check, so here a finding is a warning.
func lintFailOpenNegations(stepName string, attIdx int, modules []attpolicy.RegoPolicy, result *ValidationResult) {
	findings, err := attpolicy.LintRegoFailOpenSet(modules)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Step '%s', attestation %d: the rego modules do not compile together, so the fail-open negation lint did not run: %v", stepName, attIdx, err))
		return
	}
	for _, f := range findings {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Step '%s', attestation %d, rego policy '%s': %s", stepName, attIdx, f.Module, f))
	}
}

// probeEmptyPredicate evaluates one attestation's modules against {} with the
// verifier's evaluator. A set that denies nothing there passes any predicate
// that omits the fields it reads, which is the fail-open shape the negation
// lint cannot see (`input.repository != "x"` is undefined, not true, when the
// field is missing). Always a warning: a module may legitimately gate only on
// data that is present.
func probeEmptyPredicate(stepName string, attIdx int, predicateType string, modules []attpolicy.RegoPolicy, result *ValidationResult) {
	admits, err := attpolicy.ProbeRegoEmptyPredicate(modules)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Step '%s', attestation %d (%s): could not probe the rego modules against an empty predicate: %v", stepName, attIdx, predicateType, err))
		return
	}
	if admits {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Step '%s', attestation %d (%s): the rego modules deny nothing on an empty predicate {}, so a %s predicate missing the fields they read passes; make each rule fire when its field is absent (a helper rule with `not`, or object.get with a default)", stepName, attIdx, predicateType, predicateType))
	}
}

func validateKeyReferences(policy *policyDocument, result *ValidationResult) {
	availableKeys := make(map[string]bool)
	for keyID := range policy.PublicKeys {
		availableKeys[keyID] = true
	}

	for stepName, step := range policy.Steps {
		for i, functionary := range step.Functionaries {
			if functionary.Type == functionaryTypePublicKey && functionary.PublicKeyID != "" {
				if !availableKeys[functionary.PublicKeyID] {
					result.Errors = append(result.Errors, fmt.Sprintf("Step '%s', functionary %d: references undefined public key '%s'", stepName, i, functionary.PublicKeyID))
					result.Valid = false
				}
			}
		}
	}
}

func validateSignature(_ context.Context, envelope *dsse.Envelope, verifier cryptoutil.Verifier, result *ValidationResult) {
	if len(envelope.Signatures) == 0 {
		result.Errors = append(result.Errors, "Signature verification requested but envelope has no signatures")
		result.Valid = false
		return
	}

	_, err := envelope.Verify(dsse.VerifyWithVerifiers(verifier))
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Signature verification failed: %v", err))
		result.Valid = false
		return
	}
	result.Signature = SignatureVerified
}

func validateNoCircularDeps(policy *policyDocument, result *ValidationResult, fieldName string, getRefs func(policyStep) []string) {
	// DFS cycle detection
	type color int
	const (
		white color = iota // unvisited
		gray               // in current path
		black              // fully processed
	)

	colors := make(map[string]color)
	for name := range policy.Steps {
		colors[name] = white
	}

	var visit func(name string) bool
	visit = func(name string) bool {
		colors[name] = gray
		step, ok := policy.Steps[name]
		if !ok {
			return false
		}
		for _, ref := range getRefs(step) {
			if colors[ref] == gray {
				result.Errors = append(result.Errors, fmt.Sprintf("Circular %s dependency detected involving step '%s'", fieldName, ref))
				result.Valid = false
				return true
			}
			if colors[ref] == white {
				if visit(ref) {
					return true
				}
			}
		}
		colors[name] = black
		return false
	}

	for name := range policy.Steps {
		if colors[name] == white {
			visit(name)
		}
	}
}

func validateRegoSyntax(module string, name string) error {
	_, err := ast.ParseModule(name, module)
	return err
}

// wrappedPredicateFields lists, per predicate type whose registered attestor
// marshals as {"predicate": {...}}, the predicate's top-level field names.
// Rego's input is json.Marshal of the attestor struct
// (attestation/policy/rego.go EvaluateRegoPolicy), so for these types a
// module that reads input.<field> walks a path that does not exist on the
// wire. Rego treats an undefined path in a deny body as "rule does not
// fire", never as an error, so the mistake fails open: a failing suite
// passes the gate silently (#9312). The field list mirrors the attestor's
// Predicate struct; keep it in sync with
// plugins/attestors/test-results/test_results.go when fields are added.
var wrappedPredicateFields = map[string][]string{
	"https://aflock.ai/attestations/test-results/v0.1":   {"format", "toolName", "toolVersion", "summary", "failedTests", "reportFile", "reportDigest"},
	"https://witness.dev/attestations/test-results/v0.1": {"format", "toolName", "toolVersion", "summary", "failedTests", "reportFile", "reportDigest"},
}

// flatInputReads returns the top-level input fields a module actually READS,
// in either dotted (input.summary) or bracket (input["summary"]) form — the
// two spell the same reference, and the parser normalises both.
//
// It walks the module's parsed references rather than its bytes. Matching raw
// text cannot tell a read from a mention, so a policy whose comment warns its
// own reader away from `input.summary`, or whose deny message quotes the path,
// was told it read the path it was warning about (#9312 review round 2).
// A module that does not parse yields nothing: validateRegoSyntax has already
// reported that as an error, and a lint on top of it would be noise.
func flatInputReads(module []byte) map[string]bool {
	parsed, err := ast.ParseModule("lint", string(module))
	if err != nil || parsed == nil {
		return nil
	}
	read := map[string]bool{}
	ast.WalkRefs(parsed, func(ref ast.Ref) bool {
		// input.<field> is a two-term reference: the var "input" and a
		// string. Anything longer (input.predicate.summary) has "predicate"
		// in that position, which is the correct shape and not a finding.
		if len(ref) < 2 || !ref[0].Equal(ast.InputRootDocument) {
			return false
		}
		if field, ok := ref[1].Value.(ast.String); ok {
			read[string(field)] = true
		}
		return false
	})
	return read
}

// lintWrappedPredicateReads appends a warning for each top-level predicate
// field a module reads when the bound predicate type wraps its predicate.
// A warning, not an error: a module may legitimately read nothing from
// input, and the verifier will still evaluate the module as written.
func lintWrappedPredicateReads(stepName string, attIdx int, predicateType, policyName string, module []byte, result *ValidationResult) {
	fields, ok := wrappedPredicateFields[predicateType]
	if !ok {
		return
	}
	read := flatInputReads(module)
	for _, field := range fields {
		if !read[field] {
			continue
		}
		result.Warnings = append(result.Warnings, fmt.Sprintf(
			"Step '%s', attestation %d, rego policy '%s': reads input.%s, but %s marshals its fields under a 'predicate' wrapper, so that path is undefined at verify time and the rule never fires; read input.predicate.%s instead (#9312)",
			stepName, attIdx, policyName, field, predicateType, field))
	}
}
