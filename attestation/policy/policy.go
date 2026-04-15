// Copyright 2021 The Witness Contributors
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
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/attestation/signer/kms"
	"github.com/aflock-ai/rookery/attestation/source"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const PolicyPredicate = "https://aflock.ai/policy/v0.1"
const LegacyPolicyPredicate = "https://witness.testifysec.com/policy/v0.1"

// +kubebuilder:object:generate=true
type Policy struct {
	Expires              metav1.Time                    `json:"expires" jsonschema:"title=Expires,description=Timestamp when this policy expires and should no longer be used for verification"`
	Roots                map[string]Root                `json:"roots,omitempty" jsonschema:"title=Root Certificates,description=Trusted root certificates keyed by a unique identifier"`
	TimestampAuthorities map[string]Root                `json:"timestampauthorities,omitempty" jsonschema:"title=Timestamp Authorities,description=Trusted timestamp authority certificates keyed by a unique identifier"`
	PublicKeys           map[string]PublicKey           `json:"publickeys,omitempty" jsonschema:"title=Public Keys,description=Trusted public keys keyed by their key ID"`
	Steps                map[string]Step                `json:"steps" jsonschema:"title=Steps,description=Verification steps that must be satisfied,required"`
	ExternalAttestations map[string]ExternalAttestation `json:"externalAttestations,omitempty" jsonschema:"title=External Attestations,description=Bare predicate DSSE envelopes (SLSA provenance, VSAs, cosign attestations) verified as first-class policy evidence"`
}

// +kubebuilder:object:generate=true
type Root struct {
	Certificate   []byte   `json:"certificate" jsonschema:"title=Certificate,description=PEM-encoded root certificate"`
	Intermediates [][]byte `json:"intermediates,omitempty" jsonschema:"title=Intermediates,description=PEM-encoded intermediate certificates in the chain"`
}

// +kubebuilder:object:generate=true
type PublicKey struct {
	KeyID string `json:"keyid" jsonschema:"title=Key ID,description=Unique identifier for this public key (hash of the key material or KMS URI)"`
	Key   []byte `json:"key" jsonschema:"title=Key,description=PEM-encoded public key material"`
}

// PublicKeyVerifiers returns verifiers for each of the policy's embedded public keys grouped by the key's ID
func (p Policy) PublicKeyVerifiers(ko map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)) (map[string]cryptoutil.Verifier, error) { //nolint:gocognit,gocyclo
	verifiers := make(map[string]cryptoutil.Verifier)
	var err error

	for _, key := range p.PublicKeys {
		var verifier cryptoutil.Verifier
		isKMSKey := false
		for _, prefix := range kms.SupportedProviders() {
			if strings.HasPrefix(key.KeyID, prefix) { //nolint:nestif
				isKMSKey = true
				ksp := kms.New(kms.WithRef(key.KeyID), kms.WithHash("SHA256"))
				var vp signer.SignerProvider
				for _, opt := range ksp.Options {
					pn := opt.ProviderName()
					for _, setter := range ko[pn] {
						vp, err = setter(ksp)
						if err != nil {
							continue
						}
					}
				}

				if vp != nil {
					var ok bool
					ksp, ok = vp.(*kms.KMSSignerProvider)
					if !ok {
						return nil, fmt.Errorf("provided verifier provider is not a KMS verifier provider")
					}
				}

				verifier, err = ksp.Verifier(context.TODO())
				if err != nil {
					// Security: when the KMS provider is unavailable (offline/air-gapped
					// environments), fall back to the embedded public key if present.
					// Without this fallback, offline verification is impossible even
					// when the policy embeds the public key material. (Port of
					// go-witness PR #649 / Issue #648.)
					if len(key.Key) > 0 {
						log.Debugf("KMS verifier unavailable for %s, falling back to embedded key: %v", key.KeyID, err)
						verifier = nil // clear so we fall through to embedded key path
					} else {
						return nil, fmt.Errorf("failed to create kms verifier: %w", err)
					}
				}

			}
		}

		if verifier == nil {
			verifier, err = cryptoutil.NewVerifierFromReader(bytes.NewReader(key.Key))
			if err != nil {
				return nil, err
			}
		}

		keyID, err := verifier.KeyID()
		if err != nil {
			return nil, err
		}

		// Security: when a KMS key has an embedded fallback, the computed key ID
		// (a hash of the public key bytes) will never match the KMS URI stored in
		// key.KeyID. We use the policy's key.KeyID directly so functionary matching
		// works correctly. For non-KMS keys, verify that the computed ID matches.
		if !isKMSKey && keyID != key.KeyID {
			return nil, ErrKeyIDMismatch{
				Expected: key.KeyID,
				Actual:   keyID,
			}
		}

		verifiers[key.KeyID] = verifier
	}

	return verifiers, nil
}

type TrustBundle struct {
	Root          *x509.Certificate
	Intermediates []*x509.Certificate
}

// TrustBundles returns the policy's x509 roots and intermediates grouped by the root's ID
func (p Policy) TrustBundles() (map[string]TrustBundle, error) {
	return trustBundlesFromRoots(p.Roots)
}

func (p Policy) TimestampAuthorityTrustBundles() (map[string]TrustBundle, error) {
	return trustBundlesFromRoots(p.TimestampAuthorities)
}

func trustBundlesFromRoots(roots map[string]Root) (map[string]TrustBundle, error) {
	bundles := make(map[string]TrustBundle)
	for id, root := range roots {
		bundle := TrustBundle{}
		var err error
		bundle.Root, err = cryptoutil.TryParseCertificate(root.Certificate)
		if err != nil {
			return bundles, err
		}

		for _, intBytes := range root.Intermediates {
			cert, err := cryptoutil.TryParseCertificate(intBytes)
			if err != nil {
				return bundles, err
			}

			bundle.Intermediates = append(bundle.Intermediates, cert)
		}

		bundles[id] = bundle
	}

	return bundles, nil
}

type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	verifiedSource     source.VerifiedSourcer
	subjectDigests     []string
	searchDepth        int
	aiServerURL        string
	clockSkewTolerance time.Duration
}

func WithVerifiedSource(verifiedSource source.VerifiedSourcer) VerifyOption {
	return func(vo *verifyOptions) {
		vo.verifiedSource = verifiedSource
	}
}

func WithSubjectDigests(subjectDigests []string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.subjectDigests = subjectDigests
	}
}

func WithSearchDepth(depth int) VerifyOption {
	return func(vo *verifyOptions) {
		vo.searchDepth = depth
	}
}

func WithAiServerURL(url string) VerifyOption {
	return func(vo *verifyOptions) {
		vo.aiServerURL = url
	}
}

// WithClockSkewTolerance sets the tolerance for policy expiry checks to
// accommodate clock differences between the policy author and verifier.
// A reasonable value is 30s-60s for CI/CD environments.
func WithClockSkewTolerance(d time.Duration) VerifyOption {
	return func(vo *verifyOptions) {
		vo.clockSkewTolerance = d
	}
}

func checkVerifyOpts(vo *verifyOptions) error {
	if vo.verifiedSource == nil {
		return ErrInvalidOption{
			Option: "verified source",
			Reason: "a verified attestation source is required",
		}
	}

	if len(vo.subjectDigests) == 0 {
		return ErrInvalidOption{
			Option: "subject digests",
			Reason: "at least one subject digest is required",
		}
	}

	if vo.searchDepth < 1 {
		return ErrInvalidOption{
			Option: "search depth",
			Reason: "search depth must be at least 1",
		}
	}

	return nil
}

// Validate checks the policy for structural errors, including:
//   - Self-referencing steps (AttestationsFrom contains the step itself)
//   - References to non-existent steps
//   - Circular dependencies in AttestationsFrom chains
//   - Step.ExternalFrom entries referencing undefined external attestations
func (p Policy) Validate() error { //nolint:gocognit,gocyclo
	// Check self-references and unknown steps.
	for name, step := range p.Steps {
		for _, dep := range step.AttestationsFrom {
			if dep == name {
				return ErrSelfReference{Step: name}
			}
			if _, ok := p.Steps[dep]; !ok {
				return fmt.Errorf("step %q references unknown step %q in attestationsFrom", name, dep)
			}
		}

		// Flat existence check for external-attestation references. External
		// attestations cannot reference each other (Collection-graph semantics
		// do not apply to them), so no cycle/DFS logic is needed here.
		for _, extName := range step.ExternalFrom {
			if _, ok := p.ExternalAttestations[extName]; !ok {
				return ErrUnknownExternalAttestation{Step: name, Name: extName}
			}
		}
	}

	// DFS cycle detection.
	const (
		white = 0 // unvisited
		gray  = 1 // in current path
		black = 2 // finished
	)
	color := make(map[string]int)
	var path []string

	var dfs func(name string) error
	dfs = func(name string) error {
		color[name] = gray
		path = append(path, name)

		step := p.Steps[name]
		for _, dep := range step.AttestationsFrom {
			switch color[dep] {
			case gray:
				// Found a cycle — build the cycle path.
				cycle := []string{dep}
				for i := len(path) - 1; i >= 0; i-- {
					cycle = append(cycle, path[i])
					if path[i] == dep {
						break
					}
				}
				// Reverse for readable order.
				for i, j := 0, len(cycle)-1; i < j; i, j = i+1, j-1 {
					cycle[i], cycle[j] = cycle[j], cycle[i]
				}
				return ErrCircularDependency{Steps: cycle}
			case white:
				if err := dfs(dep); err != nil {
					return err
				}
			}
		}

		color[name] = black
		path = path[:len(path)-1]
		return nil
	}

	for name := range p.Steps {
		if color[name] == white {
			if err := dfs(name); err != nil {
				return err
			}
		}
	}

	return nil
}

// topologicalSort returns the step names in an order that respects AttestationsFrom
// dependencies (i.e., if step A depends on step B, B comes before A). Uses Kahn's
// algorithm. Returns an error if the graph has a cycle (should be caught by Validate first).
func (p Policy) topologicalSort() ([]string, error) {
	// Build adjacency list and in-degree count.
	inDegree := make(map[string]int)
	dependents := make(map[string][]string) // dep -> steps that depend on it
	for name := range p.Steps {
		inDegree[name] = 0
	}
	for name, step := range p.Steps {
		for _, dep := range step.AttestationsFrom {
			dependents[dep] = append(dependents[dep], name)
			inDegree[name]++
		}
	}

	// Seed the queue with steps that have no dependencies.
	queue := make([]string, 0)
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	var sorted []string
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		sorted = append(sorted, curr)

		for _, dep := range dependents[curr] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(sorted) != len(p.Steps) {
		return nil, fmt.Errorf("cycle detected during topological sort")
	}

	return sorted, nil
}

// VerifyWithExternals is the richer entry point that returns external
// attestation results alongside step results. Policy.Verify is preserved for
// backward compatibility and internally delegates to VerifyWithExternals.
func (p Policy) VerifyWithExternals(ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, map[string]ExternalResult, error) { //nolint:gocognit,gocyclo,funlen // canonical top-level verification entry point; linear flow (opts → validate → externals → steps → aggregate) benefits from locality
	vo := &verifyOptions{
		searchDepth: 3,
	}

	for _, opt := range opts {
		opt(vo)
	}

	if err := checkVerifyOpts(vo); err != nil {
		return false, nil, nil, err
	}

	if time.Now().After(p.Expires.Add(vo.clockSkewTolerance)) {
		return false, nil, nil, ErrPolicyExpired(p.Expires.Time)
	}

	// Validate the policy structure (self-references, unknown steps, cycles).
	if err := p.Validate(); err != nil {
		return false, nil, nil, err
	}

	trustBundles, err := p.TrustBundles()
	if err != nil {
		return false, nil, nil, err
	}

	// Verify external attestations BEFORE step verification so their results
	// are available when building Rego input.external for steps that
	// reference them via Step.ExternalFrom.
	//
	// Subject-graph isolation: we pass vo.subjectDigests as-is and do NOT
	// feed the externals' additional subjects back into the policy's
	// running seed set. This keeps Collection-graph semantics independent
	// from external-verification semantics (see issue #39 non-goals).
	externalResults, err := p.verifyExternalAttestations(ctx, vo, trustBundles)
	if err != nil {
		return false, nil, externalResults, err
	}

	stepResults, err := p.verifySteps(ctx, vo, trustBundles, externalResults)
	if err != nil {
		return false, stepResults, externalResults, err
	}

	pass := true
	for _, result := range stepResults {
		if !result.Analyze() {
			pass = false
		}
	}
	for _, er := range externalResults {
		if !er.Analyze() {
			pass = false
		}
	}

	return pass, stepResults, externalResults, nil
}

// Verify is the backward-compatible entry point; it discards the external
// result map. Callers that need external attestation details should use
// VerifyWithExternals.
func (p Policy) Verify(ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, error) {
	pass, stepResults, _, err := p.VerifyWithExternals(ctx, opts...)
	return pass, stepResults, err
}

// verifySteps runs the step-verification loop. Extracted from the old
// Policy.Verify body to make room for external-attestation verification
// ordering without ballooning the single function.
func (p Policy) verifySteps(ctx context.Context, vo *verifyOptions, trustBundles map[string]TrustBundle, externalResults map[string]ExternalResult) (map[string]StepResult, error) { //nolint:gocognit,gocyclo,funlen // loop body mixes search / functionary / context-build / backref-expansion on shared per-iteration state; splitting would require threading state through extra parameters
	// Validate that all artifactsFrom references point to steps defined in the policy.
	// This catches configuration errors early rather than producing confusing
	// "failed to verify artifacts" errors during the artifact comparison phase.
	for stepName, step := range p.Steps {
		for _, ref := range step.ArtifactsFrom {
			if _, ok := p.Steps[ref]; !ok {
				return nil, fmt.Errorf("step %q references unknown step %q in artifactsFrom", stepName, ref)
			}
		}
	}

	attestationsByStep := make(map[string][]string)
	for name, step := range p.Steps {
		for _, attestation := range step.Attestations {
			attestationsByStep[name] = append(attestationsByStep[name], attestation.Type)
		}
	}

	// Compute topological order so that steps are verified after their
	// AttestationsFrom dependencies, enabling cross-step context.
	stepOrder, err := p.topologicalSort()
	if err != nil {
		return nil, err
	}

	resultsByStep := make(map[string]StepResult)
	// Track all known subject digests to prevent duplicates across depth
	// iterations. Without de-duplication, the search set can grow
	// exponentially as back-references are re-discovered each iteration.
	knownDigests := make(map[string]struct{})
	for _, d := range vo.subjectDigests {
		knownDigests[d] = struct{}{}
	}

	for depth := 0; depth < vo.searchDepth; depth++ {
		// Collect back-reference digests discovered during this depth
		// iteration. They will be added to the search set for the NEXT
		// depth iteration, not the current one, to prevent a single
		// collection from widening the scope of its own depth.
		var nextDepthDigests []string

		for _, stepName := range stepOrder {
			step := p.Steps[stepName]

			// Use search to get all the attestations that match the supplied step name and subjects
			collections, err := vo.verifiedSource.Search(ctx, stepName, vo.subjectDigests, attestationsByStep[stepName])
			if err != nil {
				return nil, err
			}

			if len(collections) == 0 {
				collections = append(collections, source.CollectionVerificationResult{Errors: []error{ErrNoCollections{Step: stepName}}})
			}

			// Verify the functionaries
			functionaryCheckResults := step.checkFunctionaries(collections, trustBundles)
			passedCollections := make([]source.CollectionVerificationResult, len(functionaryCheckResults.Passed))
			for i, pc := range functionaryCheckResults.Passed {
				passedCollections[i] = pc.Collection
			}

			// Build cross-step context from already-verified dependencies
			// AND external-attestation context (input.external.<name>) from
			// this step's ExternalFrom list. When either AttestationsFrom or
			// ExternalFrom is non-empty, Rego input is wrapped; otherwise
			// input is the raw attestor JSON (backward compat).
			stepCtx := buildStepRegoContext(step, resultsByStep, externalResults)

			stepResult := step.validateAttestations(passedCollections, vo.aiServerURL, stepCtx)
			stepResult.Rejected = append(stepResult.Rejected, functionaryCheckResults.Rejected...)

			// We perform many searches against the same step, so we need to merge the relevant fields
			if resultsByStep[stepName].Step == "" {
				resultsByStep[stepName] = stepResult
			} else {
				if result, ok := resultsByStep[stepName]; ok {
					result.Passed = append(result.Passed, stepResult.Passed...)
					result.Rejected = append(result.Rejected, stepResult.Rejected...)
					resultsByStep[stepName] = result
				}
			}

			for _, coll := range passedCollections {
				for _, digestSet := range coll.Collection.BackRefs() {
					for _, digest := range digestSet {
						if _, seen := knownDigests[digest]; !seen {
							knownDigests[digest] = struct{}{}
							nextDepthDigests = append(nextDepthDigests, digest)
						}
					}
				}
			}
		}

		// Expand search scope for the next depth iteration only.
		//
		// Subject-graph isolation rule (issue #39): external-attestation
		// subjects are NOT added here. Only Collection BackRefs expand the
		// seed set. This preserves Collection-graph semantics.
		vo.subjectDigests = append(vo.subjectDigests, nextDepthDigests...)
	}

	resultsByStep, err = p.verifyArtifacts(resultsByStep)
	if err != nil {
		return nil, fmt.Errorf("failed to verify artifacts: %w", err)
	}

	// A policy with no steps is invalid — it would vacuously pass any verification.
	if len(resultsByStep) == 0 {
		return nil, fmt.Errorf("policy has no steps to verify")
	}

	return resultsByStep, nil
}

// verifyExternalAttestations runs the external-attestation verification
// pass BEFORE step verification (see issue #39). For each declared external,
// it searches the source by predicate type + policy seed subjects,
// validates the envelope's verifiers against the external's Functionaries,
// and evaluates any RegoPolicies / AiPolicies against the attestor.
//
// A required external with zero matches yields ErrMissingExternalAttestation.
// A non-required external with zero matches is marked Skipped and passes.
// Individual envelope failures are recorded in Rejected; the external as a
// whole passes iff at least one Passed envelope is accumulated (or Skipped).
func (p Policy) verifyExternalAttestations(ctx context.Context, vo *verifyOptions, trustBundles map[string]TrustBundle) (map[string]ExternalResult, error) { //nolint:gocognit,gocyclo,funlen // per-envelope verification has irreducible branching (functionary match / rego / ai / success); each branch produces a distinct rejection path
	results := make(map[string]ExternalResult, len(p.ExternalAttestations))
	if len(p.ExternalAttestations) == 0 {
		return results, nil
	}

	for name, ext := range p.ExternalAttestations {
		er := ExternalResult{Name: name}

		envelopes, err := vo.verifiedSource.SearchByPredicateType(ctx, []string{ext.PredicateType}, vo.subjectDigests)
		if err != nil {
			return results, fmt.Errorf("failed to search external attestation %q: %w", name, err)
		}

		if len(envelopes) == 0 {
			if ext.Required {
				results[name] = er
				return results, ErrMissingExternalAttestation{Name: name, PredicateType: ext.PredicateType}
			}
			er.Skipped = true
			results[name] = er
			continue
		}

		for _, env := range envelopes {
			// If the source reported envelope-level errors (e.g. signature
			// verification failure), surface them as a rejection.
			if len(env.Errors) > 0 && len(env.Verifiers) == 0 {
				er.Rejected = append(er.Rejected, RejectedExternal{
					Envelope: env,
					Reason:   errors.Join(env.Errors...),
				})
				continue
			}

			// Functionary validation — at least one verifier must match at
			// least one functionary.
			var validFunctionaries []cryptoutil.Verifier
			var functionaryErrs []error
			for _, verifier := range env.Verifiers {
				for _, functionary := range ext.Functionaries {
					if err := functionary.Validate(verifier, trustBundles); err != nil {
						functionaryErrs = append(functionaryErrs, err)
						continue
					}
					validFunctionaries = append(validFunctionaries, verifier)
				}
			}

			if len(validFunctionaries) == 0 {
				reason := fmt.Errorf("no verifiers matched with allowed functionaries for external attestation %q", name)
				if len(functionaryErrs) > 0 {
					reason = fmt.Errorf("%w: %w", reason, errors.Join(functionaryErrs...))
				}
				er.Rejected = append(er.Rejected, RejectedExternal{Envelope: env, Reason: reason})
				continue
			}

			// Policy evaluation. External attestations are standalone —
			// their Rego input is the bare predicate (same shape as when a
			// step has no AttestationsFrom/ExternalFrom). Pass nil stepCtx.
			if env.Attestor == nil {
				er.Rejected = append(er.Rejected, RejectedExternal{
					Envelope: env,
					Reason:   fmt.Errorf("external attestation %q: envelope has no attestor", name),
				})
				continue
			}

			if err := EvaluateRegoPolicy(env.Attestor, ext.RegoPolicies, nil); err != nil {
				er.Rejected = append(er.Rejected, RejectedExternal{Envelope: env, Reason: err})
				continue
			}

			aiResponses, err := EvaluateAIPolicy(env.Attestor, ext.AiPolicies, vo.aiServerURL)
			if err != nil {
				er.Rejected = append(er.Rejected, RejectedExternal{
					Envelope:    env,
					Reason:      err,
					AiResponses: aiResponses,
				})
				continue
			}

			aiFailed := false
			for i, resp := range aiResponses {
				if resp.Status == AiStatusFail {
					policyName := ""
					if i < len(ext.AiPolicies) {
						policyName = ext.AiPolicies[i].Name
					}
					if policyName == "" {
						policyName = fmt.Sprintf("AI Policy %d", i+1)
					}
					er.Rejected = append(er.Rejected, RejectedExternal{
						Envelope:    env,
						Reason:      fmt.Errorf("external attestation %q: AI policy %q failed: %s", name, policyName, resp.Reason),
						AiResponses: aiResponses,
					})
					aiFailed = true
					break
				}
			}
			if aiFailed {
				continue
			}

			er.Passed = append(er.Passed, PassedExternal{
				Envelope:    env,
				AiResponses: aiResponses,
			})
		}

		// Passed count = 0 AND required → hard failure.
		if len(er.Passed) == 0 && ext.Required {
			results[name] = er
			return results, ErrMissingExternalAttestation{Name: name, PredicateType: ext.PredicateType}
		}

		results[name] = er
	}

	return results, nil
}

// checkFunctionaries checks to make sure the signature on each statement corresponds to a trusted functionary for
// the step the statement corresponds to
func (step Step) checkFunctionaries(statements []source.CollectionVerificationResult, trustBundles map[string]TrustBundle) StepResult { //nolint:gocognit
	result := StepResult{Step: step.Name}
	for i, statement := range statements {
		// If the caller supplied a placeholder result carrying an authoritative
		// error (e.g. ErrNoCollections when the source returned zero matches),
		// surface that error directly instead of misclassifying the empty
		// statement as a bad predicate type. The predicate-type check below
		// would otherwise swallow the real reason and produce a misleading
		// "predicate type  is not a collection predicate type" error.
		if len(statement.Errors) > 0 && len(statement.Verifiers) == 0 && len(statement.Envelope.Payload) == 0 && statement.Statement.PredicateType == "" {
			reason := errors.Join(statement.Errors...)
			result.Rejected = append(result.Rejected, RejectedCollection{Collection: statement, Reason: reason})
			continue
		}

		// Check that the statement contains a predicate type that we accept.
		// A statement with the wrong predicate type must be rejected and must
		// NOT proceed to functionary validation — otherwise it could appear in
		// both the Passed and Rejected lists.
		if statement.Statement.PredicateType != attestation.CollectionType && statement.Statement.PredicateType != attestation.LegacyCollectionType {
			log.Debugf("policy: rejecting collection ref=%s: predicateType=%q (expected %q or %q), payload len=%d, errors=%v",
				statement.Reference, statement.Statement.PredicateType, attestation.CollectionType, attestation.LegacyCollectionType, len(statement.Envelope.Payload), statement.Errors)
			result.Rejected = append(result.Rejected, RejectedCollection{Collection: statement, Reason: fmt.Errorf("predicate type %v is not a collection predicate type", statement.Statement.PredicateType)})
			continue
		}

		if len(statement.Verifiers) > 0 { //nolint:nestif
			for _, verifier := range statement.Verifiers {
				for _, functionary := range step.Functionaries {
					if err := functionary.Validate(verifier, trustBundles); err != nil {
						statements[i].Warnings = append(statements[i].Warnings, fmt.Sprintf("failed to validate functionary of KeyID %s in step %s: %s", functionary.PublicKeyID, step.Name, err.Error()))
						continue
					} else {
						statements[i].ValidFunctionaries = append(statements[i].ValidFunctionaries, verifier)
					}
				}
			}

			if len(statements[i].ValidFunctionaries) == 0 {
				result.Rejected = append(result.Rejected, RejectedCollection{Collection: statements[i], Reason: fmt.Errorf("no verifiers matched with allowed functionaries for step %s", step.Name)})
			} else {
				result.Passed = append(result.Passed, PassedCollection{Collection: statements[i]})
			}
		} else {
			result.Rejected = append(result.Rejected, RejectedCollection{Collection: statements[i], Reason: fmt.Errorf("no verifiers present to validate against collection verifiers")})
		}
	}

	return result
}

// verifyArtifacts will check the artifacts (materials+products) of the step referred to by `ArtifactsFrom` against the
// materials of the original step.  This ensures file integrity between each step.
func (p Policy) verifyArtifacts(resultsByStep map[string]StepResult) (map[string]StepResult, error) { //nolint:gocognit
	for _, step := range p.Steps {
		accepted := false
		if len(resultsByStep[step.Name].Passed) == 0 {
			if result, ok := resultsByStep[step.Name]; ok {
				result.Rejected = append(result.Rejected, RejectedCollection{Reason: fmt.Errorf("failed to verify artifacts for step %s: no passed collections present", step.Name)})
				resultsByStep[step.Name] = result
			} else {
				return nil, fmt.Errorf("failed to find step %s in step results map", step.Name)
			}

			continue
		}

		reasons := []error{}
		for _, collection := range resultsByStep[step.Name].Passed {
			if err := verifyCollectionArtifacts(step, collection.Collection, resultsByStep); err == nil {
				accepted = true
			} else {
				reasons = append(reasons, err)
			}
		}

		if !accepted {
			// can't address the map fields directly so have to make a copy and overwrite
			if result, ok := resultsByStep[step.Name]; ok {
				reject := RejectedCollection{Reason: fmt.Errorf("failed to verify artifacts for step %s: ", step.Name)}
				for _, reason := range reasons {
					reject.Reason = errors.Join(reject.Reason, reason)
				}

				result.Rejected = append(result.Rejected, reject)
				result.Passed = []PassedCollection{}
				resultsByStep[step.Name] = result
			}
		}

	}

	return resultsByStep, nil
}

func verifyCollectionArtifacts(step Step, collection source.CollectionVerificationResult, collectionsByStep map[string]StepResult) error { //nolint:gocognit
	mats := collection.Collection.Materials()
	reasons := []string{}
	for _, artifactsFrom := range step.ArtifactsFrom {
		refResult, ok := collectionsByStep[artifactsFrom]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("step %q referenced in artifactsFrom does not exist in results", artifactsFrom))
			return ErrVerifyArtifactsFailed{Reasons: reasons}
		}

		if len(refResult.Passed) == 0 {
			reasons = append(reasons, fmt.Sprintf("step %q referenced in artifactsFrom has no passed collections", artifactsFrom))
			return ErrVerifyArtifactsFailed{Reasons: reasons}
		}

		accepted := make([]source.CollectionVerificationResult, 0)
		for _, testCollection := range refResult.Passed {
			if err := compareArtifacts(mats, testCollection.Collection.Collection.Artifacts()); err != nil {
				collection.Warnings = append(collection.Warnings, fmt.Sprintf("failed to verify artifacts for step %s: %v", step.Name, err))
				reasons = append(reasons, err.Error())
				continue
			}

			accepted = append(accepted, testCollection.Collection)
		}

		if len(accepted) <= 0 {
			return ErrVerifyArtifactsFailed{Reasons: reasons}
		}
	}

	return nil
}

func compareArtifacts(mats map[string]cryptoutil.DigestSet, arts map[string]cryptoutil.DigestSet) error {
	for path, mat := range mats {
		art, ok := arts[path]
		if !ok {
			continue
		}

		if !mat.Equal(art) {
			return ErrMismatchArtifact{
				Artifact: art,
				Material: mat,
				Path:     path,
			}
		}
	}

	// Warn about artifacts that appear in the producing step but not in the
	// consuming step's materials. Extra artifacts could indicate supply chain
	// injection — a file added to a step's output that nobody downstream
	// checks. We log rather than error to avoid breaking existing deployments,
	// but this should be reviewed for strict mode enforcement.
	for path := range arts {
		if _, ok := mats[path]; !ok {
			log.Debugf("artifact %q present in producing step but not consumed as material by the verifying step", path)
		}
	}

	return nil
}
