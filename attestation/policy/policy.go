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
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/attestation/signer/kms"
	"github.com/aflock-ai/rookery/attestation/source"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const PolicyPredicate = "https://aflock.ai/policy/v0.1"
const LegacyPolicyPredicate = "https://witness.testifysec.com/policy/v0.1"

// sha256OfEmpty is sha256(""), which is also the RFC 6962 root of an EMPTY
// Merkle tree. The material and product attestors compute exactly this value as
// their tree root whenever a step consumed or produced nothing, so as a tree
// root it is shared by every such step rather than identifying any one of them.
const sha256OfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// The back-reference names whose CONTRACT defines sha256("") as the
// empty-tree sentinel. Back-reference names are namespaced by the producing
// attestor's type — "<type>/<name>" — so the suffix is what identifies the
// contract regardless of attestor version or vendor prefix.
//
// Spelled literally rather than imported from plugins/attestors/{material,
// product}: the attestation core must not depend on the plugin modules, and
// those packages already import this one transitively.
const (
	materialTreeBackRefName = "/tree:materials"
	productTreeBackRefName  = "/tree:products"
)

// isEmptyTreeHubBackRef reports whether a back-reference is the empty-MERKLE-TREE
// sentinel — the one case where sha256("") is not an identity claim but a
// "this step consumed/produced nothing" marker that every such step emits
// identically. Expanding on it joins them all into a single clique.
//
// Measured on a 16,939-envelope production corpus: sha256("") appears as a
// back-reference 3,973 times, and 100.0000% of those are material/product tree
// roots (product 2,050, material 1,923). Non-tree back-reference emissions of
// this value: zero. Guarding it cuts depth-3 reach by 87-100% depending on
// dispatch shape (a build dispatch goes from 7,141 reachable envelopes to 9).
//
// SCOPED BY NAMESPACE, NOT BY VALUE ALONE. sha256("") is also the legitimate
// content digest of a genuine zero-byte artifact, and a value-blind filter
// would drop that edge too — falsely rejecting a collection reachable ONLY
// through it (raised in review on #7689 and reproduced: the collection was
// never searched). Restricting to the tree contracts removes that false-reject
// class while dropping exactly the same 3,973 edges on real data.
//
// Why namespace scoping is safe rather than a concession: the EMISSION-side fix
// stops new attestations from recording this edge at all, so this consumer-side
// check exists solely for back-references already baked into signed payloads
// that can never be re-signed — and every one of those is a tree root. Nothing
// is given up.
//
// Laundering (relabelling sha256("") under, say, "commithash:") is deliberately
// NOT defended here. Back-references are only harvested from collections that
// PASS the step gate, so such an adversary is already a policy-authorized
// functionary for the step and can emit any high-fanout digest they like — a
// shared base-image layer, a toolchain blob. The bound on that adversary is
// WithMaxSubjectFanout (production default VERIFY_SUBJECT_FANOUT_LIMIT=32),
// not this check.
//
// FALSE-REJECT-ONLY: this may only decline to WIDEN the search. It never removes
// a collection that some other digest makes reachable.
func isEmptyTreeHubBackRef(backRefName, digest string) bool {
	if digest != sha256OfEmpty {
		return false
	}
	return strings.HasSuffix(backRefName, materialTreeBackRefName) ||
		strings.HasSuffix(backRefName, productTreeBackRefName)
}

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
	verifiedSource      source.VerifiedSourcer
	subjectDigests      []string
	searchDepth         int
	maxSubjectFanout    int
	aiServerURL         string
	clockSkewTolerance  time.Duration
	requireAllArtifacts bool
	// lazyStepSatisfaction enables within-step stop-at-first-pass on the
	// streamed arm. Default false — see WithLazyStepSatisfaction (lazy.go) for
	// the soundness argument and the three exclusions.
	lazyStepSatisfaction bool
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

// WithMaxSubjectFanout enables the subject fan-out guard: during step
// verification, a closure digest matched by more than n candidates in one
// search is treated as a HUB (shared base-image layer, runner image,
// toolchain blob — digests that connect every build in a tenant), and
// candidates whose ONLY intersection with the search closure is a hub digest
// are rejected before the step gate. This confines a verify to the dispatch
// subject's own evidence closure (order ~10 attestations per commit) instead
// of the whole tenant corpus.
//
// SOUNDNESS: the guard only ever drops candidates, and admitted candidates
// still undergo per-envelope signature verification and the step gate, so
// its failure mode is a false REJECT, never a false PASS. n <= 0 disables
// the guard entirely (legacy behavior).
func WithMaxSubjectFanout(n int) VerifyOption {
	return func(vo *verifyOptions) {
		vo.maxSubjectFanout = n
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

// WithRequireAllArtifacts enables STRICT artifact matching for artifactsFrom
// edges (opt-in; default OFF). When enabled, the verifier fails closed if a
// producing step emits an artifact that the consuming step does NOT consume as
// a material — an unconsumed/extra artifact can indicate supply-chain injection
// (a file slipped into a step's output that nobody downstream checks).
//
// This is DEFAULT-OFF by design: existing policies routinely under-declare
// materials (build steps that read more than they enumerate), so enabling it
// unconditionally would break them. Off (the default) preserves the historical
// warn-only behavior — extra artifacts are logged, never rejected.
func WithRequireAllArtifacts() VerifyOption {
	return func(vo *verifyOptions) {
		vo.requireAllArtifacts = true
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

	// A negative clock-skew tolerance SHRINKS the validity window (premature
	// expiry / unidirectional skew), which is a fail-open soundness hole: it
	// could reject a policy that has not actually expired, or — if abused —
	// move the effective expiry. Tolerance must only ever widen the window.
	if vo.clockSkewTolerance < 0 {
		return ErrInvalidOption{
			Option: "clock skew tolerance",
			Reason: "clock skew tolerance must be non-negative",
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
		// R3_185/187/209 (#6266): the map key is the authoritative step name at
		// verify time, but Step.Name is what artifact/cross-step wiring and error
		// messages use. When they disagree — or Name is empty — verification fails
		// later with a misleading error that does not name the real cause.
		if step.Name == "" || step.Name != name {
			if Hardening().EnforceStepNameCoherence {
				// Enforce (opt-in): reject the misconfiguration at load time with a
				// clear error instead of a misleading verify-time failure.
				return ErrStepNameIncoherent{Key: name, Name: step.Name}
			}
			// Warn-first (default): no error is returned, so behavior is unchanged.
			if step.Name == "" {
				log.Warnf("policy misconfiguration: step keyed %q has an empty Name; verification will fail at runtime with a misleading error (#6266)", name)
			} else {
				log.Warnf("policy misconfiguration: step keyed %q has mismatched Name %q; verification will fail at runtime with a misleading error (#6266)", name, step.Name)
			}
		}

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

		// Reject malformed timestamp constraints at load time so an
		// unparseable maxAge or inverted window fails policy validation
		// instead of rejecting every collection at verify time.
		if err := step.TimestampConstraint.Validate(); err != nil {
			return fmt.Errorf("step %q: %w", name, err)
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
	//
	// DETERMINISM (#7958): Go randomizes map iteration, so seeding straight
	// from inDegree gives a different step order on every run. Step order
	// decides the order in which BackRefs widen the search set, which decides
	// the order candidates are returned in, which — under the minimum-witness
	// stop — decides WHICH collection becomes the witness and gets signed.
	// AttestationsFrom only constrains dependencies; among independent steps
	// the tie-break has to come from somewhere, and a name sort is the only
	// one available that is a function of the policy rather than of the run.
	queue := make([]string, 0)
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)

	var sorted []string
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		sorted = append(sorted, curr)

		// dependents[curr] was built by ranging p.Steps, so it too carries a
		// random order; sort the newly-ready set before enqueueing it.
		ready := make([]string, 0, len(dependents[curr]))
		for _, dep := range dependents[curr] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				ready = append(ready, dep)
			}
		}
		sort.Strings(ready)
		queue = append(queue, ready...)
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

	// A policy must affirmatively verify something to pass. A step imposes a real
	// obligation; an external attestation only counts if it was actually
	// satisfied — a Skipped (optional, unmatched) external verifies nothing.
	// A policy with no steps whose only external is Skipped therefore proves
	// nothing and must fail closed rather than pass vacuously
	// (GHSA-rgp5-33mp-jhfm). The no-steps-and-no-externals case is already
	// rejected with an error in verifySteps.
	pass := true
	verifiedSomething := len(p.Steps) > 0
	for _, result := range stepResults {
		if !result.Analyze() {
			pass = false
		}
	}
	for _, er := range externalResults {
		if !er.Analyze() {
			pass = false
		}
		if !er.Skipped {
			verifiedSomething = true
		}
	}
	if !verifiedSomething {
		pass = false
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
// VERBATIM frozen copy of the pre-lazy engine, which exists precisely so a
// mutation here cannot move the oracle with it. dupl is exempted for _test.go
// but reports the pair anchored on this side. Any OTHER duplicate of this body
// would be a real finding — check the reported partner before re-suppressing.
//
//nolint:dupl // the only clone of this body is lazy_frozen_oracle_test.go's
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

	// LOGICAL DEPTH, per digest. digestDepth records the hop count at which
	// each subject digest becomes searchable: seeds are 0, and a digest
	// harvested while searching at logical depth L is L+1. It also serves the
	// de-duplication the search set has always needed — without it the set
	// grows exponentially as back-references are re-discovered each iteration.
	//
	// Logical depth is deliberately NOT the wall-clock iteration count. What
	// searchDepth bounds is REACHABILITY — how many hops from the seeds the
	// verify may travel — and the minimum-witness valve (below) can replay an
	// iteration. Counting iterations instead would let a replay search one hop
	// further out than an eager verify ever does, which is a FAIL→PASS
	// divergence, not merely extra work.
	//
	// allDigests preserves the caller's seed slice verbatim, duplicates
	// included, and only ever grows; digests are appended in non-decreasing
	// depth order.
	allDigests := append([]string(nil), vo.subjectDigests...)
	digestDepth := make(map[string]int, len(allDigests))
	for _, d := range allDigests {
		if _, dup := digestDepth[d]; !dup {
			digestDepth[d] = 0
		}
	}

	// Minimum-witness Phase 1 (default OFF). lazyWitnessEligible is the
	// policy-shape gate; the valve tracks steps whose truncated stream has been
	// DEMANDED back. A valve firing REPLAYS the current logical depth rather
	// than advancing it, so the repair pass re-searches exactly the frontier
	// the truncated pass under-used and reaches no further. Firings are bounded
	// by the step count (each marks at least one new step and marks are never
	// cleared), so the loop runs at most searchDepth + len(p.Steps) times.
	lazyEligible := p.lazyWitnessEligible(vo)
	valve := newDemandValve()

	for depth := 0; depth < vo.searchDepth; {
		// Steps whose candidate stream stopped at their first passing
		// collection during THIS iteration — the valve's input.
		var truncatedSteps []string

		// The search set for THIS logical depth: every digest within `depth`
		// hops of the seeds. In an EAGER verify this is always the entire
		// accumulated set — a digest discovered at iteration j carries depth
		// j+1 <= depth — so the bound is a no-op and the slice handed back is
		// the original. It only bites on a valve replay, where the previous
		// pass already harvested digests belonging to the NEXT level.
		vo.subjectDigests = searchableDigests(allDigests, digestDepth, depth)

		for _, stepName := range stepOrder {
			step := p.Steps[stepName]

			// Build cross-step context from already-verified dependencies
			// AND external-attestation context (input.external.<name>) from
			// this step's ExternalFrom list. When either AttestationsFrom or
			// ExternalFrom is non-empty, Rego input is wrapped; otherwise
			// input is the raw attestor JSON (backward compat). Built BEFORE
			// the search: its inputs (resultsByStep + externalResults) cannot
			// change while this step's candidates are fetched.
			stepCtx := buildStepRegoContext(step, resultsByStep, externalResults)

			var stepResult StepResult
			//nolint:nestif // the streamed-vs-batch dispatch is two parallel arms by design; hoisting either arm would separate it from the fallback it must stay verdict-identical to
			if streamer, ok := vo.verifiedSource.(source.StreamingVerifiedSourcer); ok {
				// INTERLEAVED path (#7572): consume candidates one at a time —
				// verify, triage, gate, compact — so at most one decoded
				// envelope body is in flight per turn, instead of
				// materializing the full matching set before evaluation.
				streamed, candidates, truncated, serr := p.verifyStepStreamed(ctx, streamer, step, vo, trustBundles, stepCtx, attestationsByStep[stepName], lazyEligible && valve.lazyAllowedFor(stepName))
				if serr != nil {
					return nil, serr
				}
				stepResult = streamed
				if truncated {
					truncatedSteps = append(truncatedSteps, stepName)
				}
				if candidates == 0 {
					// Same empty-result diagnosis as the batch path below,
					// under the same once-per-verify depth guard (#7572) —
					// see diagnoseEmptyResultOnce. A nil diag means "already
					// adjudicated at an earlier depth"; nothing is appended
					// and nothing else in this iteration has work to do,
					// since a zero-candidate stream leaves stepResult with no
					// Passed and no Rejected entries to merge or expand from.
					if diag := diagnoseEmptyResultOnce(ctx, vo.verifiedSource, stepName, resultsByStep[stepName], vo.subjectDigests, attestationsByStep[stepName]); diag != nil {
						placeholder := source.CollectionVerificationResult{Errors: []error{diag}}
						if _, rejected := step.triageOne(placeholder, trustBundles); rejected != nil {
							stepResult.Rejected = append(stepResult.Rejected, *rejected)
						}
					}
				}
			} else {
				// Use search to get all the attestations that match the supplied step name and subjects
				collections, err := vo.verifiedSource.Search(ctx, stepName, vo.subjectDigests, attestationsByStep[stepName])
				if err != nil {
					return nil, err
				}

				if len(collections) == 0 {
					// Distinguish "no envelope loaded for this step" from
					// "envelope IS loaded but operator's artifact digest
					// isn't a subject of it." Without this the operator
					// chases a phantom 'did I load my attestation?' issue
					// when the real problem is digest mismatch / scoping.
					// (Fixes blind Linux UX test Bug 2.)
					//
					// A nil diag means the step was already adjudicated at an
					// earlier depth, so this empty result carries no new
					// information — see diagnoseEmptyResultOnce (#7572).
					// Nothing below can act on an empty collection set, so
					// skip the rest of the iteration.
					diag := diagnoseEmptyResultOnce(ctx, vo.verifiedSource, stepName, resultsByStep[stepName], vo.subjectDigests, attestationsByStep[stepName])
					if diag == nil {
						continue
					}
					collections = append(collections, source.CollectionVerificationResult{Errors: []error{diag}})
				}

				// Verify the functionaries
				functionaryCheckResults := step.checkFunctionaries(collections, trustBundles)

				// Subject fan-out guard: confine this verify to the dispatch
				// subject's evidence closure — candidates connected only through
				// hub digests are dropped before the gate's attestation checks.
				// Applied to the FUNCTIONARY-AUTHORIZED set, never the raw
				// candidates: only evidence the policy authorizes for THIS step
				// may classify a digest as a hub, or a signer trusted for some
				// other step could flood a victim digest and suppress this step's
				// legitimate evidence. False-reject-only; see filterHubOnlyPassed.
				var hubRejected []RejectedCollection
				if vo.maxSubjectFanout > 0 {
					functionaryCheckResults.Passed, hubRejected = filterHubOnlyPassed(functionaryCheckResults.Passed, vo.subjectDigests, vo.maxSubjectFanout)
				}

				passedCollections := make([]source.CollectionVerificationResult, len(functionaryCheckResults.Passed))
				for i, pc := range functionaryCheckResults.Passed {
					passedCollections[i] = pc.Collection
				}

				stepResult = step.validateAttestations(passedCollections, vo.aiServerURL, stepCtx)
				stepResult.Rejected = append(stepResult.Rejected, functionaryCheckResults.Rejected...)
				// Hub-suppressed candidates are reported, never silently dropped:
				// an operator whose expected evidence was demoted as a hub sees
				// the exact digests and the limit that fired.
				stepResult.Rejected = append(stepResult.Rejected, hubRejected...)
			}

			// We perform many searches against the same step (once per depth
			// iteration), so we merge results across depths. The SAME collection
			// can be returned on multiple iterations once its subjects re-enter
			// the search set, so we de-duplicate Passed collections by content
			// key (#5746, finding F12): accumulating duplicates inflates trust
			// signals and the step_results UI with phantom passing collections.
			if result, ok := resultsByStep[stepName]; ok && result.Step != "" {
				result.Passed = mergePassedCollections(result.Passed, stepResult.Passed)
				// Rejected entries get the same cross-depth de-duplication as
				// Passed (#7572): a source without seen-envelope exclusion
				// (judge-api's EntSource) re-returns the same envelope every
				// depth, and each RejectedCollection retains the FULL parsed
				// envelope — payload bytes, statement subject tree, collection
				// attestor tree. Appending raw retained one multi-MB parse
				// tree per depth per rejection. Identity is content-based
				// (statement + reason), so distinct rejections — including the
				// same collection rejected for a different reason at a later
				// depth — are all preserved. Rejected entries never affect the
				// verdict (see searchExpansionIsMonotone).
				result.Rejected = mergeRejectedCollections(result.Rejected, stepResult.Rejected)
				resultsByStep[stepName] = result
			} else {
				resultsByStep[stepName] = stepResult
			}

			// Expand the reachable-subject set from the BackRefs of collections
			// that PASSED THE STEP GATE (stepResult.Passed), NOT merely the
			// functionary survivors (passedCollections) (#5747, finding B). A
			// collection that clears the functionary check but is REJECTED by the
			// gate (missing required attestation, failing rego, etc.) is not
			// trusted, so its signer-asserted BackRefs must not widen the search
			// — otherwise a throwaway rejected collection can make an unrelated
			// downstream collection reachable.
			for _, pc := range stepResult.Passed {
				// DETERMINISM (#7958): BackRefs() is a map of name → DigestSet
				// and DigestSet is itself a map, so ranging them yields a
				// different order every run. That order becomes the order of
				// allDigests, which becomes the order the source returns
				// candidates in, which under the minimum-witness stop decides
				// which collection is signed as the witness. Collect first,
				// sort, then admit — so the search frontier is a function of
				// the evidence and not of the map seed.
				harvested := make([]string, 0)
				for backRefName, digestSet := range pc.Collection.Collection.BackRefs() {
					for _, digest := range digestSet {
						// Empty-merkle-tree sentinel: shared identically by every
						// step that consumed or produced nothing, so it names no
						// particular collection and must not widen the search.
						// See isEmptyTreeHubBackRef.
						if isEmptyTreeHubBackRef(backRefName, digest) {
							continue
						}
						harvested = append(harvested, digest)
					}
				}
				sort.Strings(harvested)
				for _, digest := range harvested {
					// A digest harvested while searching at logical depth
					// `depth` sits one hop further out, so it becomes
					// searchable at depth+1 — never in the current
					// iteration, which is what stops a single collection
					// from widening the scope of its own depth.
					if _, seen := digestDepth[digest]; !seen {
						digestDepth[digest] = depth + 1
						allDigests = append(allDigests, digest)
					}
				}
			}
		}

		// Search scope for the next depth iteration is derived from
		// digestDepth at the top of that iteration; the harvest above has
		// already recorded every newly reachable digest at depth+1.
		//
		// Subject-graph isolation rule (issue #39): external-attestation
		// subjects are NOT added there. Only Collection BackRefs expand the
		// seed set. This preserves Collection-graph semantics.

		// DEMAND VALVE (minimum-witness Phase 1, lazy only; no-op when the
		// option is off because truncatedSteps is then always empty).
		//
		// A step that stopped at its first passing collection produced a
		// WITNESS, not a survey. If the verify is globally satisfied on that
		// witness, the skipped candidates cannot change the verdict (every
		// verdict component is existential over Passed) and we fall through to
		// the ordinary breaks below. If it is NOT satisfied, the skipped
		// evidence is now DEMANDED — for either of two reasons, both covered by
		// the same coarse response:
		//
		//   - an artifactsFrom edge is unsatisfied because the one witness this
		//     step kept is not the collection the consumer needed, or
		//   - a downstream step never found its evidence because the BackRef
		//     frontier the skipped candidates would have contributed was never
		//     harvested.
		//
		// Both are repaired by re-running the truncated steps EXHAUSTIVELY, so
		// the valve does not try to tell them apart (per-candidate cursors are
		// Phase 2). Marked steps never stop early again in this verify, so the
		// loop cannot livelock.
		//
		// The repair pass REPLAYS the current logical depth — `depth` is not
		// incremented. That is the whole safety property: the pass re-searches
		// exactly the digest set the truncated pass was entitled to and reaches
		// no further, so it can recover evidence eager would have found without
		// ever finding evidence eager could not. Granting an extra ITERATION
		// instead (the first implementation) advanced the accumulated subject
		// graph one hop past searchDepth and turned an eager FAIL into a PASS.
		if len(truncatedSteps) > 0 && !p.allStepsSatisfied(ctx, vo, resultsByStep) && valve.demand(truncatedSteps) {
			// Skip BOTH breaks below: the demanded evidence has not been
			// examined yet, so neither "nothing new is reachable" nor "not
			// satisfied" is a verdict this loop is entitled to settle on.
			continue
		}

		// Stop expanding once a further iteration cannot change the verdict.
		// Depth expansion exists to REACH evidence the seed digests do not name
		// directly; it is not an evidence-quantity requirement. Continuing past
		// the point where the answer is settled costs a full re-search of every
		// step against the accumulated digest set — on a monorepo that is
		// hundreds of envelope fetches per artifact (judge#7551).
		//
		// Case 1: nothing is reachable at the NEXT logical depth, so the next
		// iteration would issue byte-identical queries. Unconditionally safe.
		//
		// This is a question about the accumulated graph, not about what THIS
		// pass happened to harvest. In an eager verify the two coincide exactly
		// — every depth+1 digest was discovered by this iteration. After a
		// valve replay they do not: the earlier pass at this same depth already
		// recorded the frontier, so a replay that harvests nothing new would
		// strand it if the break looked only at its own harvest.
		if countDigestsAtDepth(digestDepth, depth+1) == 0 {
			break
		}

		// Case 2: every step is already satisfied, and the policy shape has no
		// AttestationsFrom (the only construct that makes verification
		// arbitrarily non-monotone). Safe because the break fires ONLY on an
		// already-passing verdict, so it can never skip evidence that would
		// rescue a failing step — see searchExpansionIsMonotone for why the
		// fan-out guard's non-monotonicity does not break this.
		//
		// NOTE: a multi-step policy that is only PARTIALLY satisfied never
		// takes either break and runs the full depth walk, re-searching every
		// step — including the already-satisfied ones — on every iteration.
		// That is the dominant cost shape in practice, not attestationsFrom.
		if p.searchExpansionIsMonotone() && p.allStepsSatisfied(ctx, vo, resultsByStep) {
			break
		}

		depth++
	}

	// Restore the full accumulated set. The loop searched a depth-bounded view
	// of it; everything downstream (and any caller reading vo back) sees the
	// same thing it always has: seeds plus every digest the walk discovered.
	vo.subjectDigests = allDigests

	resultsByStep, err = p.verifyArtifacts(ctx, vo, resultsByStep)
	if err != nil {
		return nil, fmt.Errorf("failed to verify artifacts: %w", err)
	}

	// A policy is invalid when it declares nothing to verify — no steps AND no
	// external attestations. External-attestations-only policies (e.g. VSA-chain
	// gates) are valid after #39; they're verified in verifyExternalAttestations
	// which runs before this function returns control.
	if len(resultsByStep) == 0 && len(p.ExternalAttestations) == 0 {
		return nil, fmt.Errorf("policy has no steps or external attestations to verify")
	}

	return resultsByStep, nil
}

// streamedVerdict labels the outcome recorded for one functionary-AUTHORIZED
// candidate while the stream was in flight.
type streamedVerdict int

const (
	streamedGatePassed streamedVerdict = iota
	streamedGateRejected
	// streamedWrongName: the gate skipped the candidate entirely — it is not
	// named for this step (F10; see gateOne).
	streamedWrongName
	// streamedHubSkip: the gate never ran — the fan-out tracker proved
	// mid-stream that the candidate can only be hub-rejected (fan-out counts
	// are monotone), so its gate verdict would be discarded anyway.
	streamedHubSkip
	// streamedDeferredGate: the gate has not run YET. Used when the step
	// declares AI policies and the fan-out guard is active: gate evaluation
	// makes external AI-server calls, and a provisional evaluation of a
	// candidate the final classification then hub-rejects would be an AI
	// request the batch path never makes. The candidate holds only its raw
	// signed payload (decoded bodies dropped); the gate runs post-admission
	// on a rehydrated copy. See verifyStepStreamed.
	streamedDeferredGate
)

// stepHasAiPolicies reports whether any of the step's required attestations
// carries AI policies — the side-effecting gate evaluations whose execution
// must wait for final fan-out admission on the streamed path.
func stepHasAiPolicies(step Step) bool {
	for _, att := range step.Attestations {
		if len(att.AiPolicies) > 0 {
			return true
		}
	}
	return false
}

// compactAwaitingGate strips the decoded bodies from a functionary-authorized
// candidate whose gate evaluation is deferred until fan-out admission. The
// raw signed payload (Envelope.Payload) is kept — it is the rehydration
// source the deferred gate decodes from — and Statement.Predicate is already
// nil (the source releases it once the payload is retained). Only the typed
// Collection is dropped, so a deferred candidate costs O(raw payload), not
// O(decoded bodies).
func compactAwaitingGate(c source.CollectionVerificationResult) source.CollectionVerificationResult {
	c.Collection = attestation.Collection{Name: c.Collection.Name}
	return c
}

// rehydrateAwaitingGate re-decodes the typed Collection from the retained
// signed payload — same bytes, same in-process registry, therefore the same
// typed result the inline gate would have seen. The stored Statement is kept
// as-is (Subject/Type/PredicateType from the source decode; Predicate nil),
// matching the inline gate's input exactly.
func rehydrateAwaitingGate(c source.CollectionVerificationResult) (source.CollectionVerificationResult, error) {
	stmt := intoto.Statement{}
	if err := json.Unmarshal(c.Envelope.Payload, &stmt); err != nil {
		return c, fmt.Errorf("rehydrate %s for deferred gate: failed to unmarshal statement: %w", c.Reference, err)
	}
	coll := attestation.Collection{}
	if err := json.Unmarshal(stmt.Predicate, &coll); err != nil {
		return c, fmt.Errorf("rehydrate %s for deferred gate: failed to unmarshal collection: %w", c.Reference, err)
	}
	c.Collection = coll
	return c, nil
}

// verifyStepStreamed is the INTERLEAVED per-candidate form of the step
// pipeline (#7572). For each candidate, as it streams from the source:
// signature verification (inside StreamingVerifiedSourcer), functionary
// triage (triageOne), the step gate (gateOne) and pass/reject compaction all
// complete before the next candidate's decoded body is materialized, so the
// verify peak is O(largest envelope) + O(compact results), not O(matching
// corpus). It produces the same StepResult as the batch path —
// checkFunctionaries → filterHubOnlyPassed → validateAttestations — with the
// same entry ordering (gate rejections, then functionary rejections, then
// hub rejections).
//
// Subject fan-out guard equivalence: the batch guard classifies hubs over
// the FULL functionary-authorized candidate set before any gate runs. Here
// candidates are gated as they arrive — before the full set is known — so
// gate verdicts are provisional: the final hub classification runs at end of
// stream over exactly the same authorized set (per-candidate closure
// intersections + counts accumulated by fanoutTracker), and a candidate it
// demotes has its gate verdict DISCARDED and replaced by the hub rejection,
// exactly as if the gate had never seen it. BackRef harvesting is unaffected:
// the caller reads BackRefs from the final Passed set (compacted with
// RecordedBackRefs stamped at gate time, before the body was released), so
// depth expansion sees frontiers identical to the batch path.
//
// The one deliberate delta vs the batch order is COST, not output: a
// candidate whose hub-only status is not yet provable when it arrives is
// gate-evaluated even though the final classification may demote it. The
// tracker's provably-rejected fast path bounds that extra work at
// ~maxFanout gate evaluations per hub digest — and it is PURE work only:
// for steps carrying AI policies (external server calls) the entire gate is
// deferred until admission is final (deferGateForAI), so a hub-rejected
// candidate never triggers an AI request the batch path would not have made.
//
// LAZY STOP (minimum-witness Phase 1, lazyAllowed; default off). When the
// caller allows it AND the fan-out guard is inactive for this search, the
// stream is ABORTED at the first candidate the gate passes: one passing
// collection is all StepResult.Analyze, verifyArtifacts and allStepsSatisfied
// ever need (they are existential over Passed), so the remaining candidates
// are fetched, DSSE-verified and gated for nothing. The third return value
// reports the truncation so the depth loop's demand valve can un-truncate the
// step if the verify does not settle on that witness.
//
// The guard exclusion is not a convenience: hub classification counts
// candidates and counts only grow, so a truncated stream sees a SMALLER hub
// set and would admit candidates the full stream demotes. Those demotions are
// false rejects, so the divergence is FAIL→PASS — the direction a Phase whose
// contract is bit-identical verdicts must not take. It also means
// deferGateForAI (tracker-dependent) and streamedHubSkip are unreachable
// whenever the lazy stop is live.
func (p Policy) verifyStepStreamed(ctx context.Context, streamer source.StreamingVerifiedSourcer, step Step, vo *verifyOptions, trustBundles map[string]TrustBundle, stepCtx map[string]interface{}, attestations []string, lazyAllowed bool) (StepResult, int, bool, error) { //nolint:gocognit,gocyclo,funlen // one candidate's verify-triage-gate-compact lifecycle reads as a single pipeline; splitting it would scatter the per-candidate memory contract this function exists to enforce
	// authorizedCandidate is the compact per-candidate state retained while
	// the stream is in flight: the gate verdict, the closure-intersection
	// digests for the final fan-out classification, and the compacted
	// rejection material a hub demotion would need (captured post-triage,
	// exactly what the batch guard's compactHubReject reads). No decoded
	// bodies and no raw envelope bytes are retained here beyond what the
	// compacted verdicts themselves carry.
	type authorizedCandidate struct {
		verdict     streamedVerdict
		pc          PassedCollection
		gateReject  RejectedCollection
		hubMaterial source.CollectionVerificationResult
		digests     map[string]struct{}
		// deferred holds the candidate awaiting its gate run (raw payload
		// kept, decoded bodies dropped) when verdict == streamedDeferredGate.
		deferred source.CollectionVerificationResult
	}

	var authorized []authorizedCandidate
	var funcRejected []RejectedCollection
	tracker := newFanoutTracker(vo.subjectDigests, vo.maxSubjectFanout)
	// AI policies make external server calls from inside the gate. With the
	// guard active, a provisional gate run on a candidate the final
	// classification later hub-rejects would be an AI request the batch path
	// never makes — so for AI-bearing steps the whole gate is deferred until
	// admission is final. Hub-rejected candidates make ZERO AI calls. The
	// cost is holding the raw payload of each not-provably-rejected
	// candidate until end of stream — bounded by ~(maxFanout+1) candidates
	// per hub digest plus the genuine closure evidence.
	deferGateForAI := tracker != nil && stepHasAiPolicies(step)
	candidates := 0
	// The fan-out guard and the lazy stop are mutually exclusive: see the
	// function doc. tracker == nil is the guard's own no-op condition
	// (newFanoutTracker), read here rather than recomputed so the two can
	// never drift apart.
	lazyStop := lazyAllowed && tracker == nil
	truncated := false

	err := streamer.SearchStream(ctx, step.Name, vo.subjectDigests, attestations, func(cvr source.CollectionVerificationResult) error {
		candidates++
		triaged, rejected := step.triageOne(cvr, trustBundles)
		if rejected != nil {
			funcRejected = append(funcRejected, *rejected)
			return nil
		}

		ac := authorizedCandidate{hubMaterial: compactRejected(triaged)}
		provablyRejected := false
		if tracker != nil {
			ac.digests, provablyRejected = tracker.add(triaged.Statement.Subject)
		}
		switch {
		case provablyRejected:
			ac.verdict = streamedHubSkip
		case deferGateForAI:
			ac.verdict = streamedDeferredGate
			ac.deferred = compactAwaitingGate(triaged)
		default:
			switch outcome, pc, rc := step.gateOne(triaged, vo.aiServerURL, stepCtx); outcome {
			case gatePassed:
				ac.verdict, ac.pc = streamedGatePassed, pc
			case gateRejected:
				ac.verdict, ac.gateReject = streamedGateRejected, rc
			case gateWrongName:
				ac.verdict = streamedWrongName
			}
		}
		authorized = append(authorized, ac)
		// LAZY STOP: the step is satisfied — abort the stream. Everything the
		// verdict reads is existential over Passed, so the untouched
		// candidates cannot change it unless the verify fails to settle, in
		// which case the depth loop's demand valve re-runs this step
		// exhaustively.
		if lazyStop && ac.verdict == streamedGatePassed {
			truncated = true
			return errStepSatisfied
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStepSatisfied) {
		return StepResult{}, 0, false, err
	}

	// End of stream: final hub classification over the full authorized set,
	// then assembly in the batch path's entry order.
	result := StepResult{Step: step.Name}
	var hubRejected []RejectedCollection
	var hubs map[string]struct{}
	if tracker != nil {
		hubs = tracker.hubs()
	}
	for _, ac := range authorized {
		admitted := true
		var hubOnly []string
		if tracker != nil {
			admitted, hubOnly = classifyAdmission(ac.digests, hubs)
		}
		if !admitted {
			// Hub-suppressed candidates are reported, never silently
			// dropped, whichever provisional verdict they carried.
			hubRejected = append(hubRejected, RejectedCollection{
				Collection: compactHubReject(ac.hubMaterial),
				Reason:     hubRejectReason(hubOnly, vo.maxSubjectFanout),
			})
			continue
		}
		switch ac.verdict {
		case streamedGatePassed:
			result.Passed = append(result.Passed, ac.pc)
		case streamedGateRejected:
			result.Rejected = append(result.Rejected, ac.gateReject)
		case streamedWrongName:
			// Admitted but not named for this step: skipped, as in the batch
			// gate (F10).
		case streamedDeferredGate:
			// Admission is final — run the deferred gate (including its AI
			// evaluations) on the rehydrated candidate, in stream order,
			// exactly as the batch path gates its admitted set.
			full, rerr := rehydrateAwaitingGate(ac.deferred)
			if rerr != nil {
				// Fail closed: the payload decoded successfully at the
				// source, so this is unreachable for a real candidate.
				return StepResult{}, 0, false, rerr
			}
			switch outcome, pc, rc := step.gateOne(full, vo.aiServerURL, stepCtx); outcome {
			case gatePassed:
				result.Passed = append(result.Passed, pc)
			case gateRejected:
				result.Rejected = append(result.Rejected, rc)
			case gateWrongName:
				// Skipped, as in the batch gate (F10).
			}
		case streamedHubSkip:
			// Impossible: a provably-rejected candidate cannot be admitted by
			// the final classification (counts are monotone). Fail closed
			// rather than silently dropping a candidate whose gate never ran.
			return StepResult{}, 0, false, fmt.Errorf("internal: hub-skipped candidate %s admitted by final fan-out classification", ac.hubMaterial.Reference)
		}
	}
	result.Rejected = append(result.Rejected, funcRejected...)
	result.Rejected = append(result.Rejected, hubRejected...)
	return result, candidates, truncated, nil
}

// searchExpansionIsMonotone reports whether the POLICY SHAPE is free of the
// one construct that makes step verification arbitrarily non-monotone in the
// discovered-collection set: Step.AttestationsFrom. It gates the depth loop's
// "already satisfied" early break.
//
// SCOPE — read this before relying on the name. It is a statement about the
// policy's shape, NOT a guarantee that widening the search cannot subtract
// from a verdict. The subject fan-out guard (filterHubOnlyPassed) makes
// verification non-monotone in the CANDIDATE set for every policy shape:
// admitting more authorized evidence can push a closure digest over the
// fan-out limit, classify it as a hub, and demote evidence that previously
// passed. Measured: the same subject and policy verify PASS with one
// envelope present and FAIL with six.
//
// The early break remains sound anyway, for a reason the original enumeration
// did not state. It fires only when every step is ALREADY satisfied, so it
// can never skip evidence that would rescue a failing step. What further
// expansion could do is demote a passing step — and only via the guard, whose
// demotions are false rejects by construction. Stopping early therefore
// preserves a verdict reached on evidence that was crypto-verified,
// functionary-authorized and gate-passed on its own merits; it cannot
// manufacture a pass.
//
// CONSEQUENCE, worth stating plainly: a verdict is no longer a pure function
// of (subject, policy). It depends on what else the corpus holds, in the
// false-reject direction. That is the accepted cost of bounding fan-out, and
// it is why a verdict cannot be safely cached and replayed against a
// different corpus state.
//
// The components below are monotone in the discovered-collection set, which
// is what makes AttestationsFrom the only shape-level exception:
//
//   - validateAttestations judges each collection independently (step.go); with
//     no cross-step context, one collection's verdict cannot be changed by the
//     presence of another.
//   - mergePassedCollections only appends, so StepResult.Passed grows monotonically.
//   - StepResult.Analyze is `len(Passed) > 0`. Its "errors lurking in a passed
//     collection" branch cannot fire, because validateAttestations routes any
//     collection carrying Errors to Rejected rather than Passed.
//   - verifyArtifacts accepts a step if ANY passed collection verifies, and
//     verifyCollectionArtifacts satisfies an artifactsFrom edge if ANY upstream
//     passed collection matches. Both are existential.
//   - Rejected collections never affect the verdict.
//
// The one exception is Step.AttestationsFrom. It feeds upstream steps' passed
// collections into Rego as evaluation input (buildStepRegoContext), and an
// arbitrary Rego module over that set need not be monotone — a rule asserting
// "exactly one upstream collection" flips from pass to fail as more collections
// are discovered. A policy that uses it must run the full search.
//
// Step.ExternalFrom is NOT an exception: external attestations are verified once,
// before the depth loop, against the policy's seed digests only, and verifySteps
// never mutates externalResults — so that Rego context is depth-invariant.
func (p Policy) searchExpansionIsMonotone() bool {
	for _, step := range p.Steps {
		if len(step.AttestationsFrom) > 0 {
			return false
		}
	}
	return true
}

// allStepsSatisfied reports whether every step currently has at least one passed
// collection whose artifacts also verify — i.e. whether the step-verification
// phase would already return a passing verdict.
//
// It answers exactly the question the final verdict will answer, by running the
// SAME convergence (convergeArtifactPruning) the verdict runs — on a CLONE, so
// nothing here mutates resultsByStep. That sharing is load-bearing rather than
// tidy: a predicate that judged the UNPRUNED results could see a step satisfied
// by a collection the verdict is about to prune, stop the depth loop, and then
// return FAIL — a false FAIL, because the next depth may hold a legitimate
// replacement for exactly that collection. Settlement and verdict must be
// decided on one view.
//
// The depth loop deliberately continues with the UNPRUNED results: a collection
// that cannot satisfy its artifact edge at this depth may still be the upstream
// that a later depth's evidence hangs off, so pruning must not be made
// permanent until the search is over.
//
// Cost: one clone plus one convergence per depth iteration, O(collections ×
// artifactsFrom edges). Bounded by the same cap as the verdict path.
func (p Policy) allStepsSatisfied(ctx context.Context, vo *verifyOptions, resultsByStep map[string]StepResult) bool {
	if len(p.Steps) == 0 {
		return false
	}

	// Cheap pre-check: a step with no adjudicated evidence at all can never be
	// settled, and this skips the clone for the common not-yet-satisfied case.
	for _, step := range p.Steps {
		result, ok := resultsByStep[step.Name]
		if !ok || !result.Analyze() {
			return false
		}
	}

	pruned := cloneStepResults(resultsByStep)
	p.convergeArtifactPruning(ctx, vo, p.sortedStepNames(), pruned)

	for _, step := range p.Steps {
		if len(pruned[step.Name].Passed) == 0 {
			return false
		}
	}

	return true
}

// mergePassedCollections appends src onto dst while skipping any collection
// already present in dst (#5746, finding F12). Across depth iterations the same
// collection can be re-discovered once its subjects re-enter the search set;
// without de-duplication it would be appended once per iteration, inflating the
// passing-collection count in trust signals and the step_results UI. Identity
// is by content key (passedCollectionKey), so genuinely distinct collections
// are still preserved.
func mergePassedCollections(dst, src []PassedCollection) []PassedCollection {
	seen := make(map[string]struct{}, len(dst))
	for _, pc := range dst {
		seen[passedCollectionKeyOf(pc)] = struct{}{}
	}
	for _, pc := range src {
		key := passedCollectionKeyOf(pc)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, pc)
	}
	return dst
}

// passedCollectionKeyOf returns the collection's content identity: the
// pass-time payload key stamped at the gate (payloadContentKey — the raw
// signed payload bound to the verified-signer set), or, for collections that
// did not travel the byte-retaining gate path (direct construction in tests,
// legacy sources), the legacy statement-marshal key. The two are namespaced
// apart so they can never collide; within one verify every gate-produced
// collection carries the same key form, so dedup semantics are uniform.
func passedCollectionKeyOf(pc PassedCollection) string {
	if pc.contentKey != "" {
		return pc.contentKey
	}
	return passedCollectionKey(pc)
}

// mergeRejectedCollections appends src onto dst while skipping entries already
// present in dst — the Rejected-side counterpart of mergePassedCollections
// (#7572). Identity is rejectedCollectionKey: the statement/envelope content
// key PLUS the rejection reason, so the same collection rejected for a
// DIFFERENT reason at a later depth is preserved, while the byte-identical
// re-rejection an exclusion-less source produces every depth collapses to one
// entry. Rejected entries are diagnostic only — they never affect the verdict
// (see searchExpansionIsMonotone) — so de-duplication cannot change a
// verification outcome, only stop retaining searchDepth copies of a fully
// parsed envelope per rejection.
func mergeRejectedCollections(dst, src []RejectedCollection) []RejectedCollection {
	seen := make(map[string]struct{}, len(dst))
	for _, rc := range dst {
		seen[rejectedCollectionKey(rc)] = struct{}{}
	}
	for _, rc := range src {
		key := rejectedCollectionKey(rc)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, rc)
	}
	return dst
}

// diagnoseEmptyResultOnce is the depth loop's ONLY route to
// diagnoseEmptyCollectionResult, and the single place the #7572
// once-per-verify rule lives. It returns nil — diagnose nothing — when the
// step already carries results from an earlier depth.
//
// WHY THE RULE IS SOUND. The depth loop only ever WIDENS the digest set
// (vo.subjectDigests is appended to at the end of each iteration, never
// reset), so a step that matched something at depth N still matches it at
// depth N+1. An empty result at a later depth therefore means "nothing NEW
// was reached", not "this step has no evidence" — and re-answering the
// question the diagnostic asks would produce the same answer at a real cost.
// The probe is an UNFILTERED search: on a prod source it re-fetches and
// re-verifies every collection ever recorded under the step name (806
// candidate envelopes in the incident that opened #7572), and each repeat
// also appends another multi-line diagnostic rejection.
//
// WHY IT LIVES HERE RATHER THAN AT THE CALL SITES. It used to be inline at
// the batch call site only, and the streamed arm — which is the arm every
// PRODUCTION verify takes, because *source.VerifiedSource always satisfies
// StreamingVerifiedSourcer — silently had no guard at all: three probes per
// verify at the default search depth, against the batch arm's one. Nothing in
// the code made that second, unguarded call site visible. Routing both arms
// through one guarded function makes the un-guarded probe unreachable rather
// than merely discouraged; TestDiagnosticProbeIsReachableOnlyThroughTheDepthGuard
// fails if a third call site is ever added.
//
// It is verdict-safe by construction: it can only suppress a REJECTED entry,
// and rejections never contribute to a verdict (only StepResult.Passed does —
// see allStepsSatisfied and searchExpansionIsMonotone). It cannot suppress the
// FIRST diagnosis for a step, so every consumer that needs an ErrNoCollections
// to be present — judge-api's readiness classifier, most sharply — still sees
// exactly one.
//
// prior is resultsByStep[stepName] read WITHOUT the comma-ok. A step not yet
// in the map yields the zero StepResult, which has no Passed and no Rejected
// entries and so fails the predicate on its own; a separate "was it present"
// boolean would be a parameter no input can distinguish, and it is precisely
// that first-encounter case the batch arm's `continue` depends on — a step
// reaching verifyArtifacts with no entry in the results map is a hard error
// ("failed to find step %s in step results map"), so the guard MUST NOT be
// able to fire before a step has been recorded even once.
func diagnoseEmptyResultOnce(ctx context.Context, src source.VerifiedSourcer, stepName string, prior StepResult, suppliedDigests, attestations []string) error {
	if len(prior.Passed) > 0 || len(prior.Rejected) > 0 {
		return nil
	}
	return diagnoseEmptyCollectionResult(ctx, src, stepName, suppliedDigests, attestations)
}

// rejectedCollectionKey returns a stable content identity for a rejected
// collection. The collection identity reuses the passed-collection key
// derivation (statement + verified-signer set, with the deterministic
// envelope-content fallback for entries that never parsed a statement), and
// the rejection REASON is framed in so distinct failure modes never collapse.
// A nil reason (not produced today, but the type allows it) frames as empty.
func rejectedCollectionKey(rc RejectedCollection) string {
	collectionKey := passedCollectionKey(PassedCollection{Collection: rc.Collection})
	reason := ""
	if rc.Reason != nil {
		reason = rc.Reason.Error()
	}
	var buf bytes.Buffer
	writeFramed(&buf, []byte(collectionKey))
	writeFramed(&buf, []byte(reason))
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// passedCollectionKey returns a stable content identity for a passed
// collection, used to de-duplicate the same collection re-discovered across
// depth iterations.
//
// Identity is the verified in-toto Statement (subject + predicateType +
// predicate) bound to the SET OF SIGNERS THAT ACTUALLY PASSED VERIFICATION
// (ValidFunctionaries), NOT the raw DSSE envelope bytes or the source
// reference. DSSE signatures cover only the payload, so keying on the envelope
// would let an attacker mutate/append unverified signature entries — or vary
// the source reference — to make the SAME verified collection hash to a new
// key and be counted twice; reference-based keying could likewise wrongly
// collapse genuinely distinct collections from a MultiSource. Keying on the
// verified signer identity is malleability-resistant (GHSA-c346-qp3r-53vf).
//
// Fields are length-prefix framed so field boundaries are unambiguous, and the
// signer key IDs are sorted so the identity is order-independent.
func passedCollectionKey(pc PassedCollection) string {
	cvr := pc.Collection

	stmt, err := json.Marshal(cvr.Statement)
	if err != nil {
		// Marshaling the statement should not fail (it is already-parsed JSON in
		// the verified path). If it does, fall back to a DETERMINISTIC,
		// content-derived key so identical collections still collapse and
		// distinct ones stay distinct — never a non-stable per-instance key.
		return passedCollectionFallbackKey(cvr)
	}

	// Collect the DISTINCT verified signer key IDs. The set (not the multiset)
	// is the identity: the same verifier can legitimately appear more than once
	// in ValidFunctionaries (e.g. accumulated across search-depth iterations),
	// and that must not change the collection's identity.
	seen := make(map[string]struct{}, len(cvr.ValidFunctionaries))
	keyIDs := make([]string, 0, len(cvr.ValidFunctionaries))
	for _, v := range cvr.ValidFunctionaries {
		kid, err := v.KeyID()
		if err != nil {
			return passedCollectionFallbackKey(cvr)
		}
		if _, ok := seen[kid]; ok {
			continue
		}
		seen[kid] = struct{}{}
		keyIDs = append(keyIDs, kid)
	}
	sort.Strings(keyIDs)

	var buf bytes.Buffer
	writeFramed(&buf, stmt)
	for _, kid := range keyIDs {
		writeFramed(&buf, []byte(kid))
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// passedCollectionFallbackKey is the deterministic fallback identity used only
// when the verified Statement cannot be marshaled or a verified signer's KeyID
// cannot be derived — exceptional cases that do not occur in the standard
// verified path. It is derived from the DSSE envelope payload + signatures so
// it is stable (identical collections collapse, distinct collections do not),
// unlike a per-instance pointer key which would silently defeat de-duplication.
// It is namespaced so it can never collide with a normal identity key.
func passedCollectionFallbackKey(cvr source.CollectionVerificationResult) string {
	env := cvr.Envelope
	var buf bytes.Buffer
	writeFramed(&buf, env.Payload)
	writeFramed(&buf, []byte(env.PayloadType))
	for _, s := range env.Signatures {
		writeFramed(&buf, []byte(s.KeyID))
		writeFramed(&buf, s.Signature)
	}
	// When the envelope bytes were released upstream (VerifiedSource drops
	// payload/signatures from results), the hash above is content-free and
	// every exceptional candidate would collapse to ONE near-common key —
	// silently deduplicating DISTINCT collections. Bind the source reference
	// in that case: it may under-deduplicate across sources, which is the
	// safe direction (a duplicate survives; a distinct collection is never
	// swallowed).
	if len(env.Payload) == 0 && len(env.Signatures) == 0 {
		writeFramed(&buf, []byte(cvr.Reference))
	}
	sum := sha256.Sum256(buf.Bytes())
	return "fallback:" + hex.EncodeToString(sum[:])
}

// writeFramed writes b to buf prefixed with its big-endian uint64 length, so
// concatenated fields cannot be confused for one another when hashed.
func writeFramed(buf *bytes.Buffer, b []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
	buf.Write(lenBuf[:])
	buf.Write(b)
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

		// Passed count = 0 AND required → hard failure. Two sub-cases:
		// (a) no envelopes were ever found (already handled at line ~593
		//     where we return ErrMissingExternalAttestation before the
		//     envelope loop). If we're here, len(envelopes) > 0.
		// (b) envelopes were found but every one was rejected (functionary
		//     mismatch, rego deny, ai deny). Returning
		//     ErrMissingExternalAttestation here would mask the real deny
		//     reason. Surface the rejection reasons instead.
		if len(er.Passed) == 0 && ext.Required {
			results[name] = er
			reasons := make([]error, 0, len(er.Rejected))
			for _, r := range er.Rejected {
				reasons = append(reasons, r.Reason)
			}
			return results, ErrExternalAttestationRejected{
				Name:          name,
				PredicateType: ext.PredicateType,
				Rejections:    reasons,
			}
		}

		results[name] = er
	}

	return results, nil
}

// compactRejected strips the retained bodies from a REJECTED verification
// result before it is stored in StepResult.Rejected. On the prod corpus the
// step results held the full parsed Statement (multi-MB predicate
// json.RawMessage) AND the typed Collection (decoded material leaves) for
// every rejected candidate — ~85% of candidates on the incident corpus —
// making durable verify memory proportional to the corpus rather than to the
// evidence that passed (#7572).
//
// Rejected results are WRITE-ONLY downstream of the rejection decision. The
// audited reader set (every non-test consumer of StepResult.Rejected /
// RejectedCollection as of this change) reads ONLY:
//
//   - Reason                       — deny reasons, readiness classification
//     (errors.As on typed errors), trust-mismatch carriers, tests
//   - Collection.Reference         — deny reasons, step_results, VSA descriptors
//   - Collection.Collection.Name   — deny reasons, CLI failure rendering
//   - Collection.Warnings          — functionary-validate diagnostics surfaced
//     as supplementary deny reasons
//   - Collection.Errors            — envelope-level verification errors
//   - Collection.PayloadDigests    — the VSA's inputAttestations descriptors
//     for rejected evidence on a non-accepted verify
//
// (judge-api's leafFromRejection also probes Collection.Envelope.Signatures,
// but VerifiedSource releases those bytes before any rejection is recorded —
// verified.go releaseEnvelopeBytes — so that fallback is already nil on every
// policy-engine path; its live carrier is the typed error in Reason.)
//
// Everything else — Statement, the parsed Collection members, the Envelope —
// is dropped. A FRESH struct is built rather than niling fields on the copy
// so no retained slice can alias a larger backing allocation.
//
// The rejection Reason must be fully constructed BEFORE compaction: reasons
// routinely render statement subjects and collection contents, and those
// reads are part of the rejection decision, not post-decision consumption.
func compactRejected(c source.CollectionVerificationResult) source.CollectionVerificationResult {
	return source.CollectionVerificationResult{
		Errors:   c.Errors,
		Warnings: c.Warnings,
		CollectionEnvelope: source.CollectionEnvelope{
			Reference:      c.Reference,
			PayloadDigests: c.PayloadDigests,
			Collection:     attestation.Collection{Name: c.Collection.Name},
		},
	}
}

// compactPassed strips the DECODED bodies from a PASSED verification result,
// keeping the RAW signed payload (moved to PassedCollection.rawPayload by the
// caller) as the single rehydration source. On the prod corpus the decoded
// form — typed material leaves plus the raw predicate message — is ~2.9x the
// raw payload bytes, and a passing verify retained it for every passed
// candidate for the whole verify lifetime (#7572).
//
// KEPT (the audited post-decision reader set for passed collections):
//
//   - Verifiers / ValidFunctionaries / VerifiedTimestampsByKeyID — step
//     results, timestamp constraints, VSA construction, callers
//   - Warnings / Errors — StepResult.Analyze and deny-reason surfacing
//   - Reference / PayloadDigests — step results, VSA inputAttestations
//   - Statement.Type/Subject/PredicateType — diagnostics and the subject
//     fan-out guard's closure intersection (Predicate is already nil: the
//     source releases it once the payload is retained)
//   - Collection.Name — gate identity, deny reasons, callers
//   - Collection.RecordedBackRefs — normalized to the collection's full
//     BackRefs() so depth expansion reads identical edges post-compaction
//     (Collection.BackRefs prefers RecordedBackRefs)
//
// DROPPED: Collection.Attestations (typed attestors incl. decoded material
// leaves) and the Envelope (payload moves to rawPayload; signatures are
// already released). The three post-decision readers of the dropped data —
// verifyCollectionArtifacts' inline-leaf/materials checks, buildStepContext's
// cross-step Rego input, and the merge identity — rehydrate from rawPayload
// (hydratedCollection) or use the pass-time content key.
//
// A fresh struct is built rather than niling fields on the copy so no
// retained slice aliases a larger backing allocation.
func compactPassed(c source.CollectionVerificationResult) source.CollectionVerificationResult {
	return source.CollectionVerificationResult{
		Verifiers:                 c.Verifiers,
		ValidFunctionaries:        c.ValidFunctionaries,
		VerifiedTimestampsByKeyID: c.VerifiedTimestampsByKeyID,
		Errors:                    c.Errors,
		Warnings:                  c.Warnings,
		CollectionEnvelope: source.CollectionEnvelope{
			Reference:      c.Reference,
			PayloadDigests: c.PayloadDigests,
			// PayloadType survives compaction: the payload/signature BYTES
			// were already released upstream (VerifiedSource), but the type
			// string is part of the serialized result contract
			// (PassedCollection.MarshalJSON reproduces the pre-compaction
			// JSON byte-identically, and dsse.Envelope serializes
			// payloadType unconditionally).
			Envelope: dsse.Envelope{PayloadType: c.Envelope.PayloadType},
			Statement: intoto.Statement{
				Type:          c.Statement.Type,
				Subject:       c.Statement.Subject,
				PredicateType: c.Statement.PredicateType,
			},
			Collection: attestation.Collection{
				Name:             c.Collection.Name,
				RecordedBackRefs: c.Collection.BackRefs(),
			},
		},
	}
}

// payloadContentKey is the pass-time content identity of a passed collection:
// the RAW SIGNED PAYLOAD bytes bound to the set of verified signer key IDs,
// length-prefix framed and namespaced apart from the legacy statement-marshal
// key. The payload IS the signed statement (subject + predicateType +
// predicate), so this binds strictly more than the legacy key's re-marshal of
// the parsed Statement — and it costs a hash instead of a multi-MB
// json.Marshal per merge (#7572; the passedCollectionKey re-marshal was a
// post-decision body re-reader). Computed BEFORE compaction while the
// verified payload is in hand; malleability reasoning is unchanged from
// passedCollectionKey (GHSA-c346-qp3r-53vf): signatures and source reference
// do not participate.
func payloadContentKey(cvr source.CollectionVerificationResult) string {
	seen := make(map[string]struct{}, len(cvr.ValidFunctionaries))
	keyIDs := make([]string, 0, len(cvr.ValidFunctionaries))
	for _, v := range cvr.ValidFunctionaries {
		if v == nil {
			continue
		}
		kid, err := v.KeyID()
		if err != nil {
			// Deterministic, content-derived degradation: bind the payload
			// alone. Never a per-instance key.
			continue
		}
		if _, ok := seen[kid]; ok {
			continue
		}
		seen[kid] = struct{}{}
		keyIDs = append(keyIDs, kid)
	}
	sort.Strings(keyIDs)
	var buf bytes.Buffer
	writeFramed(&buf, cvr.Envelope.Payload)
	for _, kid := range keyIDs {
		writeFramed(&buf, []byte(kid))
	}
	sum := sha256.Sum256(buf.Bytes())
	return "payload:" + hex.EncodeToString(sum[:])
}

// checkFunctionaries checks to make sure the signature on each statement corresponds to a trusted functionary for
// the step the statement corresponds to
// triageTrustedCollection decides whether a signature-verified collection is
// accepted for the step. Returns nil to accept, or the rejection reason.
// Two gates run here, in order:
//  1. Functionary match — at least one verifier must have matched an allowed
//     functionary; the per-functionary failures captured as warnings are
//     surfaced so the operator sees WHY each one rejected the cert.
//  2. TimestampConstraint — the step's time-interval requirement, enforced
//     against the RFC3161 TSA-VERIFIED signing time. This runs only after a
//     functionary matched: an unsigned/untrusted envelope is already rejected,
//     and the constraint must judge the trusted time, not a self-asserted one.
//     Fail-closed when the collection carries no verified TSA timestamp.
func (step Step) triageTrustedCollection(statement source.CollectionVerificationResult) error {
	if len(statement.ValidFunctionaries) == 0 {
		reason := fmt.Errorf("no verifiers matched the allowed functionaries for step %s", step.Name)
		if len(statement.Warnings) > 0 {
			reason = fmt.Errorf("%w: %s", reason, strings.Join(statement.Warnings, "; "))
		}
		return reason
	}

	// Scope the timestamps to the signatures whose verifiers actually matched
	// an allowed functionary. In a multi-signature envelope, a fresh TSA
	// token on some OTHER (non-functionary) signature must not satisfy the
	// constraint for the trusted signature.
	functionaryTimestamps := make([]time.Time, 0)
	for _, v := range statement.ValidFunctionaries {
		if v == nil {
			continue
		}
		if kid, err := v.KeyID(); err == nil {
			functionaryTimestamps = append(functionaryTimestamps, statement.VerifiedTimestampsByKeyID[kid]...)
		}
	}
	if err := step.TimestampConstraint.Check(functionaryTimestamps, time.Now()); err != nil {
		return fmt.Errorf("timestamp constraint failed for step %s: %w", step.Name, err)
	}

	return nil
}

func (step Step) checkFunctionaries(statements []source.CollectionVerificationResult, trustBundles map[string]TrustBundle) StepResult {
	result := StepResult{Step: step.Name}
	for i := range statements {
		triaged, rejected := step.triageOne(statements[i], trustBundles)
		statements[i] = triaged
		if rejected != nil {
			result.Rejected = append(result.Rejected, *rejected)
		} else {
			result.Passed = append(result.Passed, PassedCollection{Collection: triaged})
		}
	}

	return result
}

// triageOne runs the per-candidate functionary triage — placeholder-error
// surfacing, predicate-type check, functionary validation (accumulating
// per-functionary failure warnings and ValidFunctionaries on the returned
// copy), and triageTrustedCollection. Extracted from the checkFunctionaries
// loop body so the interleaved per-candidate pipeline (verifyStepStreamed)
// and the batch path share one triage implementation. Exactly one outcome
// applies: a non-nil rejection, or the returned statement is
// functionary-AUTHORIZED for this step.
func (step Step) triageOne(statement source.CollectionVerificationResult, trustBundles map[string]TrustBundle) (source.CollectionVerificationResult, *RejectedCollection) { //nolint:gocognit
	// If the caller supplied a placeholder result carrying an authoritative
	// error (e.g. ErrNoCollections when the source returned zero matches),
	// surface that error directly instead of misclassifying the empty
	// statement as a bad predicate type. The predicate-type check below
	// would otherwise swallow the real reason and produce a misleading
	// "predicate type  is not a collection predicate type" error.
	if len(statement.Errors) > 0 && len(statement.Verifiers) == 0 && len(statement.Envelope.Payload) == 0 && statement.Statement.PredicateType == "" {
		reason := errors.Join(statement.Errors...)
		return statement, &RejectedCollection{Collection: compactRejected(statement), Reason: reason}
	}

	// Check that the statement contains a predicate type that we accept.
	// A statement with the wrong predicate type must be rejected and must
	// NOT proceed to functionary validation — otherwise it could appear in
	// both the Passed and Rejected lists.
	if statement.Statement.PredicateType != attestation.CollectionType && statement.Statement.PredicateType != attestation.LegacyCollectionType {
		log.Debugf("policy: rejecting collection ref=%s: predicateType=%q (expected %q or %q), payload len=%d, errors=%v",
			statement.Reference, statement.Statement.PredicateType, attestation.CollectionType, attestation.LegacyCollectionType, len(statement.Envelope.Payload), statement.Errors)
		return statement, &RejectedCollection{Collection: compactRejected(statement), Reason: fmt.Errorf("predicate type %v is not a collection predicate type", statement.Statement.PredicateType)}
	}

	if len(statement.Verifiers) == 0 {
		// No verifiers means the envelope's signature(s) failed to verify
		// upstream (source.VerifiedSource records the cause in Errors). Carry
		// those underlying errors into the rejection Reason so a typed
		// diagnostic — e.g. dsse.TrustNameKeyMismatchError wrapped in
		// ErrNoMatchingSigs — survives errors.As at the top-level CLI error
		// instead of being flattened to the bare "no verifiers present" text.
		reason := fmt.Errorf("no verifiers present to validate against collection verifiers")
		if len(statement.Errors) > 0 {
			reason = errors.Join(reason, errors.Join(statement.Errors...))
		}
		return statement, &RejectedCollection{Collection: compactRejected(statement), Reason: reason}
	}

	for _, verifier := range statement.Verifiers {
		for _, functionary := range step.Functionaries {
			if err := functionary.Validate(verifier, trustBundles); err != nil {
				statement.Warnings = append(statement.Warnings, fmt.Sprintf("failed to validate functionary of KeyID %s in step %s: %s", functionary.PublicKeyID, step.Name, err.Error()))
				continue
			} else {
				statement.ValidFunctionaries = append(statement.ValidFunctionaries, verifier)
			}
		}
	}

	if reason := step.triageTrustedCollection(statement); reason != nil {
		return statement, &RejectedCollection{Collection: compactRejected(statement), Reason: reason}
	}
	return statement, nil
}

// verifyArtifacts will check the artifacts (materials+products) of the step referred to by `ArtifactsFrom` against the
// materials of the original step.  This ensures file integrity between each step.
//
// v0.3: the artifactsFrom chain is verified entirely from the Merkle leaves
// inlined in (and signed by) each collection envelope. There is no off-envelope
// chain sidecar — inline leaves are the sole trust path, and a leaf-less
// collection with no inline materials fails closed.
func (p Policy) verifyArtifacts(ctx context.Context, vo *verifyOptions, resultsByStep map[string]StepResult) (map[string]StepResult, error) { //nolint:gocognit
	// Deterministic step order (#7572 read, design §10.6). This loop CLEARS
	// result.Passed for a step whose artifacts fail, and a step whose
	// artifactsFrom edge points at a cleared step reads a DIFFERENT upstream
	// depending on which of the two was processed first: with the upstream
	// intact it compares digests and can be accepted, after the clear it fails
	// with "has no passed collections". Ranging a Go map therefore made
	// FAIL-path step_results differ from run to run on the same corpus — a
	// downstream step could be recorded as passed on one run and rejected on
	// the next. Verdicts were never affected (the AND over Analyze() forces
	// FAIL either way, because the step that failed its own artifacts is
	// always cleared), but the recorded content was not reproducible.
	//
	// The order comes from sortedStepNames — a name sort, not topologicalSort;
	// see that function for why.
	stepNames := p.sortedStepNames()

	// Steps that arrived with nothing to check. Recorded ONCE, before the fixed
	// point, so the "no passed collections present" message stays reserved for
	// evidence that was never there — a step the fixed point CLEARS below gets
	// the richer "failed to verify artifacts: <reasons>" rejection instead, and
	// never both.
	for _, stepName := range stepNames {
		step := p.Steps[stepName]
		if len(resultsByStep[step.Name].Passed) > 0 {
			continue
		}
		result, ok := resultsByStep[step.Name]
		if !ok {
			return nil, fmt.Errorf("failed to find step %s in step results map", step.Name)
		}
		result.Rejected = append(result.Rejected, RejectedCollection{Reason: fmt.Errorf("failed to verify artifacts for step %s: no passed collections present", step.Name)})
		resultsByStep[step.Name] = result
	}

	p.convergeArtifactPruning(ctx, vo, stepNames, resultsByStep)

	return resultsByStep, nil
}

// sortedStepNames returns the step-map keys in a total, stable order.
//
// A NAME SORT, deliberately, not topologicalSort. topologicalSort orders by
// AttestationsFrom, while the edge that governs artifact verification is
// artifactsFrom — which is NOT cycle-checked (the DFS walks only
// AttestationsFrom), so a mutually-referencing artifactsFrom pair is legal
// today and has no topological order at all.
//
// What this order protects is REASON determinism, and that needs only SOME
// fixed total order, not a dependency-correct one: the artifact fixed point
// converges the passed/rejected classification regardless of order, but the
// recorded rejection TEXT differs depending on whether a step was judged before
// or after its provider was cleared. A sort over the step-map keys is total,
// always defined, and cheaper than a topological walk.
//
// (topologicalSort was also unstable until #7958 gave it name tie-breaks; that
// was a second reason and is now moot. The reason above is the one that
// survives. TestVerifyArtifacts_TopologicalSortIsStable pins the #7958 fix.)
//
// Keys, not Step.Name: keys are unique by construction, so the order has no
// ties.
func (p Policy) sortedStepNames() []string {
	stepNames := make([]string, 0, len(p.Steps))
	for name := range p.Steps {
		stepNames = append(stepNames, name)
	}
	sort.Strings(stepNames)
	return stepNames
}

// convergeArtifactPruning runs pruneInvalidArtifactCollections over
// resultsByStep until nothing reclassifies, MUTATING it in place.
//
// This is the single definition of "which collections survive artifact
// verification", and it has exactly two callers on purpose: verifyArtifacts,
// which computes the final verdict, and allStepsSatisfied, which decides
// whether the depth loop may stop early. Those two MUST agree — a predicate
// that settles on a view the verdict is about to prune stops the search on
// evidence that is about to be discarded, manufacturing a false FAIL when a
// later depth held a legitimate replacement. Sharing the convergence rather
// than mirroring its logic makes that drift unrepresentable.
//
// Termination: Passed sets only ever shrink (nothing re-populates them), so
// each pass that changes anything permanently removes at least one COLLECTION.
// The total number of passed collections is therefore the upper bound on
// reaching the fixed point, and the cap makes that structural — a
// mutually-referencing artifactsFrom pair can never spin. The +1 pays for the
// final pass that observes no change.
func (p Policy) convergeArtifactPruning(ctx context.Context, vo *verifyOptions, stepNames []string, resultsByStep map[string]StepResult) {
	totalPassed := 0
	for _, stepName := range stepNames {
		totalPassed += len(resultsByStep[p.Steps[stepName].Name].Passed)
	}

	for i := 0; i <= totalPassed; i++ {
		if !p.pruneInvalidArtifactCollections(ctx, vo, stepNames, resultsByStep) {
			return
		}
	}
}

// cloneStepResults copies the map and the Passed/Rejected slices of each entry
// so a caller can run the pruning convergence speculatively without touching
// the real results. The slices are re-allocated rather than shared: the
// convergence appends to Rejected, and append into a shared backing array would
// scribble past the original's length.
//
// The collections themselves are shared — the convergence never mutates a
// collection, only which of them a step holds.
func cloneStepResults(src map[string]StepResult) map[string]StepResult {
	out := make(map[string]StepResult, len(src))
	for name, r := range src {
		clone := r
		clone.Passed = append([]PassedCollection(nil), r.Passed...)
		clone.Rejected = append([]RejectedCollection(nil), r.Rejected...)
		out[name] = clone
	}
	return out
}

// pruneInvalidArtifactCollections runs ONE pass of verifyArtifacts' fixed point
// and reports whether it reclassified anything.
//
// It MUTATES resultsByStep, and verifyCollectionArtifacts reads the Passed sets
// of the steps named in artifactsFrom, which is what makes a single pass
// unsound in two distinct ways:
//
//   - STEP ordering. A consumer visited before its provider validates against
//     the provider's still-populated evidence, is accepted, and then stays
//     accepted after the provider is rejected — recorded evidence whose
//     provenance chain is broken. Sorting the steps made that reproducible but
//     not correct: it merely fixed WHICH policies lose, namely every one whose
//     lexical order opposes its artifactsFrom order. Only re-running to
//     convergence removes the order dependence from the outcome.
//
//   - SIBLING collections. Judging a step as a whole is fail-open for its own
//     siblings: one valid collection would keep the step accepted while the
//     invalid ones rode along inside Passed, where a downstream artifactsFrom
//     edge could match against them and satisfy itself off a collection whose
//     own chain is broken — and because the step's classification never
//     changed, the fixed point would never revisit it. So each collection is
//     judged on its own and individually-invalid ones leave Passed even when a
//     sibling keeps the step accepted. Downstream edges therefore only ever see
//     surviving collections.
//
// The caller's name sort fixes the order WITHIN a pass, which is what keeps the
// recorded reason text reproducible (the outcome converges either way, but the
// reason a collection was rejected does not).
func (p Policy) pruneInvalidArtifactCollections(ctx context.Context, vo *verifyOptions, stepNames []string, resultsByStep map[string]StepResult) bool {
	changed := false

	for _, stepName := range stepNames {
		// step.Name (not stepName) stays the lookup key, exactly as the
		// original map-range form did.
		step := p.Steps[stepName]
		result := resultsByStep[step.Name]

		// Already settled: an empty Passed set cannot recover, and its
		// rejection is already recorded.
		if len(result.Passed) == 0 {
			continue
		}

		surviving := make([]PassedCollection, 0, len(result.Passed))
		perCollection := []RejectedCollection{}
		reasons := []error{}
		for _, collection := range result.Passed {
			err := verifyCollectionArtifacts(ctx, vo, step, collection, resultsByStep)
			if err == nil {
				surviving = append(surviving, collection)
				continue
			}
			reasons = append(reasons, err)
			perCollection = append(perCollection, RejectedCollection{
				Collection: compactRejected(collection.Collection),
				Reason:     fmt.Errorf("failed to verify artifacts for step %s: %w", step.Name, err),
			})
		}

		if len(surviving) == len(result.Passed) {
			continue
		}

		// can't address the map fields directly so have to make a copy and overwrite
		if len(surviving) > 0 {
			// The step stands on its remaining evidence; only the invalid
			// collections are pruned, each recorded with its own reason.
			result.Passed = surviving
			result.Rejected = append(result.Rejected, perCollection...)
		} else {
			// Nothing survives. Keep the aggregate step-level rejection this
			// function has always produced in that case, rather than N
			// per-collection entries, so the message consumers already parse
			// is unchanged.
			reject := RejectedCollection{Reason: fmt.Errorf("failed to verify artifacts for step %s: ", step.Name)}
			for _, reason := range reasons {
				reject.Reason = errors.Join(reject.Reason, reason)
			}
			result.Rejected = append(result.Rejected, reject)
			result.Passed = []PassedCollection{}
		}

		resultsByStep[step.Name] = result
		changed = true
	}

	return changed
}

func verifyCollectionArtifacts(_ context.Context, vo *verifyOptions, step Step, passedCollection PassedCollection, collectionsByStep map[string]StepResult) error { //nolint:gocognit,gocyclo // inline-leaf chain compare shares a reason-tracking trail across the artifactsFrom loop; splitting obscures the failure-reason trail
	reasons := []string{}
	collection := passedCollection.Collection
	// Rehydrate the downstream collection's typed attestors from the retained
	// raw signed payload (gate-time compaction dropped the decoded bodies).
	// Uncompacted collections come back as stored. Fail CLOSED on a
	// rehydration error: an artifact chain that cannot re-read its own signed
	// materials must not pass.
	downstream, err := passedCollection.hydratedCollection()
	if err != nil {
		return ErrVerifyArtifactsFailed{Reasons: []string{err.Error()}}
	}
	// Verify + cap the downstream collection's inline leaves BEFORE rehydrating
	// its materials map. For v0.3 inline predicates the materials are
	// attacker-supplied until the leaves reconstruct to the signed root, and the
	// MaxLeaves cap inside VerifyInlineLeaves must fire before any O(N)
	// allocation (Materials() builds an N-entry map). Doing it once up-front also
	// guarantees compareArtifacts only ever runs on signed-root-consistent data.
	if err := downstream.VerifyInlineLeaves(); err != nil {
		reasons = append(reasons, fmt.Sprintf("step %s inline leaves: %v", step.Name, err))
		return ErrVerifyArtifactsFailed{Reasons: reasons}
	}
	mats := downstream.Materials()
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
			// Inline-leaves path (v0.3 — the ONLY trust path; the off-envelope
			// chain sidecar was removed). The upstream products and downstream
			// materials are rehydrated from Merkle leaves embedded in — and
			// signed by — each collection envelope, so the artifactsFrom chain
			// verifies entirely from the signed predicate. Before trusting that
			// rehydrated data we confirm the leaves reconstruct to their signed
			// roots: the signature covers the leaves, but this guards against a
			// signer (or bug) committing a root that doesn't match the leaves,
			// which would otherwise let the chain compare run on attacker-chosen
			// data.
			upstream, uerr := testCollection.hydratedCollection()
			if uerr != nil {
				collection.Warnings = append(collection.Warnings, fmt.Sprintf("upstream step %s for step %s: %v", artifactsFrom, step.Name, uerr))
				reasons = append(reasons, fmt.Sprintf("upstream step %s: %v", artifactsFrom, uerr))
				continue
			}
			if err := upstream.VerifyInlineLeaves(); err != nil {
				collection.Warnings = append(collection.Warnings, fmt.Sprintf("upstream step %s inline leaves for step %s: %v", artifactsFrom, step.Name, err))
				reasons = append(reasons, fmt.Sprintf("upstream step %s inline leaves: %v", artifactsFrom, err))
				continue
			}

			// Vacuous-pass defense (CVE class for v0.3): compareArtifacts matches
			// by path, so an EMPTY downstream materials map passes trivially. With
			// the chain sidecar gone, inline leaves are the SOLE trust path, so we
			// fail closed UNCONDITIONALLY when the collection is leaf-less — i.e.
			// its empty Materials() is merely unknown rather than an authoritative
			// signed commitment. A collection that inlines its material leaves
			// (even an empty set) has committed, via the signed predicate, that it
			// consumed nothing; that is a verified fact, not a bypass, so it
			// satisfies the chain without any flag. This lets an isolated-workingdir
			// build step (which records no materials) verify while a leaf-less
			// attestation always fails closed.
			if len(mats) == 0 && !downstream.HasInlineMaterials() {
				reasons = append(reasons, fmt.Sprintf("step %s carries no verified chain: the collection is leaf-less (no inline material leaves), so its empty material set is unverified and cannot satisfy artifactsFrom %s", step.Name, artifactsFrom))
				continue
			}

			arts := upstream.Artifacts()
			if err := compareArtifacts(mats, arts); err != nil {
				collection.Warnings = append(collection.Warnings, fmt.Sprintf("failed to verify artifacts for step %s: %v", step.Name, err))
				reasons = append(reasons, err.Error())
				continue
			}

			// Strict-mode (opt-in, default OFF — see WithRequireAllArtifacts):
			// fail closed if the upstream step produced an artifact the
			// downstream step does not consume as a material. compareArtifacts
			// only logs these (warn) for backward compatibility; under strict
			// mode an unconsumed/extra artifact is a hard chain-of-custody
			// failure (potential supply-chain injection).
			if vo != nil && vo.requireAllArtifacts {
				if extra := extraArtifacts(mats, arts); len(extra) > 0 {
					err := ErrUnconsumedArtifacts{Step: step.Name, ArtifactsFrom: artifactsFrom, Paths: extra}
					collection.Warnings = append(collection.Warnings, err.Error())
					reasons = append(reasons, err.Error())
					continue
				}
			}

			accepted = append(accepted, testCollection.Collection)
		}

		if len(accepted) <= 0 {
			return ErrVerifyArtifactsFailed{Reasons: reasons}
		}
	}

	return nil
}

// The empty-collection diagnostic (diagnoseEmptyCollectionResult and its
// bounded source probe) lives in diagnose.go.

func compareArtifacts(mats map[string]cryptoutil.DigestSet, arts map[string]cryptoutil.DigestSet) error {
	overlap := 0
	for path, mat := range mats {
		art, ok := arts[path]
		if !ok {
			continue
		}

		overlap++
		if !mat.Equal(art) {
			return ErrMismatchArtifact{
				Artifact: art,
				Material: mat,
				Path:     path,
			}
		}
	}

	// An artifactsFrom edge means the downstream materials came from the
	// upstream artifacts. If the step consumed materials but none of them came
	// from the referenced step (zero shared paths), nothing actually flowed
	// between the steps and the comparison would otherwise pass vacuously, so
	// reject it (GHSA-vmvj-p3hw-39q3).
	//
	// An empty material set is intentionally NOT rejected here: a leaf-less
	// (unknown) empty set is already rejected by the caller before this point,
	// so an empty set reaching compareArtifacts is an authoritative, signed
	// "consumed nothing" claim that legitimately satisfies the chain.
	if len(mats) > 0 && overlap == 0 {
		return ErrNoArtifactOverlap{}
	}

	// Warn about artifacts that appear in the producing step but not in the
	// consuming step's materials. Extra artifacts could indicate supply chain
	// injection — a file added to a step's output that nobody downstream
	// checks. We log rather than error here to avoid breaking existing
	// deployments; strict-mode enforcement (fail-closed) is opt-in at the
	// caller via WithRequireAllArtifacts (see verifyCollectionArtifacts).
	for _, path := range extraArtifacts(mats, arts) {
		log.Debugf("artifact %q present in producing step but not consumed as material by the verifying step", path)
	}

	return nil
}

// extraArtifacts returns the sorted paths present in the producing step's
// artifacts (arts) but absent from the consuming step's materials (mats) —
// i.e. artifacts produced upstream that nothing downstream consumes. Sorted
// output keeps error messages and logs deterministic.
func extraArtifacts(mats map[string]cryptoutil.DigestSet, arts map[string]cryptoutil.DigestSet) []string {
	var extra []string
	for path := range arts {
		if _, ok := mats[path]; !ok {
			extra = append(extra, path)
		}
	}
	sort.Strings(extra)
	return extra
}
