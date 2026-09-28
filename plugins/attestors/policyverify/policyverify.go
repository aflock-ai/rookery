// Copyright 2023 The Witness Contributors
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

package policyverify

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "policyverify"
	Type    = slsa.VerificationSummaryPredicate
	RunType = attestation.VerifyRunType
)

var (
	_ attestation.Subjecter = &Attestor{}
	_ attestation.Attestor  = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type Attestor struct {
	*policysig.VerifyPolicySignatureOptions
	slsa.VerificationSummary

	DenyReasons        []DenyReason `json:"denyReasons"`
	stepResults        map[string]policy.StepResult
	policyEnvelope     dsse.Envelope
	collectionSource   source.Sourcer
	subjectDigestSets  []cryptoutil.DigestSet
	aiServerURL        string
	maxSubjectFanout   int
	lazyWitness        bool
	commitBinding      string
	materialManifests  map[string][]byte
	inventoryLookup    func(string) ([]byte, bool)
	kmsProviderOptions map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)
}

type DenyReason struct {
	Reference      string `json:"reference"`
	CollectionName string `json:"collection_name"`
	Message        string `json:"message"`
}

func New() *Attestor {
	return &Attestor{
		VerifyPolicySignatureOptions: policysig.NewVerifyPolicySignatureOptions(),
	}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&a)
}

// PolicyVerifyConfigurer interface methods

func (a *Attestor) SetPolicyEnvelope(env dsse.Envelope) {
	a.policyEnvelope = env
}

func (a *Attestor) SetPolicyVerificationOptions(opts *policysig.VerifyPolicySignatureOptions) {
	a.VerifyPolicySignatureOptions = opts
}

// SetSubjectDigests records the seed subjects PRESERVING each digest's
// declared algorithm (the CLI stores a "sha1:<hex>" --subjects value under
// SHA-1). The policy engine's search consumes them as algorithm:value keys
// via seedDigestStrings; Subjects() re-emits each digest under its true
// algorithm instead of mislabeling everything sha256.
func (a *Attestor) SetSubjectDigests(digests []cryptoutil.DigestSet) {
	a.subjectDigestSets = append(a.subjectDigestSets, digests...)
}

// seedDigestStrings renders the seed subject digests as algorithm:value match
// keys (cryptoutil.SubjectDigestKey). Flattening them to bare values let a
// subject recorded under one algorithm match a seed computed under another
// (#9816). A digest whose algorithm has no wire name is an error. Passing its
// bare value on would let cryptoutil.NormalizeSubjectSeed re-bind it by shape
// (a 64-hex SHA-512 prefix becomes sha256), which is the cross-algorithm match
// this function exists to prevent.
func (a *Attestor) seedDigestStrings() ([]string, error) {
	var out []string
	for _, set := range a.subjectDigestSets {
		keys, err := cryptoutil.DigestSetSubjectKeys(set)
		if err != nil {
			return nil, fmt.Errorf("seed subject digest has no match algorithm: %w", err)
		}
		out = append(out, keys...)
	}
	return out, nil
}

func (a *Attestor) SetCollectionSource(src source.Sourcer) {
	a.collectionSource = src
}

func (a *Attestor) SetAiServerURL(url string) {
	a.aiServerURL = url
}

func (a *Attestor) SetKMSProviderOptions(opts map[string][]func(signer.SignerProvider) (signer.SignerProvider, error)) {
	a.kmsProviderOptions = opts
}

// SetMaxSubjectFanout enables the policy engine's subject fan-out guard for
// this verification (policy.WithMaxSubjectFanout). n <= 0 leaves it off.
func (a *Attestor) SetMaxSubjectFanout(n int) {
	a.maxSubjectFanout = n
}

// SetLazyWitness enables within-step stop-at-first-pass for this verification
// (policy.WithLazyStepSatisfaction — the minimum-witness Phase 1 option).
// DEFAULT OFF; see that option's doc for the soundness argument and the three
// exclusions. Note it is INERT whenever the subject fan-out guard is active,
// which is judge's production default.
func (a *Attestor) SetLazyWitness(enabled bool) {
	a.lazyWitness = enabled
}

// SetCommitBinding binds every step witness to commit
// (policy.WithCommitBinding). Empty is the unbound zero value, for verifies
// whose subject is not a commit.
func (a *Attestor) SetCommitBinding(commit string) {
	a.commitBinding = commit
}

// SetMaterialManifests supplies legacy manifests and modern inventories to
// policy.WithMaterialManifests. Only legacy manifest JSON is normalized.
//
// The caller builds this from envelopes it ALREADY holds; the engine never
// fetches. A collection whose material leaves are inline — today's default —
// never consults it.
func (a *Attestor) SetMaterialManifests(manifests map[string][]byte) {
	a.materialManifests = manifests
}

func (a *Attestor) SetInventoryLookup(lookup func(string) ([]byte, bool)) {
	a.inventoryLookup = lookup
}

// PolicyVerifyResult interface methods

func (a *Attestor) StepResults() map[string]policy.StepResult {
	return a.stepResults
}

func (a *Attestor) GetVerificationSummary() slsa.VerificationSummary {
	return a.VerificationSummary
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := map[string]cryptoutil.DigestSet{}
	for _, set := range a.subjectDigestSets {
		for dv, digest := range set {
			// Each seed digest is emitted under its DECLARED algorithm — a
			// sha1-declared subject must not be recorded as sha256 in the
			// policyverify collection.
			subjects[fmt.Sprintf("artifact:%v", digest)] = cryptoutil.DigestSet{dv: digest}
		}
	}

	subjects[fmt.Sprintf("policy:%v", a.Policy.URI)] = a.Policy.Digest
	return subjects
}

// optionalVerifyOpts returns the verify options that apply only when the
// caller set them. An unset commit binding adds nothing, so the verify stays
// unbound (see policy.WithCommitBinding).
func (a *Attestor) optionalVerifyOpts() []policy.VerifyOption {
	var opts []policy.VerifyOption
	if a.maxSubjectFanout > 0 {
		opts = append(opts, policy.WithMaxSubjectFanout(a.maxSubjectFanout))
	}
	if a.lazyWitness {
		opts = append(opts, policy.WithLazyStepSatisfaction(true))
	}
	if a.commitBinding != "" {
		opts = append(opts, policy.WithCommitBinding(a.commitBinding))
	}
	if len(a.materialManifests) > 0 {
		opts = append(opts, policy.WithMaterialManifests(a.materialManifests))
	}
	return opts
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error { //nolint:funlen,gocyclo // policy verification requires extensive setup
	if err := policysig.VerifyPolicySignature(ctx.Context(), a.policyEnvelope, a.VerifyPolicySignatureOptions); err != nil {
		return fmt.Errorf("failed to verify policy signature: %w", err)
	}

	log.Info("policy signature verified")

	// The shared decoder, never json.Unmarshal: it refuses a policy type this
	// verifier does not know, decodes v0.2 strictly, and stamps the version
	// the engine checks before it honours Step.About.
	pol, err := policy.DecodePolicyEnvelope(a.policyEnvelope.PayloadType, a.policyEnvelope.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode policy from envelope: %w", err)
	}

	pubKeysById, err := pol.PublicKeyVerifiers(a.kmsProviderOptions)
	if err != nil {
		return fmt.Errorf("failed to get public keys from policy: %w", err)
	}

	pubkeys := make([]cryptoutil.Verifier, 0)
	for _, pubkey := range pubKeysById {
		pubkeys = append(pubkeys, pubkey)
	}

	trustBundlesById, err := pol.TrustBundles()
	if err != nil {
		return fmt.Errorf("failed to load policy trust bundles: %w", err)
	}

	roots := make([]*x509.Certificate, 0)
	intermediates := make([]*x509.Certificate, 0)
	for _, trustBundle := range trustBundlesById {
		roots = append(roots, trustBundle.Root)
		intermediates = append(intermediates, trustBundle.Intermediates...)
	}

	timestampAuthoritiesById, err := pol.TimestampAuthorityTrustBundles()
	if err != nil {
		return fmt.Errorf("failed to load policy timestamp authorities: %w", err)
	}

	timestampVerifiers := make([]timestamp.TimestampVerifier, 0)
	for _, timestampAuthority := range timestampAuthoritiesById {
		certs := make([]*x509.Certificate, 0, 1+len(timestampAuthority.Intermediates))
		certs = append(certs, timestampAuthority.Root)
		certs = append(certs, timestampAuthority.Intermediates...)
		timestampVerifiers = append(timestampVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts(certs)))
	}

	// WithEvidenceHashes: the source releases raw payload bytes from results
	// after verification, so it must record their digests (with THIS context's
	// hash set) for the VSA's inputAttestations — the digest is the evidence
	// identity once the bytes are gone.
	verifiedSource := source.NewVerifiedSource(
		a.collectionSource,
		dsse.VerifyWithVerifiers(pubkeys...),
		dsse.VerifyWithRoots(roots...),
		dsse.VerifyWithIntermediates(intermediates...),
		dsse.VerifyWithTimestampVerifiers(timestampVerifiers...),
	).WithEvidenceHashes(ctx.Hashes())

	lookup := a.inventoryLookup
	if lookup == nil {
		lookup = source.InventoryLookup(ctx.Context(), a.collectionSource)
	}
	seeds, err := a.seedDigestStrings()
	if err != nil {
		return err
	}
	verifyOpts := []policy.VerifyOption{
		policy.WithSubjectDigests(seeds),
		policy.WithInventoryLookup(lookup),
	}
	verifyOpts = append(verifyOpts, a.optionalVerifyOpts()...)
	verifyOpts = append(verifyOpts,
		policy.WithVerifiedSource(verifiedSource),
	)
	if a.aiServerURL != "" {
		verifyOpts = append(verifyOpts, policy.WithAiServerURL(a.aiServerURL))
	}

	accepted, stepResults, policyErr := pol.Verify(ctx.Context(), verifyOpts...)
	if policyErr != nil {
		for step, result := range stepResults {
			log.Warnf("Step %s: passed=%v, accepted=%d, rejected=%d",
				step, result.Analyze(), len(result.Passed), len(result.Rejected))
			for _, reject := range result.Rejected {
				log.Warnf("  rejected: %v", reject.Reason)
			}
		}
		return fmt.Errorf("failed to verify policy: %w", policyErr)
	}

	a.stepResults = stepResults

	a.VerificationSummary, err = verificationSummaryFromResults(ctx, a.policyEnvelope, stepResults, accepted)
	if err != nil {
		return fmt.Errorf("failed to generate verification summary: %w", err)
	}

	return nil
}

// evidenceDigest resolves the digest of the exact signed payload bytes a
// result was verified against. VerifiedSource releases raw payload bytes
// from results after verification, recording their digest set first
// (PayloadDigests) — prefer that. A result that still carries its payload
// (a source that does not release bytes) is digested directly, exactly as
// before. Never digest released (nil) bytes: that would record the digest
// of EMPTY input as the identity of real evidence.
func evidenceDigest(ctx *attestation.AttestationContext, ce source.CollectionEnvelope) (cryptoutil.DigestSet, bool) {
	if len(ce.PayloadDigests) > 0 {
		return ce.PayloadDigests, true
	}
	if len(ce.Envelope.Payload) == 0 {
		log.Debugf("skipping evidence descriptor for %s: payload released and no recorded digest", ce.Reference)
		return nil, false
	}
	digest, err := cryptoutil.CalculateDigestSetFromBytes(ce.Envelope.Payload, ctx.Hashes())
	if err != nil {
		log.Debugf("failed to calculate evidence hash: %v", err)
		return nil, false
	}
	return digest, true
}

// vsaPolicyURI is the policy type the VSA names: the signed envelope's own
// PayloadType, so a consumer learns which predicate, and so which step
// semantics, the verdict was reached under. The legacy witness v0.1 type is an
// alias of aflock v0.1 and an envelope with no type predates types; both name
// aflock v0.1, as every VSA did before, so a v0.1 policy's VSA is unchanged.
// Attest writes a VSA only for a policy policy.DecodePolicyEnvelope accepted,
// so in practice the input is one of the three allowlisted types; the other
// arms keep this function total.
func vsaPolicyURI(payloadType string) string {
	if payloadType == "" || payloadType == policy.LegacyPolicyPredicate {
		return policy.PolicyPredicate
	}
	return payloadType
}

func verificationSummaryFromResults(ctx *attestation.AttestationContext, policyEnvelope dsse.Envelope, stepResults map[string]policy.StepResult, accepted bool) (slsa.VerificationSummary, error) {
	inputAttestations := make([]slsa.ResourceDescriptor, 0, len(stepResults))
	for _, step := range stepResults {
		for _, collection := range step.Passed {
			digest, ok := evidenceDigest(ctx, collection.Collection.CollectionEnvelope)
			if !ok {
				continue
			}

			inputAttestations = append(inputAttestations, slsa.ResourceDescriptor{
				URI:    collection.Collection.Reference,
				Digest: digest,
			})
		}

		if !accepted {
			for _, collection := range step.Rejected {
				digest, ok := evidenceDigest(ctx, collection.Collection.CollectionEnvelope)
				if !ok {
					continue
				}

				inputAttestations = append(inputAttestations, slsa.ResourceDescriptor{
					URI:    collection.Collection.Reference,
					Digest: digest,
				})
			}
		}
	}

	policyDigest, err := cryptoutil.CalculateDigestSetFromBytes(policyEnvelope.Payload, ctx.Hashes())
	if err != nil {
		return slsa.VerificationSummary{}, fmt.Errorf("failed to calculate policy digest: %w", err)
	}

	verificationResult := slsa.FailedVerificationResult
	if accepted {
		verificationResult = slsa.PassedVerificationResult
	}

	return slsa.VerificationSummary{
		Verifier: slsa.Verifier{
			ID: "aflock",
		},
		TimeVerified: time.Now(),
		Policy: slsa.ResourceDescriptor{
			URI:    vsaPolicyURI(policyEnvelope.PayloadType),
			Digest: policyDigest,
		},
		InputAttestations:  inputAttestations,
		VerificationResult: verificationResult,
	}, nil
}
