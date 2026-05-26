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
	"crypto"
	"crypto/x509"
	"encoding/json"
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
	subjectDigests     []string
	aiServerURL        string
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

func (a *Attestor) SetSubjectDigests(digests []cryptoutil.DigestSet) {
	for _, set := range digests {
		for _, digest := range set {
			a.subjectDigests = append(a.subjectDigests, digest)
		}
	}
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

// PolicyVerifyResult interface methods

func (a *Attestor) StepResults() map[string]policy.StepResult {
	return a.stepResults
}

func (a *Attestor) GetVerificationSummary() slsa.VerificationSummary {
	return a.VerificationSummary
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := map[string]cryptoutil.DigestSet{}
	for _, digest := range a.subjectDigests {
		subjects[fmt.Sprintf("artifact:%v", digest)] = cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: digest,
		}
	}

	subjects[fmt.Sprintf("policy:%v", a.Policy.URI)] = a.Policy.Digest
	return subjects
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error { //nolint:funlen // policy verification requires extensive setup
	if err := policysig.VerifyPolicySignature(ctx.Context(), a.policyEnvelope, a.VerifyPolicySignatureOptions); err != nil {
		return fmt.Errorf("failed to verify policy signature: %w", err)
	}

	log.Info("policy signature verified")

	pol := policy.Policy{}
	if err := json.Unmarshal(a.policyEnvelope.Payload, &pol); err != nil {
		return fmt.Errorf("failed to unmarshal policy from envelope: %w", err)
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

	verifiedSource := source.NewVerifiedSource(
		a.collectionSource,
		dsse.VerifyWithVerifiers(pubkeys...),
		dsse.VerifyWithRoots(roots...),
		dsse.VerifyWithIntermediates(intermediates...),
		dsse.VerifyWithTimestampVerifiers(timestampVerifiers...),
	)

	verifyOpts := []policy.VerifyOption{
		policy.WithSubjectDigests(a.subjectDigests),
		policy.WithVerifiedSource(verifiedSource),
	}
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

func verificationSummaryFromResults(ctx *attestation.AttestationContext, policyEnvelope dsse.Envelope, stepResults map[string]policy.StepResult, accepted bool) (slsa.VerificationSummary, error) {
	inputAttestations := make([]slsa.ResourceDescriptor, 0, len(stepResults))
	for _, step := range stepResults {
		for _, collection := range step.Passed {
			digest, err := cryptoutil.CalculateDigestSetFromBytes(collection.Collection.Envelope.Payload, ctx.Hashes())
			if err != nil {
				log.Debugf("failed to calculate evidence hash: %v", err)
				continue
			}

			inputAttestations = append(inputAttestations, slsa.ResourceDescriptor{
				URI:    collection.Collection.Reference,
				Digest: digest,
			})
		}

		if !accepted {
			for _, collection := range step.Rejected {
				digest, err := cryptoutil.CalculateDigestSetFromBytes(collection.Collection.Envelope.Payload, ctx.Hashes())
				if err != nil {
					log.Debugf("failed to calculate evidence hash: %v", err)
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
			URI:    policy.PolicyPredicate,
			Digest: policyDigest,
		},
		InputAttestations:  inputAttestations,
		VerificationResult: verificationResult,
	}, nil
}
