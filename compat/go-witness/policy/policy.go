// Package policy is a compatibility shim mapping go-witness policy to rookery.
package policy

import (
	rookery "github.com/aflock-ai/rookery/attestation/policy"
)

// Types
type Policy = rookery.Policy
type Root = rookery.Root
type PublicKey = rookery.PublicKey
type TrustBundle = rookery.TrustBundle
type VerifyOption = rookery.VerifyOption
type Step = rookery.Step
type Functionary = rookery.Functionary
type Attestation = rookery.Attestation
type AiPolicy = rookery.AiPolicy
type RegoPolicy = rookery.RegoPolicy
type StepResult = rookery.StepResult
type PassedCollection = rookery.PassedCollection
type RejectedCollection = rookery.RejectedCollection
type AiResponse = rookery.AiResponse
type CertConstraint = rookery.CertConstraint

// Error types
type ErrVerifyArtifactsFailed = rookery.ErrVerifyArtifactsFailed
type ErrNoCollections = rookery.ErrNoCollections
type ErrMissingAttestation = rookery.ErrMissingAttestation
type ErrPolicyExpired = rookery.ErrPolicyExpired
type ErrKeyIDMismatch = rookery.ErrKeyIDMismatch
type ErrUnknownStep = rookery.ErrUnknownStep
type ErrArtifactCycle = rookery.ErrArtifactCycle
type ErrMismatchArtifact = rookery.ErrMismatchArtifact
type ErrRegoInvalidData = rookery.ErrRegoInvalidData
type ErrPolicyDenied = rookery.ErrPolicyDenied
type ErrConstraintCheckFailed = rookery.ErrConstraintCheckFailed
type ErrInvalidOption = rookery.ErrInvalidOption

// Constants
const (
	PolicyPredicate       = rookery.PolicyPredicate
	LegacyPolicyPredicate = rookery.LegacyPolicyPredicate
	AllowAllConstraint    = rookery.AllowAllConstraint
)

// Functions
var WithVerifiedSource = rookery.WithVerifiedSource
var WithSubjectDigests = rookery.WithSubjectDigests
var WithSearchDepth = rookery.WithSearchDepth
var WithAiServerURL = rookery.WithAiServerURL
var EvaluateRegoPolicy = rookery.EvaluateRegoPolicy
var EvaluateAIPolicy = rookery.EvaluateAIPolicy
var ExecuteAiPolicy = rookery.ExecuteAiPolicy
