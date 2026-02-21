// Package slsa is a compatibility shim mapping go-witness slsa to rookery.
package slsa

import (
	rookery "github.com/aflock-ai/rookery/attestation/slsa"
)

// Types
type VerificationResult = rookery.VerificationResult
type Verifier = rookery.Verifier
type ResourceDescriptor = rookery.ResourceDescriptor
type VerificationSummary = rookery.VerificationSummary

// Constants
const (
	VerificationSummaryPredicate = rookery.VerificationSummaryPredicate
	PassedVerificationResult     = rookery.PassedVerificationResult
	FailedVerificationResult     = rookery.FailedVerificationResult
)
