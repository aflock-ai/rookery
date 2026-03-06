// Package policysig is a compatibility shim mapping go-witness policysig to rookery.
package policysig

import (
	rookery "github.com/aflock-ai/rookery/attestation/policysig"
)

// Types
type VerifyPolicySignatureOptions = rookery.VerifyPolicySignatureOptions
type Option = rookery.Option

// Functions
var VerifyWithPolicyVerifiers = rookery.VerifyWithPolicyVerifiers
var VerifyWithPolicyTimestampAuthorities = rookery.VerifyWithPolicyTimestampAuthorities
var VerifyWithPolicyCARoots = rookery.VerifyWithPolicyCARoots
var VerifyWithPolicyCAIntermediates = rookery.VerifyWithPolicyCAIntermediates
var NewVerifyPolicySignatureOptions = rookery.NewVerifyPolicySignatureOptions
var VerifyWithPolicyFulcioCertExtensions = rookery.VerifyWithPolicyFulcioCertExtensions
var VerifyWithPolicyCertConstraints = rookery.VerifyWithPolicyCertConstraints
var VerifyPolicySignature = rookery.VerifyPolicySignature
