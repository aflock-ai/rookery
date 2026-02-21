// Package witness is a compatibility shim that maps go-witness imports to rookery.
//
// This allows unmodified go-witness plugins to compile against rookery
// by aliasing all exported types, functions, and constants to their
// rookery equivalents. Type aliases preserve Go type identity, so
// a go-witness plugin's init() registers into rookery's registry.
//
// Usage: add a replace directive in your build module:
//
//	replace github.com/in-toto/go-witness => <path>/compat/go-witness
package witness

import (
	"github.com/aflock-ai/rookery/attestation/workflow"
)

// Types
type RunOption = workflow.RunOption
type RunResult = workflow.RunResult
type VerifyOption = workflow.VerifyOption
type VerifyResult = workflow.VerifyResult

// Functions — root go-witness package maps to workflow
var Run = workflow.Run
var RunWithExports = workflow.RunWithExports
var Sign = workflow.Sign
var Verify = workflow.Verify
var VerifySignature = workflow.VerifySignature

// RunOption constructors
var RunWithInsecure = workflow.RunWithInsecure
var RunWithIgnoreErrors = workflow.RunWithIgnoreErrors
var RunWithAttestors = workflow.RunWithAttestors
var RunWithAttestationOpts = workflow.RunWithAttestationOpts
var RunWithTimestampers = workflow.RunWithTimestampers
var RunWithSigners = workflow.RunWithSigners

// VerifyOption constructors
var VerifyWithSigners = workflow.VerifyWithSigners
var VerifyWithSubjectDigests = workflow.VerifyWithSubjectDigests
var VerifyWithCollectionSource = workflow.VerifyWithCollectionSource
var VerifyWithRunOptions = workflow.VerifyWithRunOptions
var VerifyWithPolicyFulcioCertExtensions = workflow.VerifyWithPolicyFulcioCertExtensions
var VerifyWithPolicyCertConstraints = workflow.VerifyWithPolicyCertConstraints
var VerifyWithPolicyTimestampAuthorities = workflow.VerifyWithPolicyTimestampAuthorities
var VerifyWithPolicyCARoots = workflow.VerifyWithPolicyCARoots
var VerifyWithPolicyCAIntermediates = workflow.VerifyWithPolicyCAIntermediates
var VerifyWithAiServerURL = workflow.VerifyWithAiServerURL
var VerifyWithKMSProviderOptions = workflow.VerifyWithKMSProviderOptions
