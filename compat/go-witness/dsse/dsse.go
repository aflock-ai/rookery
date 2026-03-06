// Package dsse is a compatibility shim mapping go-witness dsse to rookery.
package dsse

import (
	rookery "github.com/aflock-ai/rookery/attestation/dsse"
)

// Types
type Envelope = rookery.Envelope
type Signature = rookery.Signature
type SignatureTimestampType = rookery.SignatureTimestampType
type SignatureTimestamp = rookery.SignatureTimestamp
type SignOption = rookery.SignOption
type VerificationOption = rookery.VerificationOption
type CheckedVerifier = rookery.CheckedVerifier
type ErrNoSignatures = rookery.ErrNoSignatures
type ErrNoMatchingSigs = rookery.ErrNoMatchingSigs
type ErrThresholdNotMet = rookery.ErrThresholdNotMet
type ErrInvalidThreshold = rookery.ErrInvalidThreshold

// Constants
const (
	PemTypeCertificate = rookery.PemTypeCertificate
	TimestampRFC3161   = rookery.TimestampRFC3161
)

// Functions
var Sign = rookery.Sign
var SignWithSigners = rookery.SignWithSigners
var SignWithTimestampers = rookery.SignWithTimestampers
var VerifyWithRoots = rookery.VerifyWithRoots
var VerifyWithIntermediates = rookery.VerifyWithIntermediates
var VerifyWithVerifiers = rookery.VerifyWithVerifiers
var VerifyWithThreshold = rookery.VerifyWithThreshold
var VerifyWithTimestampVerifiers = rookery.VerifyWithTimestampVerifiers
