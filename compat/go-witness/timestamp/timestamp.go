// Package timestamp is a compatibility shim mapping go-witness timestamp to rookery.
package timestamp

import (
	rookery "github.com/aflock-ai/rookery/attestation/timestamp"
)

// Types
type TSPTimestamper = rookery.TSPTimestamper
type TSPTimestamperOption = rookery.TSPTimestamperOption
type TSPVerifier = rookery.TSPVerifier
type TSPVerifierOption = rookery.TSPVerifierOption
type FakeTimestamper = rookery.FakeTimestamper

// Interfaces
type TimestampVerifier = rookery.TimestampVerifier
type Timestamper = rookery.Timestamper

// Functions
var NewTimestamper = rookery.NewTimestamper
var TimestampWithUrl = rookery.TimestampWithUrl
var TimestampWithHash = rookery.TimestampWithHash
var TimestampWithRequestCertificate = rookery.TimestampWithRequestCertificate
var NewVerifier = rookery.NewVerifier
var VerifyWithCerts = rookery.VerifyWithCerts
var VerifyWithHash = rookery.VerifyWithHash
