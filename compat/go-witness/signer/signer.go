// Package signer is a compatibility shim mapping go-witness signer to rookery.
package signer

import (
	rookery "github.com/aflock-ai/rookery/attestation/signer"
)

// Interfaces
type SignerProvider = rookery.SignerProvider
type VerifierProvider = rookery.VerifierProvider

// Functions
var Register = rookery.Register
var RegistryEntries = rookery.RegistryEntries
var NewSignerProvider = rookery.NewSignerProvider
var RegisterVerifier = rookery.RegisterVerifier
var VerifierRegistryEntries = rookery.VerifierRegistryEntries
var NewVerifierProvider = rookery.NewVerifierProvider
