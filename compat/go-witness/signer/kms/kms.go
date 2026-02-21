// Package kms is a compatibility shim mapping go-witness signer/kms to rookery.
package kms

import (
	rookery "github.com/aflock-ai/rookery/attestation/signer/kms"
)

// Types
type KMSSignerProvider = rookery.KMSSignerProvider
type Option = rookery.Option
type ProviderInit = rookery.ProviderInit
type ProviderNotFoundError = rookery.ProviderNotFoundError

// Interfaces
type KMSClientOptions = rookery.KMSClientOptions

// Functions
var New = rookery.New
var WithRef = rookery.WithRef
var WithHash = rookery.WithHash
var WithKeyVersion = rookery.WithKeyVersion
var AddProvider = rookery.AddProvider
var SupportedProviders = rookery.SupportedProviders
var ProviderOptions = rookery.ProviderOptions
