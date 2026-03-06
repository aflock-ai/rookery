// Package attestation is a compatibility shim mapping go-witness attestation to rookery.
package attestation

import (
	rookery "github.com/aflock-ai/rookery/attestation"
)

// Types
type RunType = rookery.RunType
type AttestationContextOption = rookery.AttestationContextOption
type AttestationContext = rookery.AttestationContext
type CompletedAttestor = rookery.CompletedAttestor
type Product = rookery.Product
type Collection = rookery.Collection
type CollectionAttestation = rookery.CollectionAttestation
type ErrAttestor = rookery.ErrAttestor
type ErrAttestationNotFound = rookery.ErrAttestationNotFound
type ErrAttestorNotFound = rookery.ErrAttestorNotFound

// Interfaces
type Attestor = rookery.Attestor
type Subjecter = rookery.Subjecter
type Materialer = rookery.Materialer
type Producer = rookery.Producer
type Exporter = rookery.Exporter
type MultiExporter = rookery.MultiExporter
type BackReffer = rookery.BackReffer
type EnvironmentCapturer = rookery.EnvironmentCapturer

// Constants
const (
	CollectionType       = rookery.CollectionType
	LegacyCollectionType = rookery.LegacyCollectionType
	PreMaterialRunType   = rookery.PreMaterialRunType
	MaterialRunType      = rookery.MaterialRunType
	ExecuteRunType       = rookery.ExecuteRunType
	ProductRunType       = rookery.ProductRunType
	PostProductRunType   = rookery.PostProductRunType
	VerifyRunType        = rookery.VerifyRunType
)

// Functions
var NewContext = rookery.NewContext
var NewCollection = rookery.NewCollection
var NewCollectionAttestation = rookery.NewCollectionAttestation

// Context options
var WithContext = rookery.WithContext
var WithHashes = rookery.WithHashes
var WithWorkingDir = rookery.WithWorkingDir
var WithDirHashGlob = rookery.WithDirHashGlob
var WithEnvironmentCapturer = rookery.WithEnvironmentCapturer
var WithOutputWriters = rookery.WithOutputWriters
var WithEnvFilterVarsEnabled = rookery.WithEnvFilterVarsEnabled
var WithEnvAdditionalKeys = rookery.WithEnvAdditionalKeys
var WithEnvExcludeKeys = rookery.WithEnvExcludeKeys
var WithEnvDisableDefaultSensitiveList = rookery.WithEnvDisableDefaultSensitiveList

// Factory functions
var RegisterAttestation = rookery.RegisterAttestation
var RegisterAttestationWithTypes = rookery.RegisterAttestationWithTypes
var FactoryByType = rookery.FactoryByType
var FactoryByName = rookery.FactoryByName
var GetAttestor = rookery.GetAttestor
var Attestors = rookery.Attestors
var GetAttestors = rookery.GetAttestors
var AttestorOptions = rookery.AttestorOptions
var RegistrationEntries = rookery.RegistrationEntries
var RegisterLegacyAlias = rookery.RegisterLegacyAlias
var RegisterLegacyAliases = rookery.RegisterLegacyAliases
var ResolveLegacyType = rookery.ResolveLegacyType
var DefaultSensitiveEnvList = rookery.DefaultSensitiveEnvList

// RawAttestation type for unregistered attestor types
type RawAttestation = rookery.RawAttestation
