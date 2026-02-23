// Package source is a compatibility shim mapping go-witness source to rookery.
package source

import (
	rookery "github.com/aflock-ai/rookery/attestation/source"
)

// Types
type CollectionEnvelope = rookery.CollectionEnvelope
type MemorySource = rookery.MemorySource
type MultiSource = rookery.MultiSource
type VerifiedSource = rookery.VerifiedSource
type ArchivistaSource = rookery.ArchivistaSource
type CollectionVerificationResult = rookery.CollectionVerificationResult
type ErrDuplicateReference = rookery.ErrDuplicateReference

// Interfaces
type Sourcer = rookery.Sourcer
type VerifiedSourcer = rookery.VerifiedSourcer

// Functions
var NewMemorySource = rookery.NewMemorySource
var NewMultiSource = rookery.NewMultiSource
var NewVerifiedSource = rookery.NewVerifiedSource
var NewArchivistaSource = rookery.NewArchivistaSource

// NewArchvistSource is the deprecated misspelled alias from go-witness.
// Deprecated: Use NewArchivistaSource.
var NewArchvistSource = rookery.NewArchvistSource
