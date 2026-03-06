// Package provenance is a compatibility shim mapping go-witness intoto/provenance to rookery.
package provenance

import (
	rookery "github.com/aflock-ai/rookery/attestation/intoto/provenance"
)

// Types
type Provenance = rookery.Provenance
type BuildDefinition = rookery.BuildDefinition
type RunDetails = rookery.RunDetails
type Builder = rookery.Builder
type BuildMetadata = rookery.BuildMetadata
