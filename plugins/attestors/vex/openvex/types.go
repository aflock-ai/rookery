// Inlined from github.com/openvex/go-vex at commit
// 3185a64ed27703fc3fe4af8cd5e1ce0ed2fa2569 (tag v0.2.7).
//
// Upstream source files this file derives from:
//   pkg/vex/vex.go            (VEX, Metadata)
//   pkg/vex/statement.go      (Statement)
//   pkg/vex/vulnerability.go  (Vulnerability, VulnerabilityID)
//   pkg/vex/product.go        (Product, Subcomponent, IdentifierType, Algorithm, Hash + constants)
//   pkg/vex/component.go      (Component)
//   pkg/vex/status.go         (Status + constants)
//   pkg/vex/justification.go  (Justification + constants)
//
// Only the type definitions and constants the rookery vex attestor
// transitively requires (via encoding/json) are inlined here. None of
// the upstream methods (Validate, Matches, Builder, MarshalJSON timestamp
// normalization, etc.) are reproduced — the attestor doesn't call them.
//
// All upstream code is licensed under Apache-2.0, the same as rookery.
// See .provenance/openvex-types.json for the verifiable record and
// NOTICE.md for the attribution surface.
//
// Original copyright notice from go-vex (preserved per Apache-2.0):
//   Copyright 2023 The OpenVEX Authors
//   SPDX-License-Identifier: Apache-2.0

// Package openvex provides the OpenVEX type definitions used by the vex
// attestor. The types are byte-compatible with the OpenVEX 0.2.0 JSON
// shape, so any document produced by an upstream go-vex consumer decodes
// here cleanly via encoding/json.
package openvex

import (
	"encoding/json"
	"time"
)

// VEX is a VEX document and all of its contained information.
type VEX struct {
	Metadata
	Statements []Statement `json:"statements"`
}

// Metadata holds the document-level fields of an OpenVEX document.
type Metadata struct {
	// Context is the URL pointing to the jsonld context definition.
	Context string `json:"@context"`

	// ID is the identifying string for the VEX document. Should be unique per
	// document.
	ID string `json:"@id"`

	// Author is the identifier for the author of the VEX statement.
	Author string `json:"author"`

	// AuthorRole describes the role of the document Author.
	AuthorRole string `json:"role,omitempty"`

	// Timestamp defines the time at which the document was issued.
	Timestamp *time.Time `json:"timestamp"`

	// LastUpdated marks the time when the document had its last update.
	LastUpdated *time.Time `json:"last_updated,omitempty"`

	// Version is the document version. Incremented when any content within
	// the VEX document changes.
	Version int `json:"version"`

	// Tooling expresses how the VEX document and contained VEX statements
	// were generated. Optional.
	Tooling string `json:"tooling,omitempty"`

	// Supplier is an optional field.
	Supplier string `json:"supplier,omitempty"`
}

// Statement is a declaration conveying a single Status for a single
// vulnerability for one or more products.
type Statement struct {
	// ID is an optional identifier for the statement.
	ID string `json:"@id,omitempty"`

	Vulnerability Vulnerability `json:"vulnerability,omitempty"`

	// Timestamp is the time at which the information expressed in the
	// Statement was known to be true.
	Timestamp *time.Time `json:"timestamp,omitempty"`

	// LastUpdated records the time when the statement last had a modification.
	LastUpdated *time.Time `json:"last_updated,omitempty"`

	Products []Product `json:"products,omitempty"`

	Status Status `json:"status"`

	StatusNotes string `json:"status_notes,omitempty"`

	Justification Justification `json:"justification,omitempty"`

	ImpactStatement string `json:"impact_statement,omitempty"`

	ActionStatement          string     `json:"action_statement,omitempty"`
	ActionStatementTimestamp *time.Time `json:"action_statement_timestamp,omitempty"`
}

// Vulnerability captures a vulnerability identifier and its aliases.
type Vulnerability struct {
	ID          string            `json:"@id,omitempty"`
	Name        VulnerabilityID   `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Aliases     []VulnerabilityID `json:"aliases,omitempty"`
}

// VulnerabilityID is a free-form string identifying a vulnerability,
// typically a CVE / GSD / vendor ID.
type VulnerabilityID string

// Product is software identified by IRI, hashes, and/or other identifiers.
type Product struct {
	Component
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

// Subcomponent is a nested entry within a Product. Cannot itself nest.
type Subcomponent struct {
	Component
}

// Component is the common construct shared by Product and Subcomponent.
type Component struct {
	// ID is an IRI identifying the component.
	ID string `json:"@id,omitempty"`

	// Hashes is a map of cryptographic hashes identifying the component.
	Hashes map[Algorithm]Hash `json:"hashes,omitempty"`

	// Identifiers is a list of software identifiers (purl, cpe22, cpe23, …).
	Identifiers map[IdentifierType]string `json:"identifiers,omitempty"`

	// Supplier is an optional machine-readable identifier for the supplier.
	Supplier string `json:"supplier,omitempty"`
}

// IdentifierType enumerates the kinds of software identifier strings.
type IdentifierType string

const (
	PURL  IdentifierType = "purl"
	CPE22 IdentifierType = "cpe22"
	CPE23 IdentifierType = "cpe23"
)

// Algorithm is the name of a cryptographic hash algorithm.
type Algorithm string

// Hash is a hash value.
type Hash string

// Algorithm constants — mirror the OpenVEX 0.2.0 set.
const (
	MD5        Algorithm = "md5"
	SHA1       Algorithm = "sha1"
	SHA256     Algorithm = "sha-256"
	SHA384     Algorithm = "sha-384"
	SHA512     Algorithm = "sha-512"
	SHA3224    Algorithm = "sha3-224"
	SHA3256    Algorithm = "sha3-256"
	SHA3384    Algorithm = "sha3-384"
	SHA3512    Algorithm = "sha3-512"
	BLAKE2S256 Algorithm = "blake2s-256"
	BLAKE2B256 Algorithm = "blake2b-256"
	BLAKE2B512 Algorithm = "blake2b-512"
	BLAKE3     Algorithm = "blake3"
)

// Status describes the exploitability status of a component for a
// vulnerability.
type Status string

const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// Justification describes why a given component is not affected by a
// vulnerability.
type Justification string

const (
	ComponentNotPresent                         Justification = "component_not_present"
	VulnerableCodeNotPresent                    Justification = "vulnerable_code_not_present"
	VulnerableCodeNotInExecutePath              Justification = "vulnerable_code_not_in_execute_path"
	VulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	InlineMitigationsAlreadyExist               Justification = "inline_mitigations_already_exist"
)

// TypeURI is the type used to describe VEX documents in in-toto statements.
const TypeURI = "https://openvex.dev/ns"

// MarshalJSON mirrors the OpenVEX wire format: timestamps are normalized to
// UTC RFC3339 (no nanoseconds) and emitted *after* the statements array,
// preserving byte-compatibility with documents produced by upstream go-vex.
//
// Ported from github.com/openvex/go-vex pkg/vex/vex.go at commit
// 3185a64ed27703fc3fe4af8cd5e1ce0ed2fa2569 (Apache-2.0). Same logic,
// trimmed to the fields rookery actually uses.
func (vexDoc *VEX) MarshalJSON() (data []byte, err error) {
	type alias VEX
	var ts, lu string

	if vexDoc.Timestamp != nil {
		ts = vexDoc.Timestamp.UTC().Format(time.RFC3339)
	}
	if vexDoc.LastUpdated != nil {
		lu = vexDoc.LastUpdated.UTC().Format(time.RFC3339)
	}

	return json.Marshal(&struct {
		*alias
		TimeZonedTimestamp   string `json:"timestamp"`
		TimeZonedLastUpdated string `json:"last_updated,omitempty"`
	}{
		alias:                (*alias)(vexDoc),
		TimeZonedTimestamp:   ts,
		TimeZonedLastUpdated: lu,
	})
}
