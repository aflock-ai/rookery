// Package intoto is a compatibility shim mapping go-witness intoto to rookery.
package intoto

import (
	rookery "github.com/aflock-ai/rookery/attestation/intoto"
)

// Types
type Subject = rookery.Subject
type Statement = rookery.Statement

// Constants
const (
	StatementType = rookery.StatementType
	PayloadType   = rookery.PayloadType
)

// Functions
var NewStatement = rookery.NewStatement
var DigestSetToSubject = rookery.DigestSetToSubject
