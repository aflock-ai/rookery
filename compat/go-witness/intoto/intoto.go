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
	StatementType   = rookery.StatementType
	StatementTypeV1 = rookery.StatementTypeV1
	PayloadType     = rookery.PayloadType
)

// Functions
var NewStatement = rookery.NewStatement
var NewStatementV1 = rookery.NewStatementV1
var IsStatementType = rookery.IsStatementType
var DigestSetToSubject = rookery.DigestSetToSubject
