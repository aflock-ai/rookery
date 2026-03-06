// Package log is a compatibility shim mapping go-witness log to rookery.
package log

import (
	rookery "github.com/aflock-ai/rookery/attestation/log"
)

// Types
type SilentLogger = rookery.SilentLogger
type ConsoleLogger = rookery.ConsoleLogger

// Interfaces
type Logger = rookery.Logger

// Functions
var SetLogger = rookery.SetLogger
var GetLogger = rookery.GetLogger
var Errorf = rookery.Errorf
var Error = rookery.Error
var Warnf = rookery.Warnf
var Warn = rookery.Warn
var Debugf = rookery.Debugf
var Debug = rookery.Debug
var Infof = rookery.Infof
var Info = rookery.Info
