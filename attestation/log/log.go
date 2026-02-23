// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"fmt"
	"sync"
)

// logMu protects the global log variable so that concurrent reads (from
// attestor goroutines) and writes (from SetLogger) are safe.  Without this
// synchronization, a data race on the Logger interface value can cause panics
// because Go interface values are two machine words (type + data pointer) and
// a torn read of a half-updated interface triggers nil-pointer dereferences.
var (
	logMu sync.RWMutex
	log   Logger = SilentLogger{}
)

// logger returns the currently active Logger. All package-level log functions
// must call this instead of reading the bare global variable directly.
func logger() Logger {
	logMu.RLock()
	l := log
	logMu.RUnlock()
	return l
}

// Logger is used by attestation library code to print out relevant information at runtime.
type Logger interface {
	Errorf(format string, args ...interface{})
	Error(args ...interface{})
	Warnf(format string, args ...interface{})
	Warn(args ...interface{})
	Debugf(format string, args ...interface{})
	Debug(args ...interface{})
	Infof(format string, args ...interface{})
	Info(args ...interface{})
}

// SetLogger will set the Logger instance that all attestation library code will use as logging output.
// The default is a SilentLogger that will output nothing.
// SetLogger is safe for concurrent use.
func SetLogger(l Logger) {
	logMu.Lock()
	log = l
	logMu.Unlock()
}

// GetLogger returns the Logger instance currently being used by attestation library code.
func GetLogger() Logger {
	return logger()
}

func Errorf(format string, args ...interface{}) {
	err := fmt.Errorf(format, args...)
	logger().Error(err)
}

func Error(args ...interface{}) {
	logger().Error(args...)
}

func Warnf(format string, args ...interface{}) {
	l := logger()
	// We want to wrap the error if there is one.
	for _, a := range args {
		if _, ok := a.(error); ok {
			err := fmt.Errorf(format, args...)
			l.Warn(err)
			return
		}
	}

	l.Warnf(format, args...)
}

func Warn(args ...interface{}) {
	logger().Warn(args...)
}

func Debugf(format string, args ...interface{}) {
	l := logger()
	for _, a := range args {
		if _, ok := a.(error); ok {
			err := fmt.Errorf(format, args...)
			l.Debug(err)
			return
		}
	}

	l.Debugf(format, args...)
}

func Debug(args ...interface{}) {
	logger().Debug(args...)
}

func Infof(format string, args ...interface{}) {
	logger().Infof(format, args...)
}

func Info(args ...interface{}) {
	logger().Info(args...)
}
