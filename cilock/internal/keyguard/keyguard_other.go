//go:build !linux

// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package keyguard

// protect is a no-op on platforms without the Linux process-hardening
// primitives (e.g. macOS developer machines, which do not produce trusted
// provenance). Applied stays false so a verifier never mistakes an unprotected
// dev run for a hardened one.
func protect() State {
	return State{
		Applied:         false,
		Dumpable:        true,
		YamaPtraceScope: -1,
		Note:            "memory-hardening unsupported on this platform (non-Linux)",
	}
}
