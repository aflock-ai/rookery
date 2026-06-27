// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import "errors"

// ErrUnpinnable signals a resolve produced a credential whose source cannot
// persist a trust-on-first-use pin (does not declare CapCanPinTrust). The
// discovery-trust adoption gate uses it to fail closed instead of silently
// re-adopting an un-pinned bundle (the jctl gap in GHSA #5988 / #6014).
var ErrUnpinnable = errors.New("credential source cannot pin trust (un-pinnable session)")

// CapabilityError reports that a required capability was not declared by the
// source that resolved a credential. A trust branch returns it when it demands a
// capability the resolved source lacks.
type CapabilityError struct {
	Source string
	Want   Capability
}

func (e *CapabilityError) Error() string {
	return "credential from source " + e.Source + " does not declare required capability " + string(e.Want)
}
