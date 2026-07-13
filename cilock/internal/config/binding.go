// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package config

import (
	"strings"
	"sync"
)

// ResolvedProductBinding is the tenant + product the run-entry gate resolved
// server-side for the current process, threaded to the platform attestor so an
// ambient-CI run can sign concrete testifysec-product/tenant subjects instead of
// deferring resolution to upload time. It is deliberately NOT persisted: the
// binding is refreshed per run from a freshly-minted login-audience token (a
// persisted marker id must never be treated as authority).
type ResolvedProductBinding struct {
	PlatformURL string
	TenantID    string
	TenantName  string
	ProductID   string
	ProductName string
}

var (
	resolvedBinding   *ResolvedProductBinding
	resolvedBindingMu sync.RWMutex
)

// MarkResolvedBinding records the tenant/product the run-entry gate resolved for
// platformURL this process. The platform attestor's ambient branch reads it (via
// ResolvedBinding) to emit concrete subjects. Stored normalized so the attestor
// can compare it to the URL it is about to bind. Passing an empty PlatformURL
// clears it (used by test cleanup).
func MarkResolvedBinding(b ResolvedProductBinding) {
	resolvedBindingMu.Lock()
	defer resolvedBindingMu.Unlock()
	if strings.TrimSpace(b.PlatformURL) == "" {
		resolvedBinding = nil
		return
	}
	b.PlatformURL = strings.TrimRight(strings.TrimSpace(b.PlatformURL), "/")
	resolvedBinding = &b
}

// ResolvedBinding reports the tenant/product the run-entry gate resolved for
// platformURL, and whether one was set this process for THAT url. A binding
// recorded for a different url does not match (fail-closed): the attestor must
// not emit a binding the gate did not authorize for the url it is binding.
func ResolvedBinding(platformURL string) (ResolvedProductBinding, bool) {
	resolvedBindingMu.RLock()
	defer resolvedBindingMu.RUnlock()
	if resolvedBinding == nil {
		return ResolvedProductBinding{}, false
	}
	want := strings.TrimRight(strings.TrimSpace(platformURL), "/")
	if resolvedBinding.PlatformURL != want {
		return ResolvedProductBinding{}, false
	}
	return *resolvedBinding, true
}
