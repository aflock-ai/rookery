// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package options' resolve.go centralises the override-hierarchy
// rules documented in docs/configuration.md. Every cilock knob is
// resolvable from three layers, in most-specific-wins order:
//
//  1. CLI flag (per-invocation)
//  2. Env var (CILOCK_*)
//  3. Built-in default
//
// cilock is args-only: there is no config file. New flags should
// consistently route through these helpers so the hierarchy is
// enforced uniformly.

package options

import (
	"os"
	"strconv"
	"time"
)

// ResolveString returns the first non-empty value in the override
// hierarchy:
//   - cliVal if cliChanged is true (operator passed the flag, even
//     if they passed an empty value — empty-but-explicit is still
//     an explicit choice that beats the env-var fallback)
//   - the env var named by envVar, when non-empty
//   - defaultVal as the last resort
//
// Callers pass cliChanged from cmd.Flags().Changed("flag-name") so
// the helper can tell "user explicitly passed --foo=<empty>" from
// "user did not pass --foo".
func ResolveString(cliVal string, cliChanged bool, envVar, defaultVal string) string {
	if cliChanged {
		return cliVal
	}
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			return v
		}
	}
	return defaultVal
}

// ResolveInt is the integer companion to ResolveString. Env-var
// values that fail to parse are SILENTLY ignored — i.e. the
// hierarchy falls through to the default. This is deliberate:
// a typo'd env var means the operator gets the default (fail-safe).
//
// Callers that need parse errors to be FATAL should resolve
// themselves and validate inline. Use this helper when the default
// is the safe fallback.
func ResolveInt(cliVal int, cliChanged bool, envVar string, defaultVal int) int {
	if cliChanged {
		return cliVal
	}
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return defaultVal
}

// ResolveDuration mirrors ResolveInt for Go duration strings. Same
// fail-safe semantics: an unparseable env-var value falls through
// to the default.
func ResolveDuration(cliVal time.Duration, cliChanged bool, envVar string, defaultVal time.Duration) time.Duration {
	if cliChanged {
		return cliVal
	}
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
	}
	return defaultVal
}
