// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package options' resolve.go centralises the override-hierarchy
// rules documented in docs/configuration.md. Every cilock knob is
// resolvable from four layers, in most-specific-wins order:
//
//  1. CLI flag (per-invocation)
//  2. Env var (CILOCK_*)
//  3. Config file (.cilock.yaml / .witness.yaml)
//  4. Built-in default
//
// New flags should consistently route through these helpers so the
// hierarchy is enforced uniformly. Existing flags are NOT being
// retrofitted in this PR — too much churn — but every NEW flag
// added in PR B uses these helpers when applicable.

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
//   - configVal, when non-empty (caller should have already
//     pre-resolved the config-file value via getStringFromConfig
//     or its variant)
//   - defaultVal as the last resort
//
// Callers pass cliChanged from cmd.Flags().Changed("flag-name") so
// the helper can tell "user explicitly passed --foo=<empty>" from
// "user did not pass --foo".
func ResolveString(cliVal string, cliChanged bool, envVar, configVal, defaultVal string) string {
	if cliChanged {
		return cliVal
	}
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			return v
		}
	}
	if configVal != "" {
		return configVal
	}
	return defaultVal
}

// ResolveInt is the integer companion to ResolveString. Env-var and
// config values that fail to parse are SILENTLY ignored — i.e. the
// hierarchy falls through to the next layer. This is deliberate:
//   - typo'd env var → operator gets the default (fail-safe),
//   - garbage config-file value → operator gets the default
//     (config files are user-edited and a stray quote should not
//     OOM the verifier).
//
// Callers that need parse errors to be FATAL should resolve
// themselves and validate inline. Use this helper when the default
// is the safe fallback.
func ResolveInt(cliVal int, cliChanged bool, envVar string, configVal string, defaultVal int) int {
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
	if configVal != "" {
		if n, err := strconv.Atoi(configVal); err == nil {
			return n
		}
	}
	return defaultVal
}

// ResolveDuration mirrors ResolveInt for Go duration strings. Same
// fail-safe semantics: an unparseable env-var or config value falls
// through to the next layer, ending at the default.
func ResolveDuration(cliVal time.Duration, cliChanged bool, envVar, configVal string, defaultVal time.Duration) time.Duration {
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
	if configVal != "" {
		if d, err := time.ParseDuration(configVal); err == nil {
			return d
		}
	}
	return defaultVal
}
