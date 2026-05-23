// Copyright 2024 The Witness Contributors
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

package environment

import (
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
)

type Capture struct {
	sensitiveVarsList           map[string]struct{}
	addSensitiveVarsList        map[string]struct{}
	excludeSensitiveVarsList    map[string]struct{}
	filterVarsEnabled           bool
	disableSensitiveVarsDefault bool

	// captureAllowExact and captureAllowGlobs implement an OPT-IN positive
	// allowlist for env capture. When EITHER is non-empty the attestor
	// captures only keys matching the allowlist; everything else is dropped
	// (regardless of whether it's on the sensitive list). When BOTH are
	// empty the legacy denylist-based behaviour is preserved.
	//
	// Defense-in-depth: the sensitive-keys filter still runs even when an
	// allowlist is configured. If the allowlist contains a key that's also
	// on the sensitive list, the sensitive filter wins (obfuscate/remove).
	captureAllowExact map[string]struct{}
	captureAllowGlobs []glob.Glob
}

type CaptureOption func(*Capture)

// WithFilterVarsEnabled will make the filter (removing) of vars the acting behavior.
// The default behavior is obfuscation of variables.
func WithFilterVarsEnabled() CaptureOption {
	return func(c *Capture) {
		c.filterVarsEnabled = true
	}
}

// WithAdditionalKeys add additional keys to final list that is checked for sensitive variables.
func WithAdditionalKeys(additionalKeys []string) CaptureOption {
	return func(c *Capture) {
		for _, value := range additionalKeys {
			c.addSensitiveVarsList[value] = struct{}{}
		}
	}
}

// WithExcludeKeys add additional keys to final list that is checked for sensitive variables.
func WithExcludeKeys(excludeKeys []string) CaptureOption {
	return func(c *Capture) {
		for _, value := range excludeKeys {
			c.excludeSensitiveVarsList[value] = struct{}{}
		}
	}
}

// WithDisableDefaultSensitiveList will disable the default list and only use the additional keys.
func WithDisableDefaultSensitiveList() CaptureOption {
	return func(c *Capture) {
		c.disableSensitiveVarsDefault = true
	}
}

// WithCaptureAllowlist switches the attestor into POSITIVE-allowlist mode:
// only env keys matching one of the supplied patterns are captured at all.
// Each pattern is either an exact key (case-insensitive: "PATH",
// "AWS_REGION") or a glob ("GITHUB_*", "CI_*"). Use when committing
// captured envelopes to a public repo — the default denylist still leaks
// host-identifying state (PATH-with-Homebrew-prefix, USER, SHELL,
// validator-installed editor CLIs) that's fine in production but noisy
// in committed validation artifacts.
//
// Defense-in-depth: the sensitive-keys obfuscate/filter pipeline still
// runs. A key on the allowlist that ALSO matches a sensitive pattern
// (e.g. allowlist contains "GITHUB_*" and one of the captured keys is
// "GITHUB_TOKEN") gets the sensitive treatment — the allowlist only
// decides which keys are CONSIDERED for capture; the sensitive filter
// decides what happens to the values.
func WithCaptureAllowlist(patterns []string) CaptureOption {
	return func(c *Capture) {
		if c.captureAllowExact == nil {
			c.captureAllowExact = map[string]struct{}{}
		}
		for _, p := range patterns {
			if strings.Contains(p, "*") || strings.Contains(p, "?") {
				g, err := glob.Compile(strings.ToUpper(p))
				if err != nil {
					log.Errorf("env capture-allowlist glob %q could not be compiled: %v", p, err)
					continue
				}
				c.captureAllowGlobs = append(c.captureAllowGlobs, g)
			} else {
				c.captureAllowExact[strings.ToUpper(p)] = struct{}{}
			}
		}
	}
}

// hasAllowlist reports whether a positive capture allowlist is configured.
func (c *Capture) hasAllowlist() bool {
	return len(c.captureAllowExact) > 0 || len(c.captureAllowGlobs) > 0
}

// allowed reports whether a key passes the positive allowlist. Always
// returns true when no allowlist is configured (legacy behaviour).
func (c *Capture) allowed(key string) bool {
	if !c.hasAllowlist() {
		return true
	}
	upper := strings.ToUpper(key)
	if _, ok := c.captureAllowExact[upper]; ok {
		return true
	}
	for _, g := range c.captureAllowGlobs {
		if matched, _ := safeGlobMatch(g, upper); matched {
			return true
		}
	}
	return false
}

func NewCapturer(opts ...CaptureOption) *Capture {
	capture := &Capture{
		sensitiveVarsList:        attestation.DefaultSensitiveEnvList(),
		addSensitiveVarsList:     map[string]struct{}{},
		excludeSensitiveVarsList: map[string]struct{}{},
	}

	for _, opt := range opts {
		opt(capture)
	}

	return capture
}

func (c *Capture) Capture(env []string) map[string]string {
	variables := make(map[string]string)

	// Build a local copy of the sensitive keys list so that concurrent calls
	// to Capture() don't race on map iteration/write, and repeated calls
	// don't destructively mutate c.sensitiveVarsList (R3-125).
	finalSensitiveKeysList := make(map[string]struct{})
	if !c.disableSensitiveVarsDefault {
		for k, v := range c.sensitiveVarsList {
			finalSensitiveKeysList[k] = v
		}
	}
	for k, v := range c.addSensitiveVarsList {
		finalSensitiveKeysList[k] = v
	}

	// Filter or obfuscate. The onAllowed callback applies the positive
	// allowlist (if configured) on top of the sensitive-keys denylist —
	// keys that aren't on the allowlist are dropped entirely.
	onAllowed := func(key, val, _ string) {
		if !c.allowed(key) {
			return
		}
		variables[key] = val
	}
	if c.filterVarsEnabled {
		FilterEnvironmentArray(env, finalSensitiveKeysList, c.excludeSensitiveVarsList, onAllowed)
	} else {
		ObfuscateEnvironmentArray(env, finalSensitiveKeysList, c.excludeSensitiveVarsList, onAllowed)
	}

	return variables
}

// splitVariable splits a string representing an environment variable in the format of
// "KEY=VAL" and returns the key and val separately.
func splitVariable(v string) (key, val string) {
	parts := strings.SplitN(v, "=", 2)
	key = parts[0]
	if len(parts) > 1 {
		val = parts[1]
	}

	return
}

// NewCapturerFromContext creates a Capture configured from the AttestationContext's env settings.
func NewCapturerFromContext(ctx *attestation.AttestationContext) *Capture {
	var opts []CaptureOption
	if ctx.EnvFilterVarsEnabled() {
		opts = append(opts, WithFilterVarsEnabled())
	}
	if keys := ctx.EnvAdditionalKeys(); len(keys) > 0 {
		opts = append(opts, WithAdditionalKeys(keys))
	}
	if keys := ctx.EnvExcludeKeys(); len(keys) > 0 {
		opts = append(opts, WithExcludeKeys(keys))
	}
	if ctx.EnvDisableDefaultSensitiveList() {
		opts = append(opts, WithDisableDefaultSensitiveList())
	}
	if patterns := ctx.EnvCaptureAllowlist(); len(patterns) > 0 {
		opts = append(opts, WithCaptureAllowlist(patterns))
	}
	return NewCapturer(opts...)
}
