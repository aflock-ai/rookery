// Copyright 2026 TestifySec, Inc.
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

package alpsevidence

import (
	"sort"
	"strings"
	"sync"

	"github.com/aflock-ai/rookery/attestation"
)

// The credential-shaped-key backstop is DERIVED from
// attestation.DefaultSensitiveEnvList — the same list the environment and
// commandrun attestors obfuscate against — rather than maintained as a private
// word list.
//
// This is a backstop, not the primary control. The primary control is that
// providers request specific keys by name and nothing else is ever read. The
// backstop exists because allowlists are edited by humans: Claude Code exports
// CLAUDE_CODE_MESSAGING_TOKEN alongside CLAUDE_CODE_SESSION_ID, and the two are
// one careless copy-paste apart. The private 10-word list this replaces missed
// exactly the classes the shared list already named — PAT, JWT, BEARER, OAUTH,
// PASSPHRASE — so a provider typo like GH_PAT would have serialized a personal
// access token the sibling attestors know to obfuscate.
//
// Derived, not applied raw: the shared list's globs match SUBSTRINGS (*PAT*
// matches PATH and every *PATH* variable), which is correct for an attestor
// that obfuscates values in place and would be evidence-deleting here, where
// legitimate allowlisted keys are path-shaped (CLAUDE_CODE_EXECPATH). So each
// glob contributes its credential token, matched at WORD granularity below —
// every credential CLASS on the shared list still blocks, while a path-shaped
// key does not trip *PAT*.
type sensitiveKeySets struct {
	// exact holds the list's non-glob entries, matched whole.
	exact map[string]struct{}

	// words holds single-word tokens (KEY, TOKEN, PAT, JWT ...), matched
	// against each separator-delimited word of a name — by prefix, so plural
	// and suffixed forms (CREDENTIALS, TOKENS) stay covered.
	words []string

	// phrases holds multi-word tokens (ACCESS_KEY, SESSION_TOKEN,
	// CONNECTION_STRING ...), matched as substrings of the
	// separator-normalized name so the pair must appear adjacent.
	phrases []string
}

var sensitiveKeyMatcher = sync.OnceValue(func() sensitiveKeySets {
	m := sensitiveKeySets{exact: map[string]struct{}{}}
	for pattern := range attestation.DefaultSensitiveEnvList() {
		upper := normalizeEnvKey(pattern)
		if !strings.Contains(upper, "*") {
			m.exact[upper] = struct{}{}
			continue
		}
		token := strings.Trim(upper, "*")
		if token == "" {
			continue
		}
		if strings.Contains(token, "_") {
			m.phrases = append(m.phrases, token)
		} else {
			m.words = append(m.words, token)
		}
	}
	return m
})

// normalizeEnvKey uppercases a name and folds the separator alphabet to '_',
// so npm-auth-token and service.credentials compare like NPM_AUTH_TOKEN.
func normalizeEnvKey(name string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', '.':
			return '_'
		}
		return r
	}, strings.ToUpper(name))
}

// isCredentialShapedKey reports whether an environment variable name looks like
// it names a credential, per the classes in
// attestation.DefaultSensitiveEnvList.
//
// Matching errs toward dropping — a prefix hit like TOKENIZER or KEYBOARD
// costs a value whose presence is still recorded, while a miss serializes a
// credential into signed, published evidence. A lost observation costs a
// field, a leaked credential costs an incident. The one deliberate narrowing
// against the shared list is word granularity; see sensitiveKeySets.
func isCredentialShapedKey(name string) bool {
	normalized := normalizeEnvKey(name)
	m := sensitiveKeyMatcher()
	if _, ok := m.exact[normalized]; ok {
		return true
	}
	for _, phrase := range m.phrases {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	for _, word := range strings.Split(normalized, "_") {
		for _, token := range m.words {
			if strings.HasPrefix(word, token) {
				return true
			}
		}
	}
	return false
}

// envValueKeepFunc adapts the run-wide attestation.EnvironmentCapturer — the
// filter/obfuscation configuration the operator gave the whole run, which
// commandrun already honors for its per-process environments — into the
// keep/drop question collectEnv asks per retained value.
//
// The capturer answers by transforming a KEY=VALUE list: a key it filters out
// disappears, and a key it obfuscates comes back with its value replaced.
// Either way the original value must not be serialized here, and an obfuscated
// placeholder is no better — this attestor's values feed Observations a policy
// may compare against, and a placeholder masquerading as a model name is a
// wrong claim, not a redacted one. So only a value the capturer passes through
// UNCHANGED is kept, and everything else degrades to presence-only, which is
// this package's standing shape for "real but unpublishable".
//
// A nil capturer imposes nothing: the provider allowlist and the
// credential-shape backstop remain the controls, exactly as before.
func envValueKeepFunc(c attestation.EnvironmentCapturer) func(key, value string) bool {
	if c == nil {
		return nil
	}
	return func(key, value string) bool {
		captured := c.Capture([]string{key + "=" + value})
		got, ok := captured[key]
		return ok && got == value
	}
}

// collectEnv reads the allowlisted keys for one scope and turns them into
// observations.
//
// Only keys whose Scopes include the requested scope are asked for, so a key
// declared readable from cilock's own environment is never requested from the
// agent process and vice versa.
//
// The read bit distinguishes "the environment was read" (true — an absent key
// really was unset) from "the environment could not be read at all" (false —
// a higher-precedence override may be hiding there). A key that was present
// but whose value redaction withheld is recorded separately below and has the
// same resolution effect as an unreadable environment: unknown, never absent.
// envScope is one environment READ: the allowlisted values it returned, and
// whether the read succeeded at all.
//
// The values are unexported and there is no way to index them directly. That
// is the fix for a defect that kept reappearing in a different provider each
// time: `firstNonEmpty(agentEnv[k], selfEnv[k])` reads a LOWER-priority scope
// whenever a higher-priority one came back empty — and an unreadable
// environment is empty. Four providers spelled that out, and all four signed
// cilock's own inherited value as the agent's whenever the agent's environment
// could not be read. With no index expression available, the only way to get a
// value is resolveEnvValue, which knows the difference.
type envScope struct {
	values map[string]string

	// present records every key the process environment carried, including
	// values the run-wide redaction policy refused to retain. Presence and a
	// publishable value are different facts: a redacted higher-precedence
	// value must block resolution rather than masquerade as an absent key and
	// let a lower-precedence config or process scope answer in its place.
	present map[string]struct{}
	read    bool
}

// carries reports whether this captured scope contained key, independently of
// whether its value was empty or withheld by redaction. Callers that have
// lower-precedence, non-environment fallbacks need this distinction because
// resolveEnvValue intentionally returns the carried value verbatim — including
// the empty string.
func (s envScope) carries(key string) bool {
	_, ok := s.present[key]
	return ok
}

// resolveEnvValue returns the value of key from the highest-priority scope that
// carries it.
//
// Scopes are given in DESCENDING priority. A lower-priority scope is consulted
// only when every scope above it was actually READ and did not carry the key:
// an environment that could not be read may hold an override, so nothing below
// it can be trusted to be the answer. blocked reports that case and a carried
// value withheld by redaction — either way the value is unknown rather than
// absent, and callers must publish nothing and say why.
//
// CARRIED decides the fallthrough, not non-emptiness. The scope maps store an
// explicitly empty variable — KEY= — as present-with-"", and an agent that
// cleared a variable for itself has answered the question: the value, for
// that scope, is empty. The `v != ""` guard this replaces read carried-empty
// as not-carried and fell through, so cilock's own inherited value was
// published as the agent's for exactly the runs where the agent had cleared
// it.
func resolveEnvValue(key string, scopes ...envScope) (value string, blocked bool) {
	for _, scope := range scopes {
		if !scope.read {
			return "", true
		}
		if _, carried := scope.present[key]; carried {
			v, retained := scope.values[key]
			if !retained {
				return "", true
			}
			return v, false
		}
	}
	return "", false
}

// collectEnv reads the allowlisted keys from the environment of the process
// the requested scope names: the matched agent for EnvScopeAgent, cilock's own
// process for EnvScopeSelf.
//
// It reads through the CAPTURED ProcessInfo rather than a pid, because the
// instance the read must be bound to is the one the walk observed: re-reading
// the process here first would happily capture whatever program holds the
// number NOW and then validate the environment against that — the exact
// substitution the binding exists to refuse.
//
// Three controls decide whether a value (as opposed to presence) is retained,
// and all three must agree: the provider's allowlist (RecordValue), the
// credential-shape backstop, and the run-wide redaction policy in
// r.EnvValueKeep — the operator's own environment filter configuration, which
// commandrun honors for its traced processes and this attestor honors here.
func collectEnv(r InspectRequest, scope EnvScope, allow []EnvKey) ([]EnvObservation, envScope) {
	src := r.Source
	p := r.Process
	if scope == EnvScopeSelf {
		p = r.Self
	}
	wanted := make([]string, 0, len(allow))
	byName := make(map[string]EnvKey, len(allow))
	for _, key := range allow {
		if !scopeAllows(key, scope) {
			continue
		}
		wanted = append(wanted, key.Name)
		byName[key.Name] = key
	}
	if len(wanted) == 0 {
		return nil, envScope{values: map[string]string{}, present: map[string]struct{}{}, read: true}
	}

	values, err := src.ReadEnvironment(p.instance(), wanted)
	if err != nil {
		return nil, envScope{}
	}
	if len(values) == 0 {
		return nil, envScope{values: map[string]string{}, present: map[string]struct{}{}, read: true}
	}

	names := make([]string, 0, len(values))
	for name := range values {
		if _, requested := byName[name]; requested {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	observations := make([]EnvObservation, 0, len(names))
	resolved := make(map[string]string, len(names))
	present := make(map[string]struct{}, len(names))
	for _, name := range names {
		present[name] = struct{}{}
		key := byName[name]
		obs := EnvObservation{
			Key:       name,
			Present:   true,
			From:      string(scope),
			Assurance: AssuranceEnvironmentObserved,
		}
		if key.RecordValue && !isCredentialShapedKey(name) && (r.EnvValueKeep == nil || r.EnvValueKeep(name, values[name])) {
			obs.Value = values[name]
			resolved[name] = values[name]
		}
		observations = append(observations, obs)
	}
	return observations, envScope{values: resolved, present: present, read: true}
}

func scopeAllows(key EnvKey, scope EnvScope) bool {
	if len(key.Scopes) == 0 {
		return true
	}
	for _, s := range key.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// mergeEnv combines observations from several scopes, keeping order stable.
func mergeEnv(groups ...[]EnvObservation) []EnvObservation {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	if total == 0 {
		return nil
	}
	out := make([]EnvObservation, 0, total)
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}
