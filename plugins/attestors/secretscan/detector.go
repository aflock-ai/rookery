// Copyright 2025 The Witness Contributors
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

package secretscan

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/pelletier/go-toml/v2"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// initGitleaksDetector creates and configures a Gitleaks detector
// It supports either:
// 1. Loading a custom configuration from a TOML file via configPath, or
// 2. Using default configuration with optional allowlist settings
func (a *Attestor) initGitleaksDetector() (*detect.Detector, error) {
	var detector *detect.Detector
	var err error

	if a.configPath != "" {
		detector, err = a.loadCustomGitleaksConfig()
	} else {
		detector, err = a.createDefaultGitleaksConfig()
	}

	if err != nil {
		return nil, err
	}

	// Apply file size limit configuration regardless of config source
	if detector != nil && a.maxFileSizeMB > 0 {
		detector.MaxTargetMegaBytes = a.maxFileSizeMB
	}

	return detector, nil
}

// loadCustomGitleaksConfig creates a detector using a custom TOML configuration file
func (a *Attestor) loadCustomGitleaksConfig() (*detect.Detector, error) {
	log.Debugf("(attestation/secretscan) loading gitleaks configuration from: %s", a.configPath)

	// gitleaks's config.ViperConfig is just a TOML-tagged struct — the
	// "Viper" name is historical. Decode it directly with pelletier/go-toml/v2
	// to avoid pulling viper (+ fsnotify + afero + mapstructure + locafero
	// + cast + pflag, ~16 transitive packages) for a single Unmarshal call.
	data, err := os.ReadFile(a.configPath) //nolint:gosec // G304: path is operator-supplied secretscan config
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("gitleaks config file not found at %s: %w", a.configPath, err)
		}
		return nil, fmt.Errorf("error reading gitleaks config file %s: %w", a.configPath, err)
	}

	viperConfig, err := decodeGitleaksConfig(a.configPath, data)
	if err != nil {
		return nil, err
	}
	wantRules, err := checkExtendChain(&viperConfig, a.configPath)
	if err != nil {
		return nil, fmt.Errorf("gitleaks config %s: %w", a.configPath, err)
	}

	// Convert ViperConfig to Gitleaks internal config.Config format
	cfg, err := viperConfig.Translate()
	if err != nil {
		return nil, fmt.Errorf("error translating gitleaks config from %s: %w", a.configPath, err)
	}
	if err := dropInheritedPathExceptions(&cfg); err != nil {
		return nil, fmt.Errorf("gitleaks config %s: %w", a.configPath, err)
	}

	// A config with no rules scans for nothing and reports a clean run: an
	// empty or allowlist-only file, or an [extend] that gitleaks silently
	// stopped merging (it stops on the third extending load in a process).
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("gitleaks config %s loads no rules, so it would scan for nothing; add [[rules]] or [extend] useDefault = true", a.configPath)
	}
	if missing := missingRules(wantRules, cfg.Rules); len(missing) > 0 {
		return nil, fmt.Errorf("gitleaks config %s: rules its [extend] chain defines did not load (gitleaks stops extending after its second extending load in one process), refusing to scan for less than the config says: %s", a.configPath, strings.Join(missing, ", "))
	}

	// Create detector using the loaded config
	detector := detect.NewDetector(cfg)
	log.Infof("(attestation/secretscan) using custom gitleaks config from %s (command-line allowlists ignored)", a.configPath)

	return detector, nil
}

// checkExtend refuses an [extend] section that cannot do what it says. It runs
// before Translate, which is where gitleaks would otherwise drop it silently:
// disabledRules applies only while extending another config and only to that
// config's rules, and url is not implemented at all.
func checkExtend(ext config.Extend) error {
	if ext.URL != "" {
		return fmt.Errorf("[extend].url is not implemented by gitleaks and would extend nothing; use path or useDefault")
	}
	if len(ext.DisabledRules) == 0 {
		return nil
	}
	if !ext.UseDefault && ext.Path == "" {
		return fmt.Errorf("[extend].disabledRules only disables rules of an extended config; set useDefault or path, or delete the rule from this file")
	}
	for _, id := range ext.DisabledRules {
		if strings.HasPrefix(id, "witness-env-value-") || strings.HasPrefix(id, "witness-encoded-env-value-") {
			return fmt.Errorf("[extend].disabledRules names %q, cilock's environment-value check, which no gitleaks config can disable; if that variable's value is not a secret, pass --env-allow-sensitive-key with its name", id)
		}
	}
	return nil
}

// decodeGitleaksConfig decodes one gitleaks config file strictly and checks
// its [extend] section. Every file that reaches the detector goes through it,
// the one cilock is given and each file that one extends: a lenient decode
// drops any key the struct does not carry, and a dropped allowlist key is an
// exception that reads as reviewed and exempts something else. A misspelled
// regexes in an "AND" entry leaves a path-only exception.
func decodeGitleaksConfig(path string, data []byte) (config.ViperConfig, error) {
	var vc config.ViperConfig
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vc); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			keys := make([]string, 0, len(strict.Errors))
			for _, e := range strict.Errors {
				keys = append(keys, strings.Join(e.Key(), "."))
			}
			return config.ViperConfig{}, fmt.Errorf("gitleaks config %s has keys gitleaks does not read, refusing rather than ignoring them: %s", path, strings.Join(keys, ", "))
		}
		return config.ViperConfig{}, fmt.Errorf("error unmarshaling gitleaks config from %s: %w", path, err)
	}
	if err := checkExtend(vc.Extend); err != nil {
		return config.ViperConfig{}, fmt.Errorf("gitleaks config %s: %w", path, err)
	}
	return vc, nil
}

// maxExtendHops is how many [extend] hops gitleaks follows from the config it
// is given (config/config.go maxExtendDepth). The file at the last hop is
// read, but its own [extend] is ignored without a word.
const maxExtendHops = 2

// checkExtendChain walks the files the config extends, transitively, and
// holds each to the config's own rules (decodeGitleaksConfig). gitleaks reads
// them itself, with viper, after cilock is done, so a file cilock did not
// check is one the detector trusts unchecked. It returns the ID of every rule
// the chain defines and does not disable, which must all load.
//
// The chain may not leave the files the operator named: a relative path in
// the config resolves beside it (gitleaks would resolve it against the working
// directory, the pushed repository), and a relative path further down, which
// cilock cannot rewrite, is refused. It may not be longer than gitleaks
// follows, nor loop, and every file in it must be one viper reads as TOML.
// An extended file's targetRules are refused: gitleaks applies them only in
// the config it is given, so below it they exempt nothing.
func checkExtendChain(main *config.ViperConfig, configPath string) (map[string]struct{}, error) {
	c := &extendChain{configPath: configPath, want: map[string]struct{}{}, disabled: map[string]struct{}{}, seen: map[string]bool{}}
	c.addRules(main)
	self, err := canonicalConfigPath(configPath)
	if err != nil {
		return nil, err
	}
	c.seen[self] = true
	cur, curPath := main, configPath
	for hop := 1; cur.Extend.UseDefault || cur.Extend.Path != ""; hop++ {
		next, nextPath, err := c.follow(cur, curPath, hop)
		if err != nil {
			return nil, err
		}
		if next == nil {
			break
		}
		cur, curPath = next, nextPath
	}
	return c.want, nil
}

// extendChain is checkExtendChain's walk: the rule IDs the chain must load,
// the IDs an extending file disabled for everything below it, and the files
// already read, by real path.
type extendChain struct {
	configPath string
	want       map[string]struct{}
	disabled   map[string]struct{}
	seen       map[string]bool
}

func (c *extendChain) addRules(vc *config.ViperConfig) {
	for _, r := range vc.Rules {
		if _, off := c.disabled[r.ID]; !off {
			c.want[r.ID] = struct{}{}
		}
	}
}

// follow checks the [extend] of cur, the file at hop-1, and reads the file it
// extends. It returns nil when that is gitleaks' built-in config, which
// extends nothing further.
func (c *extendChain) follow(cur *config.ViperConfig, curPath string, hop int) (*config.ViperConfig, string, error) {
	ext := &cur.Extend
	if hop > maxExtendHops {
		return nil, "", fmt.Errorf("%s extends further, but gitleaks follows at most %d [extend] levels and would ignore that without a word; fold it into a file gitleaks reads", curPath, maxExtendHops)
	}
	if ext.UseDefault && ext.Path != "" {
		return nil, "", fmt.Errorf("%s sets both [extend].path and [extend].useDefault, which gitleaks refuses", curPath)
	}
	// An extending file's disabledRules apply to every rule it extends,
	// however deep.
	for _, id := range ext.DisabledRules {
		c.disabled[id] = struct{}{}
	}
	if ext.UseDefault {
		var def config.ViperConfig
		if err := toml.Unmarshal([]byte(config.DefaultConfig), &def); err != nil {
			return nil, "", fmt.Errorf("decoding gitleaks' built-in config: %w", err)
		}
		c.addRules(&def)
		return nil, "", nil
	}
	next, err := c.resolve(ext, curPath, hop)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(next) //nolint:gosec // G304: path is named by the operator-supplied secretscan config
	if err != nil {
		return nil, "", fmt.Errorf("reading [extend].path %s: %w", next, err)
	}
	vc, err := decodeGitleaksConfig(next, data)
	if err != nil {
		return nil, "", fmt.Errorf("[extend].path: %w", err)
	}
	if err := refuseTargetRules(&vc, next); err != nil {
		return nil, "", err
	}
	c.addRules(&vc)
	return &vc, next, nil
}

// resolve makes ext.Path absolute where cilock may (in the config it was
// given, beside that config) and refuses it where it may not, and refuses a
// file viper would not read as TOML or one already in the chain.
func (c *extendChain) resolve(ext *config.Extend, curPath string, hop int) (string, error) {
	if !filepath.IsAbs(ext.Path) {
		if hop > 1 {
			return "", fmt.Errorf("[extend].path %s extends the relative path %q, which gitleaks resolves against the scanned repository; make it absolute", curPath, ext.Path)
		}
		abs, err := filepath.Abs(filepath.Join(filepath.Dir(c.configPath), ext.Path))
		if err != nil {
			return "", fmt.Errorf("resolving [extend].path %q: %w", ext.Path, err)
		}
		ext.Path = abs
	}
	next := ext.Path
	if filepath.Ext(next) != ".toml" {
		return "", fmt.Errorf("[extend].path %s is not a TOML gitleaks config cilock can check: gitleaks picks the format by the extension, and only .toml is TOML", next)
	}
	canon, err := canonicalConfigPath(next)
	if err != nil {
		return "", err
	}
	if c.seen[canon] {
		return "", fmt.Errorf("[extend].path %s is already in this config's extend chain, a cycle gitleaks cuts off without a word", next)
	}
	c.seen[canon] = true
	return next, nil
}

// canonicalConfigPath names a config file by its real path, so a symlink or a
// "../" spelling cannot hide a cycle.
func canonicalConfigPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", p, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("reading [extend].path %s: %w", p, err)
	}
	return resolved, nil
}

// refuseTargetRules refuses an extended file's targeted allowlists. gitleaks
// attaches targetRules entries to their rules only in the config it was given
// (config/config.go, Translate, currentExtendDepth == 0) and drops them below.
func refuseTargetRules(vc *config.ViperConfig, path string) error {
	lists := slices.Clone(vc.Allowlists)
	if vc.AllowList != nil {
		lists = append(lists, vc.AllowList)
	}
	for _, a := range lists {
		if a != nil && len(a.TargetRules) > 0 {
			return fmt.Errorf("[extend].path %s has an allowlist with targetRules %v, which gitleaks applies only in the config cilock is given and drops here; move that entry into %s's extending config", path, a.TargetRules, filepath.Base(path))
		}
	}
	return nil
}

// missingRules lists, sorted, each rule ID in want that cfg does not carry.
func missingRules(want map[string]struct{}, rules map[string]config.Rule) []string {
	var out []string
	for id := range want {
		if _, ok := rules[id]; !ok {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// dropInheritedPathExceptions removes every path exception whose pattern is,
// word for word, one gitleaks ships: in the linked release's default config,
// in the default config at every v8 tag and every master commit that touched
// config/gitleaks.toml, in the example configs of gitleaks' README.md, or in
// any other .toml file in the gitleaks tree, its own repo-root .gitleaks.toml
// and its test and example configs (gitleaks_path_patterns.go). Those are any
// path containing "gitleaks.toml", node_modules, lockfiles, vendored trees,
// an @octokit README for two rules, the README's unanchored
// (.*?)(jpg|gif|doc), go\.mod and go\.sum, and the repo config's unanchored
// testdata and .*test\.go. Whoever pushes a file chooses its name, and the
// operator did not write those patterns. They reach a config by useDefault,
// by an [extend].path to a vendored copy, or by copying the built-in config,
// a README example or a gitleaks repo config outright; each keeps them
// verbatim, anywhere in any entry, so they are matched by text, not by
// position. An operator who wrote one of those texts on purpose loses it too:
// the scan fails closed. The built-in regexes and stopwords judge the secret
// itself and are kept, as is every path the operator wrote.
//
// Under useDefault gitleaks appends the built-in global allowlists after the
// config's own and puts each built-in rule's allowlists first (config/config.go,
// extend). A different layout is refused, not guessed at: it is also what
// gitleaks produces when it silently stops extending on the third load in a
// process. The config is left unchanged unless every check passes.
func dropInheritedPathExceptions(cfg *config.Config) error {
	builtin, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return fmt.Errorf("loading gitleaks' built-in config: %w", err)
	}
	def := builtin.Config
	if cfg.Extend.UseDefault {
		if err := checkDefaultMerged(cfg, def); err != nil {
			return err
		}
	}
	builtinPaths := builtinPathPatterns(def)
	var dropped int
	cfg.Allowlists = withoutBuiltinPaths(cfg.Allowlists, builtinPaths, &dropped)
	for id, rule := range cfg.Rules {
		rule.Allowlists = withoutBuiltinPaths(rule.Allowlists, builtinPaths, &dropped)
		cfg.Rules[id] = rule
	}
	if dropped > 0 {
		log.Infof("(attestation/secretscan) %d path exceptions from gitleaks' built-in config are not applied; only this config's own paths exempt a file", dropped)
	}
	return nil
}

// checkDefaultMerged verifies that useDefault merged gitleaks' built-in
// allowlists where gitleaks puts them.
func checkDefaultMerged(cfg *config.Config, def config.Config) error {
	own := len(cfg.Allowlists) - len(def.Allowlists)
	if own < 0 || !sameAllowlists(cfg.Allowlists[own:], def.Allowlists) {
		return errors.New("[extend].useDefault did not merge gitleaks' built-in allowlists where cilock expects them (gitleaks stops extending after its second load in one process); refusing rather than guessing which path exceptions this config wrote")
	}
	for id, rule := range def.Rules {
		merged, ok := cfg.Rules[id]
		if !ok || slices.Contains(cfg.Extend.DisabledRules, id) {
			continue
		}
		n := len(rule.Allowlists)
		if len(merged.Allowlists) < n || !sameAllowlists(merged.Allowlists[:n], rule.Allowlists) {
			return fmt.Errorf("rule %q does not start with gitleaks' built-in allowlists; refusing rather than guessing which path exceptions this config wrote", id)
		}
	}
	return nil
}

// builtinPathPatterns returns the text of every path pattern gitleaks ships:
// the linked release's built-in allowlists, global and per rule, plus
// gitleaks_path_patterns.go, which holds the default config's at every v8 tag
// and every master commit that touched config/gitleaks.toml, the example
// configs' in README.md at every v8 tag and every master commit that touched
// it, and every other .toml file's in the gitleaks tree at every v8 tag and
// every master commit that touched one. Operators vendor .gitleaks.toml from
// whatever release or snapshot they had, and a copy from v8.18 or v8.21
// carries path texts the linked release no longer ships.
func builtinPathPatterns(def config.Config) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range gitleaksReleasedPathPatterns {
		out[p] = struct{}{}
	}
	add := func(lists []*config.Allowlist) {
		for _, a := range lists {
			for _, p := range a.Paths {
				out[p.String()] = struct{}{}
			}
		}
	}
	add(def.Allowlists)
	for _, rule := range def.Rules {
		add(rule.Allowlists)
	}
	return out
}

// withoutBuiltinPaths returns the allowlists minus the path patterns found in
// builtin, counting each pattern removed. gitleaks makes each non-empty check
// of an "AND" entry one conjunct (detect/detect.go, checkFindingAllowed), so
// an "AND" entry left with paths of its own keeps a narrower path conjunct and
// is rebuilt with every other check it had; one whose paths were all built-in
// would lose its path conjunct and exempt everywhere, so it is dropped whole.
// An entry is rebuilt, not edited: Validate has already compiled Paths into a
// pattern that PathAllowed prefers (config/allowlist.go), so clearing the
// field would exempt by path still. A rebuilt entry left with no check at all
// fails Validate and is dropped.
func withoutBuiltinPaths(lists []*config.Allowlist, builtin map[string]struct{}, dropped *int) []*config.Allowlist {
	out := make([]*config.Allowlist, 0, len(lists))
	for _, a := range lists {
		var own []*regexp.Regexp
		for _, p := range a.Paths {
			if _, ok := builtin[p.String()]; ok {
				*dropped++
				continue
			}
			own = append(own, p)
		}
		if len(own) == len(a.Paths) {
			out = append(out, a)
			continue
		}
		if a.MatchCondition == config.AllowlistMatchAnd && len(own) == 0 {
			continue
		}
		kept := &config.Allowlist{
			Description:    a.Description,
			MatchCondition: a.MatchCondition,
			Commits:        a.Commits,
			Paths:          own,
			RegexTarget:    a.RegexTarget,
			Regexes:        a.Regexes,
			StopWords:      a.StopWords,
		}
		if kept.Validate() == nil {
			out = append(out, kept)
		}
	}
	return out
}

func sameAllowlists(got, want []*config.Allowlist) bool {
	return slices.EqualFunc(got, want, func(a, b *config.Allowlist) bool {
		return a.Description == b.Description &&
			a.MatchCondition == b.MatchCondition &&
			a.RegexTarget == b.RegexTarget &&
			slices.Equal(patterns(a.Paths), patterns(b.Paths)) &&
			slices.Equal(patterns(a.Regexes), patterns(b.Regexes)) &&
			slices.Equal(slices.Sorted(slices.Values(a.Commits)), slices.Sorted(slices.Values(b.Commits))) &&
			slices.Equal(slices.Sorted(slices.Values(a.StopWords)), slices.Sorted(slices.Values(b.StopWords)))
	})
}

func patterns(rs []*regexp.Regexp) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.String()
	}
	return out
}

// createDefaultGitleaksConfig creates a detector with default configuration
// and applies allowlist settings if provided
func (a *Attestor) createDefaultGitleaksConfig() (*detect.Detector, error) {
	log.Debugf("(attestation/secretscan) using default gitleaks configuration")

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating default gitleaks detector: %w", err)
	}

	// Apply manual allowlists if provided
	if a.allowList != nil {
		if err := a.mergeAllowlistIntoGitleaksConfig(detector); err != nil {
			log.Warnf("(attestation/secretscan) error merging allowlist: %s", err)
			// Continue even if there was an error merging allowlists
		}
	}

	return detector, nil
}

// mergeAllowlistIntoGitleaksConfig applies the attestor's allowlist settings to the detector
// This is only used when no custom config file is provided
func (a *Attestor) mergeAllowlistIntoGitleaksConfig(detector *detect.Detector) error {
	// Validate and compile the content regexes
	validatedPatterns, err := a.compileRegexes(a.allowList.Regexes)
	if err != nil {
		return fmt.Errorf("error validating allowlist regexes: %w", err)
	}

	allowList := &config.Allowlist{
		Description: "rookery secretscan allowlist",
	}

	// Add compiled regexes to the allowlist
	for patternStr, compiled := range validatedPatterns {
		allowList.Regexes = append(allowList.Regexes, compiled)
		log.Debugf("(attestation/secretscan) added allowlist regex: %s", patternStr)
	}

	// Add stop words to the allowlist
	allowList.StopWords = append(allowList.StopWords, a.allowList.StopWords...)
	for _, stopWord := range a.allowList.StopWords {
		log.Debugf("(attestation/secretscan) added allowlist stop word: %s", stopWord)
	}

	// Compile and add path patterns to the allowlist
	for _, path := range a.allowList.Paths {
		compiledPath, err := regexp.Compile(path)
		if err != nil {
			return fmt.Errorf("invalid allowlist path pattern %q: %w", path, err)
		}
		allowList.Paths = append(allowList.Paths, compiledPath)
		log.Debugf("(attestation/secretscan) added allowlist path: %s", path)
	}

	detector.Config.Allowlists = append(detector.Config.Allowlists, allowList)
	return nil
}

// compileRegexes validates and compiles a list of regex patterns
// It returns a map of pattern string to compiled pattern object
func (a *Attestor) compileRegexes(patterns []string) (map[string]*regexp.Regexp, error) {
	result := make(map[string]*regexp.Regexp)
	for _, pattern := range patterns {
		compiledRegex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
		result[pattern] = compiledRegex
	}
	return result, nil
}
