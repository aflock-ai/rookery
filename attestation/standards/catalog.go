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

package standards

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// CatalogSchema is the schema tag every catalog file must carry.
const CatalogSchema = "cilock.standards-catalog/v1"

// Standard identifiers. They are also the JSON keys of Guidance.
const (
	StandardSLSABuild = "slsa_build"
	StandardALPS      = "alps"
)

// Entry statuses. A `planned` step is reported as coming, with its snippet
// and command withheld. A `future` level is named with its requirement and
// never offered as an action; a step may not be `future`.
const (
	StatusAvailable = "available"
	StatusPlanned   = "planned"
	StatusFuture    = "future"
)

// Step contexts: which run shape a step applies to.
const (
	WhenAny   = "any"
	WhenCI    = "ci"
	WhenLocal = "local"
)

// pinPlaceholder is replaced by a step's pin when its snippet is rendered.
const pinPlaceholder = "{{pin}}"

var pinRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// observationNames lists, per standard, the observations a catalog step may
// close. They are the keys of StandardCeiling.Observed.
var observationNames = map[string][]string{
	StandardSLSABuild: {ObsProvenance, ObsHostedRunner, ObsWorkflowSigner, ObsTimestamped, ObsTrustedBuilder},
	StandardALPS:      {ObsSigned, ObsPrincipalIssued, ObsTimestamped, ObsBoundaryByObserver, ObsIsolated},
}

// Catalog is one standard's guidance file.
type Catalog struct {
	Schema   string  `yaml:"schema" json:"schema"`
	Standard string  `yaml:"standard" json:"standard"`
	Title    string  `yaml:"title" json:"title"`
	Spec     string  `yaml:"spec" json:"spec"`
	SpecURL  string  `yaml:"spec_url" json:"spec_url"`
	Levels   []Level `yaml:"levels" json:"levels"`
	Steps    []Step  `yaml:"steps" json:"steps"`
	// Limits name a level that is unreachable on specific CI platforms, with
	// the reason. They are reported, never offered as an action.
	Limits []Limit `yaml:"limits,omitempty" json:"limits,omitempty"`
}

// CI platforms cilock recognizes from the signing leaf's OIDC issuer (or, on
// the run side, the job environment). CINone is a run outside any CI.
const (
	CINone       = "none"
	CIGitHub     = "github"
	CIGitLab     = "gitlab"
	CIBuildkite  = "buildkite"
	CICircleCI   = "circleci"
	CIKubernetes = "kubernetes"
)

var ciPlatforms = []string{CINone, CIGitHub, CIGitLab, CIBuildkite, CICircleCI, CIKubernetes}

// Limit says a level cannot be reached on the listed CI platforms today.
type Limit struct {
	Level    string   `yaml:"level" json:"level"`
	CI       []string `yaml:"ci" json:"ci"`
	Status   string   `yaml:"status" json:"status"`
	Requires string   `yaml:"requires" json:"requires"`
}

// Level is one level's requirement and how cilock observes it.
type Level struct {
	Level      string `yaml:"level" json:"level"`
	Status     string `yaml:"status" json:"status"`
	Requires   string `yaml:"requires" json:"requires"`
	ObservedBy string `yaml:"observed_by" json:"observed_by"`
}

// Step is one action that supplies one missing observation.
type Step struct {
	ID          string `yaml:"id" json:"id"`
	TargetLevel string `yaml:"target_level" json:"target_level"`
	Status      string `yaml:"status" json:"status"`
	Closes      string `yaml:"closes" json:"closes"`
	When        string `yaml:"when" json:"when"`
	// CI restricts the step to runs observed on these platforms; empty means
	// every platform. Values are the CI* constants.
	CI []string `yaml:"ci,omitempty" json:"ci,omitempty"`
	// NotCI keeps the step off runs observed on these platforms, where a
	// platform-specific variant (listed with CI) replaces it.
	NotCI           []string `yaml:"not_ci,omitempty" json:"not_ci,omitempty"`
	Why             string   `yaml:"why" json:"why"`
	Action          string   `yaml:"action" json:"action"`
	AgentAction     string   `yaml:"agent_action" json:"agent_action"`
	Command         string   `yaml:"command,omitempty" json:"command,omitempty"`
	Snippet         string   `yaml:"snippet,omitempty" json:"snippet,omitempty"`
	Docs            string   `yaml:"docs,omitempty" json:"docs,omitempty"`
	Design          string   `yaml:"design,omitempty" json:"design,omitempty"`
	Uses            string   `yaml:"uses,omitempty" json:"uses,omitempty"`
	Pin             string   `yaml:"pin,omitempty" json:"pin,omitempty"`
	BuilderIdentity string   `yaml:"builder_identity,omitempty" json:"builder_identity,omitempty"`
}

// RenderedSnippet returns the snippet with the pin substituted. It returns ""
// when the snippet needs a pin the catalog does not have, so an unpinned
// reference can never be printed as if it were copyable.
func (s Step) RenderedSnippet() string {
	if !strings.Contains(s.Snippet, pinPlaceholder) {
		return s.Snippet
	}
	if !pinRE.MatchString(s.Pin) {
		return ""
	}
	return strings.ReplaceAll(s.Snippet, pinPlaceholder, s.Pin)
}

//go:embed catalog/*.yaml
var catalogFS embed.FS

var (
	loadOnce   sync.Once
	loaded     map[string]Catalog
	loadErr    error
	levelNames = map[string]func(string) (int, bool){
		StandardSLSABuild: func(n string) (int, bool) { return rankOf(n, []string{"none", "L1", "L2", "L3"}) },
		StandardALPS: func(n string) (int, bool) {
			return rankOf(n, []string{"unknown", "ALPS-0", "ALPS-1", "ALPS-2", "ALPS-3"})
		},
	}
)

func rankOf(name string, names []string) (int, bool) {
	for i, n := range names {
		if n == name {
			return i, true
		}
	}
	return 0, false
}

// Catalogs returns the embedded, validated catalogs keyed by standard. The
// catalog is compiled into the binary, so an error here is a build defect;
// callers that report guidance treat it as "no guidance", never as a level.
func Catalogs() (map[string]Catalog, error) {
	loadOnce.Do(func() { loaded, loadErr = parseCatalogs(catalogFS) })
	return loaded, loadErr
}

func parseCatalogs(fsys fs.FS) (map[string]Catalog, error) {
	entries, err := fs.ReadDir(fsys, "catalog")
	if err != nil {
		return nil, fmt.Errorf("standards catalog: %w", err)
	}
	out := map[string]Catalog{}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".yaml") {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join("catalog", ent.Name()))
		if err != nil {
			return nil, fmt.Errorf("standards catalog %s: %w", ent.Name(), err)
		}
		c, err := ParseCatalog(raw)
		if err != nil {
			return nil, fmt.Errorf("standards catalog %s: %w", ent.Name(), err)
		}
		if _, dup := out[c.Standard]; dup {
			return nil, fmt.Errorf("standards catalog %s: duplicate standard %q", ent.Name(), c.Standard)
		}
		out[c.Standard] = c
	}
	for std := range observationNames {
		if _, ok := out[std]; !ok {
			return nil, fmt.Errorf("standards catalog: no catalog for %q", std)
		}
	}
	return out, nil
}

// ParseCatalog decodes one catalog file strictly and validates it.
func ParseCatalog(raw []byte) (Catalog, error) {
	var c Catalog
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Catalog{}, err
	}
	if err := c.validate(); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

func (c Catalog) validate() error {
	if c.Schema != CatalogSchema {
		return fmt.Errorf("schema %q, want %q", c.Schema, CatalogSchema)
	}
	obs, ok := observationNames[c.Standard]
	if !ok {
		return fmt.Errorf("unknown standard %q", c.Standard)
	}
	levelStatus, err := c.validateLevels()
	if err != nil {
		return err
	}
	ids := map[string]bool{}
	for _, s := range c.Steps {
		if s.ID == "" || ids[s.ID] {
			return fmt.Errorf("step id %q is empty or duplicated", s.ID)
		}
		ids[s.ID] = true
		if err := s.validate(levelStatus, obs); err != nil {
			return fmt.Errorf("step %s: %w", s.ID, err)
		}
	}
	for _, l := range c.Limits {
		if _, ok := levelStatus[l.Level]; !ok {
			return fmt.Errorf("limit: level %q is not a listed level", l.Level)
		}
		if l.Status != StatusFuture || l.Requires == "" || len(l.CI) == 0 || !allKnownCI(l.CI) {
			return fmt.Errorf("limit %s: needs status future, a requirement, and known ci platforms (got %q, %v)", l.Level, l.Status, l.CI)
		}
	}
	return nil
}

func allKnownCI(ci []string) bool {
	for _, p := range ci {
		if !contains(ciPlatforms, p) {
			return false
		}
	}
	return true
}

// validateLevels checks each level and returns its status by name.
func (c Catalog) validateLevels() (map[string]string, error) {
	rank := levelNames[c.Standard]
	levelStatus := map[string]string{}
	for _, l := range c.Levels {
		if _, ok := rank(l.Level); !ok {
			return nil, fmt.Errorf("level %q is not a %s level", l.Level, c.Standard)
		}
		if l.Status != StatusAvailable && l.Status != StatusPlanned && l.Status != StatusFuture {
			return nil, fmt.Errorf("level %s: status %q", l.Level, l.Status)
		}
		if l.Requires == "" {
			return nil, fmt.Errorf("level %s: requires is empty", l.Level)
		}
		levelStatus[l.Level] = l.Status
	}
	return levelStatus, nil
}

// validate checks one step against its catalog's levels and observations.
func (s Step) validate(levelStatus map[string]string, obs []string) error {
	st, ok := levelStatus[s.TargetLevel]
	switch {
	case !ok:
		return fmt.Errorf("target_level %q is not a listed level", s.TargetLevel)
	case st == StatusFuture:
		return fmt.Errorf("targets %s, which is future; a future level gets no action", s.TargetLevel)
	case !contains(obs, s.Closes):
		return fmt.Errorf("closes %q, not one of %v", s.Closes, obs)
	case s.When != WhenAny && s.When != WhenCI && s.When != WhenLocal:
		return fmt.Errorf("when %q", s.When)
	case !allKnownCI(s.CI) || !allKnownCI(s.NotCI):
		return fmt.Errorf("ci %v / not_ci %v: not all of %v", s.CI, s.NotCI, ciPlatforms)
	case s.Why == "" || s.Action == "" || s.AgentAction == "":
		return fmt.Errorf("why, action and agent_action are required")
	}
	if err := s.validateReferences(); err != nil {
		return err
	}
	return s.validateStatus()
}

// validateReferences checks the pin and builder identity a step carries.
func (s Step) validateReferences() error {
	if s.Pin != "" && !pinRE.MatchString(s.Pin) {
		return fmt.Errorf("pin %q is not a 40-character commit SHA", s.Pin)
	}
	// A builder identity is matched as a prefix of the leaf's Build Signer
	// URI. Without the trailing `@` it would also match a lookalike workflow
	// such as `provenance.yml.evil.yml@...`.
	if s.BuilderIdentity != "" && (!strings.HasPrefix(s.BuilderIdentity, "https://") || !strings.HasSuffix(s.BuilderIdentity, "@")) {
		return fmt.Errorf("builder_identity %q must be an https URI ending in '@'", s.BuilderIdentity)
	}
	return nil
}

// validateStatus checks what a step's status requires of its text and pin.
func (s Step) validateStatus() error {
	switch s.Status {
	case StatusAvailable:
		if strings.Contains(s.Snippet, pinPlaceholder) && !pinRE.MatchString(s.Pin) {
			return fmt.Errorf("available with an unpinned snippet; set pin to a 40-character commit SHA")
		}
	case StatusPlanned:
		// The output carries no status marker of its own in prose, so the
		// text must say it: a planned step never reads as something to do now.
		if !strings.HasPrefix(s.Action, "Coming") || !strings.HasPrefix(s.AgentAction, "Coming") {
			return fmt.Errorf("planned, so action and agent_action must begin with \"Coming\"")
		}
	default:
		return fmt.Errorf("status %q (a step is available or planned)", s.Status)
	}
	return nil
}

// SortedCatalogs returns the catalogs in a stable order for listing.
func SortedCatalogs() ([]Catalog, error) {
	m, err := Catalogs()
	if err != nil {
		return nil, err
	}
	out := make([]Catalog, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return standardOrder(out[i].Standard) < standardOrder(out[j].Standard) })
	return out, nil
}

func standardOrder(s string) int {
	if s == StandardSLSABuild {
		return 0
	}
	return 1
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
