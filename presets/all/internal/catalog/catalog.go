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

// Package catalog builds the MACHINE-READABLE attestor catalog by live
// registry introspection. It is the JSON sibling of
// scripts/gen-attestor-catalog.sh (which still owns the markdown): instead of
// grepping each plugin's Go source for the registered Name/RunType/Type, it
// blank-imports presets/all (registering every attestor + every detector.yaml
// — the 32 plugin detectors and the 80 embedded catalog detectors) and reads
// the truth out of the live attestation + detection registries.
//
// The build is factored out of main() so it is unit-testable: Build() returns
// the populated Catalog struct, main() only marshals it and writes the file.
// Output is DETERMINISTIC — attestors are sorted by run-phase order then name,
// every nested list is sorted, and no timestamp is emitted — so the generated
// docs/attestor-catalog.json diffs cleanly and a "regenerate twice ⇒
// byte-identical" test holds.
//
// Importing this package (transitively, via the gen-catalog command or the
// test) pulls in presets/all through the blank import below, so callers do not
// need their own registration import.
package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"

	_ "github.com/aflock-ai/rookery/presets/all" // register every attestor + every detector.yaml
)

// GeneratedFrom is the provenance marker written into the catalog. It records
// HOW the file was produced (registry introspection + detector.yaml join), not
// WHEN — a timestamp would defeat reproducibility.
const GeneratedFrom = "registry+detector.yaml"

// runPhaseOrder maps each attestation.RunType to its lifecycle position so the
// catalog can be presented in firing order (the same ordering the markdown
// catalog and the AttestationContext use). An unknown run-type sorts last.
var runPhaseOrder = map[string]int{
	string(attestation.PreMaterialRunType): 0,
	string(attestation.MaterialRunType):    1,
	string(attestation.ExecuteRunType):     2,
	string(attestation.ProductRunType):     3,
	string(attestation.PostProductRunType): 4,
	string(attestation.VerifyRunType):      5,
}

func phaseRank(runType string) int {
	if r, ok := runPhaseOrder[runType]; ok {
		return r
	}
	return len(runPhaseOrder) // unknown run-types sort after the known phases
}

// Catalog is the top-level machine-readable document.
type Catalog struct {
	GeneratedFrom string  `json:"generated_from"`
	AttestorCount int     `json:"attestor_count"`
	Attestors     []Entry `json:"attestors"`

	// ParseErrors records detector.yaml files that failed to parse, keyed by
	// detector name with the error text. These are pre-existing data/module
	// bugs (a malformed embedded detector.yaml); they are surfaced here rather
	// than silently dropped so the catalog stays diff-stable AND honest about
	// what it could not enrich. Empty (omitted) when every detector parses.
	ParseErrors map[string]string `json:"parse_errors,omitempty"`
}

// Entry is one attestor (or detection-only tool) in the catalog. Empty fields
// are omitted so the JSON stays compact and a field's absence is meaningful.
type Entry struct {
	Name string `json:"name"`

	// PredicateType / PredicateTypes come from the LIVE attestor
	// (Attestor.Type()) when one is registered, else from the detector
	// contract (detection-only catalog entries have no live attestor).
	PredicateType  string   `json:"predicate_type,omitempty"`
	PredicateTypes []string `json:"predicate_types,omitempty"`

	// RunType is the live Attestor.RunType() when registered, else the
	// contract's run_type (detection-only entries usually have neither).
	RunType string `json:"run_type,omitempty"`

	// detector.yaml enrichment.
	Category        []string  `json:"category,omitempty"`
	PrimaryCategory string    `json:"primary_category,omitempty"`
	Tier            string    `json:"tier,omitempty"`
	Upstream        *Upstream `json:"upstream,omitempty"`
	EmitsFormats    []string  `json:"emits_formats,omitempty"`

	// DetectionOnly marks a catalog tool with no backing Go attestor — cilock
	// recognizes it (routes uploads, renders warnings) but the evidence comes
	// from a format attestor (sbom/sarif/vex/test-results). True for the
	// embedded catalog/*.yaml entries.
	DetectionOnly bool `json:"detection_only,omitempty"`

	// Registered is true when a live Go attestor backs this name. It is the
	// inverse of "this is purely a detector.yaml catalog entry" and lets a
	// consumer tell a real attestor (callable via --attestations) from a
	// detection-only label.
	Registered bool `json:"registered"`

	// Subjects are the declared subject-key prefix families from the contract
	// (the stable, build-time source). We do NOT call Subjects() on an un-run
	// attestor — that needs a real AttestationContext and would be empty/noisy.
	Subjects []Subject `json:"subjects,omitempty"`

	// HasContract records whether the detector.yaml carries an output contract
	// (the proven/declared output facet) vs. detection gates only.
	HasContract bool `json:"has_contract"`

	// AppliesWhen is a human-usable summary of the Pre/Post detection gates —
	// when cilock auto-detects this tool. Derived from the gate Match
	// predicate trees. Empty when the detector has no gates we can summarize.
	AppliesWhen *AppliesWhen `json:"applies_when,omitempty"`

	// Detection carries the raw applicability (the structured gate summary) so
	// nothing is lost when AppliesWhen's flattened form drops nuance. Present
	// whenever the detector declares pre/post gates.
	Detection *Detection `json:"detection,omitempty"`
}

// Upstream mirrors detection.UpstreamInfo with stable JSON keys.
type Upstream struct {
	Name       string `json:"name,omitempty"`
	Source     string `json:"source,omitempty"`
	License    string `json:"license,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	FormatOnly bool   `json:"format_only,omitempty"`
}

// Subject is one declared subject-key family.
type Subject struct {
	Prefix      string   `json:"prefix"`
	Description string   `json:"description,omitempty"`
	DigestAlgs  []string `json:"digest_algs,omitempty"`
}

// AppliesWhen summarizes the detection gates in flat human-readable lines.
type AppliesWhen struct {
	// Pre summarizes the pre-execution Match gate (argv/file/env shape that
	// fires the attestor before the command runs).
	Pre string `json:"pre,omitempty"`
	// Post summarizes the post-execution Match gate (products/exec-observed
	// shape that fires the attestor after the command runs).
	Post string `json:"post,omitempty"`
}

// Detection carries the structured (raw) gate predicates for callers that want
// the exact tree rather than the flattened AppliesWhen string.
type Detection struct {
	Pre  *PredicateNode `json:"pre,omitempty"`
	Post *PredicateNode `json:"post,omitempty"`
}

// PredicateNode is a JSON-friendly, deterministic projection of a
// detection.Predicate tree. Exactly one shape is populated per node, mirroring
// the tagged-union source.
type PredicateNode struct {
	AnyOf []PredicateNode `json:"any_of,omitempty"`
	AllOf []PredicateNode `json:"all_of,omitempty"`
	Not   *PredicateNode  `json:"not,omitempty"`

	ArgvPrefix     []string `json:"argv_prefix,omitempty"`
	ArgvContains   string   `json:"argv_contains,omitempty"`
	ArgvRegex      string   `json:"argv_regex,omitempty"`
	EnvSet         string   `json:"env_set,omitempty"`
	EnvEquals      string   `json:"env_equals,omitempty"`
	FileExists     string   `json:"file_exists,omitempty"`
	FileGlob       []string `json:"file_glob,omitempty"`
	BinaryDigestIn string   `json:"binary_digest_in,omitempty"`
	IMDSReachable  *bool    `json:"imds_reachable,omitempty"`
	GCPMetadata    *bool    `json:"gcp_metadata_reachable,omitempty"`
	AzureMetadata  *bool    `json:"azure_metadata_reachable,omitempty"`
	SocketListen   *int     `json:"socket_listening,omitempty"`

	ExecObserved    *PredicateNode `json:"exec_observed,omitempty"`
	ProductGlob     []string       `json:"product_glob,omitempty"`
	ProductMime     string         `json:"product_mime,omitempty"`
	MaterialChanged string         `json:"material_changed,omitempty"`
	ExitCode        string         `json:"exit_code,omitempty"`
}

// Render builds the catalog and marshals it to deterministic, indented JSON
// with a trailing newline. It is the SINGLE byte-producing path shared by the
// gen-catalog command and the determinism test, so "what the command writes" and
// "what the test asserts byte-identical" can never drift. HTML escaping is
// disabled so predicate URIs and globs (`&`, `<`, `>`) stay readable.
func Render() ([]byte, error) {
	cat, err := Build()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cat); err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}
	return buf.Bytes(), nil
}

// Build performs the live registry introspection + detector.yaml join and
// returns the deterministic Catalog. It is the single source the gen-catalog
// command and the determinism test both drive.
func Build() (*Catalog, error) {
	// 1. Every live attestor, instantiated to read Name/Type/RunType.
	type live struct {
		predicateType string
		runType       string
	}
	liveByName := map[string]live{}
	for _, e := range attestation.RegistrationEntries() {
		a := e.Factory()
		liveByName[a.Name()] = live{
			predicateType: a.Type(),
			runType:       string(a.RunType()),
		}
	}

	// 2. Every detector.yaml (plugin + embedded catalog), already parsed by the
	//    detection registry that presets/all + the detection init populate.
	//    Parse failures are PRE-EXISTING data/module bugs (a malformed embedded
	//    detector.yaml in a pinned module version); we record them in the output
	//    rather than abort, so a single bad file can't suppress the whole
	//    catalog. The same tolerant stance the existing static test takes.
	detectors, failures := detection.Default().LookupAll()
	var parseErrors map[string]string
	if len(failures) > 0 {
		parseErrors = make(map[string]string, len(failures))
		for n, err := range failures {
			parseErrors[n] = err.Error()
		}
	}

	// 3. Union of names: a live attestor MAY have no detector.yaml, and a
	//    detection-only catalog entry has a detector.yaml but no live attestor.
	names := map[string]struct{}{}
	for n := range liveByName {
		names[n] = struct{}{}
	}
	for n := range detectors {
		names[n] = struct{}{}
	}

	entries := make([]Entry, 0, len(names))
	for name := range names {
		lv, registered := liveByName[name]
		entries = append(entries, buildEntry(name, lv.predicateType, lv.runType, registered, detectors[name]))
	}

	sortEntries(entries)

	return &Catalog{
		GeneratedFrom: GeneratedFrom,
		AttestorCount: len(entries),
		Attestors:     entries,
		ParseErrors:   parseErrors,
	}, nil
}

// buildEntry assembles one catalog entry, joining the live attestor facts
// (predicate type, run type) with the detector.yaml enrichment.
func buildEntry(name, livePredicate, liveRunType string, registered bool, d *detection.DetectorYAML) Entry {
	e := Entry{
		Name:          name,
		PredicateType: livePredicate,
		RunType:       liveRunType,
		Registered:    registered,
	}

	if d == nil {
		return e
	}

	// detector.yaml enrichment. A name can be registered by BOTH a plugin
	// detector.yaml and a detection-only catalog/*.yaml (first-write-wins in the
	// detection registry, so the joined detector may be the detection-only one).
	// When a live Go attestor backs the name, it is authoritative: the tool is
	// NOT detection-only regardless of which detector.yaml won the registry key.
	e.DetectionOnly = d.DetectionOnly && !registered
	e.PrimaryCategory = string(d.PrimaryCategory)
	e.EmitsFormats = sortedCopy(d.EmitsFormats)
	if len(d.Category) > 0 {
		cats := make([]string, len(d.Category))
		for i, c := range d.Category {
			cats[i] = string(c)
		}
		sort.Strings(cats)
		e.Category = cats
	}
	if u := d.Upstream; u != nil {
		e.Upstream = &Upstream{
			Name:       u.Name,
			Source:     u.Source,
			License:    u.License,
			Vendor:     u.Vendor,
			FormatOnly: u.FormatOnly,
		}
	}

	applyContract(&e, d.Contract)
	applyDetection(&e, d)

	return e
}

// applyContract folds the detector.yaml OUTPUT contract into the entry. For
// detection-only entries (no live attestor) the contract is the only source of
// predicate type / run type, so it fills those only when still empty. A nil
// contract is a no-op.
func applyContract(e *Entry, c *detection.OutputContract) {
	if c == nil {
		return
	}
	e.HasContract = true
	e.Tier = c.Tier
	if e.PredicateType == "" {
		e.PredicateType = c.PredicateType
	}
	if e.RunType == "" {
		e.RunType = c.RunType
	}
	if len(c.PredicateTypes) > 0 {
		e.PredicateTypes = sortedCopy(c.PredicateTypes)
	}
	for _, s := range c.Subjects {
		e.Subjects = append(e.Subjects, Subject{
			Prefix:      s.Prefix,
			Description: s.Description,
			DigestAlgs:  sortedCopy(s.DigestAlgs),
		})
	}
	sort.Slice(e.Subjects, func(i, j int) bool { return e.Subjects[i].Prefix < e.Subjects[j].Prefix })
}

// applyDetection folds the detector.yaml detection gates into the entry:
// applies_when (flattened, human-usable) + detection (raw predicate trees).
// A detector with no pre/post gates leaves both fields nil.
func applyDetection(e *Entry, d *detection.DetectorYAML) {
	pre := gateMatch(d.Pre)
	post := gateMatch(d.Post)
	if pre == nil && post == nil {
		return
	}
	aw := &AppliesWhen{}
	if pre != nil {
		aw.Pre = summarizePredicate(pre)
	}
	if post != nil {
		aw.Post = summarizePredicate(post)
	}
	e.AppliesWhen = aw
	e.Detection = &Detection{
		Pre:  convertPredicate(pre),
		Post: convertPredicate(post),
	}
}

func gateMatch(g *detection.GateBlock) *detection.Predicate {
	if g == nil {
		return nil
	}
	return g.Match
}

// sortEntries orders the catalog by run-phase then name — the firing order the
// markdown catalog and the AttestationContext use — with name as a stable
// tiebreaker so the output is fully deterministic.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		ri, rj := phaseRank(entries[i].RunType), phaseRank(entries[j].RunType)
		if ri != rj {
			return ri < rj
		}
		return entries[i].Name < entries[j].Name
	})
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}
