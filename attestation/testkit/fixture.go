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

// Package testkit is the catalog verification SDK. It drives an attestor
// against a recorded FIXTURE and asserts the catalog's OUTPUT CONTRACT
// (predicate type, subjects, materials, products) — closing the loop so the
// catalog can't claim behavior the attestor doesn't have.
//
// It generalizes the per-attestor `//go:build validate` tests
// (steampipe_validate_test.go's fakeProducer pattern) into one reusable,
// always-run, hermetic harness: fixtures are committed recorded tool outputs,
// so no real tool or network is needed. testkit is the output-contract sibling
// of attestation/detection/detectiontest (which proves the detection gate).
package testkit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ManifestFile is the per-fixture manifest filename.
const ManifestFile = "fixture.yaml"

// SchemaVersion is the supported fixture manifest version.
const SchemaVersion = "0.1"

// Setup modes — keyed to the attestor's RunType. This is what lets the
// verification loop cover ALL run-types, not just file-consuming attestors.
const (
	ModeProduct      = "product"      // PostProduct: inject input as a Product (fakeProducer)
	ModeWorkdir      = "workdir"      // Product/Material: materialize input tree into a temp workdir
	ModeEnv          = "env"          // PreMaterial/Material: set env vars (+ optional workdir)
	ModeCommand      = "command"      // Execute: run a deterministic command / replay a trace
	ModeAttestations = "attestations" // Verify: run over recorded input attestations + policy
	ModeHTTPMock     = "http-mock"    // cloud identity: serve a recorded metadata response
)

// Subject match modes.
const (
	MatchExact  = "exact"
	MatchPrefix = "prefix"
)

// manifest is the on-disk fixture.yaml shape.
type manifest struct {
	SchemaVersion string         `yaml:"schema_version"`
	Attestor      string         `yaml:"attestor"`
	Description   string         `yaml:"description"`
	Setup         setupSpec      `yaml:"setup"`
	Recording     *recordingSpec `yaml:"recording"`
	Expect        expectSpec     `yaml:"expect"`
}

// recordingSpec is the provenance of the REAL tool run that produced this
// fixture. The point of an attestation kit: a fixture isn't a hand-copied
// sample, it's the recorded output of a real run, with the tool version and
// binary digest captured so staleness is visible. `attestation` points at the
// real cilock attestation collection the run produced.
type recordingSpec struct {
	Tool         string   `yaml:"tool"`
	Version      string   `yaml:"version"`
	BinarySHA256 string   `yaml:"binary_sha256"`
	RecordedWith string   `yaml:"recorded_with"`
	Attestation  string   `yaml:"attestation"` // relative path to the recorded collection
	Argv         []string `yaml:"argv"`
	RecordedAt   string   `yaml:"recorded_at"`
}

// Recording is the resolved provenance of a fixture's real run.
type Recording struct {
	Tool            string
	Version         string
	BinarySHA256    string
	RecordedWith    string
	Argv            []string
	RecordedAt      string
	AttestationPath string // abs path to the recorded cilock attestation collection ("" if none)
}

type setupSpec struct {
	Mode     string            `yaml:"mode"`
	Input    string            `yaml:"input"`     // relative to the fixture dir; "" when none
	MimeType string            `yaml:"mime_type"` // injected Product mime (product mode)
	Env      map[string]string `yaml:"env"`       // env mode
	Workdir  []string          `yaml:"workdir"`   // workdir mode: files (relative) to materialize
	Options  map[string]any    `yaml:"options"`   // attestor-specific (e.g. steampipe sql/frontmatter)
}

type expectSpec struct {
	PredicateType string       `yaml:"predicate_type"`
	RunType       string       `yaml:"run_type"`
	Subjects      subjectsSpec `yaml:"subjects"`
	Materials     []string     `yaml:"materials"` // subject/material keys (or prefixes) expected
	Products      []string     `yaml:"products"`
	Exit          *exitSpec    `yaml:"exit"`
	Golden        string       `yaml:"golden"` // relative golden predicate path; "" = assertion-only
	Redact        []string     `yaml:"redact"` // dotted paths zeroed before golden compare
}

type subjectsSpec struct {
	Match string   `yaml:"match"` // exact | prefix (default prefix)
	Keys  []string `yaml:"keys"`
}

type exitSpec struct {
	OnNoEvidence  string `yaml:"on_no_evidence"`
	ErrorContains string `yaml:"error_contains"`
}

// Fixture is a loaded + validated fixture with paths resolved to absolute.
type Fixture struct {
	Name       string // fixture dir stem
	Dir        string // abs fixture dir
	Attestor   string
	Mode       string
	InputPath  string // abs; "" if no input file
	MimeType   string
	Env        map[string]string
	Workdir    []string // abs paths
	Options    map[string]any
	Expect     expectSpec
	GoldenPath string     // abs; "" if none
	Recording  *Recording // provenance of the real run; nil if the fixture was not recorded
}

// LoadFixture parses <dir>/fixture.yaml, validates it, and resolves all
// referenced paths relative to dir. A returned error means the fixture is
// malformed — which the CI gate treats as a hard failure ("catalog data is
// verified").
func LoadFixture(dir string) (*Fixture, error) {
	// Resolve to absolute so every derived path (input, golden, recorded
	// attestation) survives the t.Chdir the product-mode driver performs.
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	mpath := filepath.Join(dir, ManifestFile)
	raw, err := os.ReadFile(mpath) //nolint:gosec // dir comes from the catalog/test harness, not user input
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mpath, err)
	}
	var m manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: parse: %w", mpath, err)
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s: schema_version %q unsupported (want %q)", mpath, m.SchemaVersion, SchemaVersion)
	}
	if strings.TrimSpace(m.Attestor) == "" {
		return nil, fmt.Errorf("%s: attestor is required", mpath)
	}
	if !isKnownMode(m.Setup.Mode) {
		return nil, fmt.Errorf("%s: setup.mode %q is not one of product|workdir|env|command|attestations|http-mock", mpath, m.Setup.Mode)
	}
	if strings.TrimSpace(m.Expect.PredicateType) == "" {
		return nil, fmt.Errorf("%s: expect.predicate_type is required", mpath)
	}
	switch m.Expect.Subjects.Match {
	case "", MatchExact, MatchPrefix:
	default:
		return nil, fmt.Errorf("%s: expect.subjects.match %q must be exact|prefix", mpath, m.Expect.Subjects.Match)
	}

	fx := &Fixture{
		Name:     filepath.Base(dir),
		Dir:      dir,
		Attestor: m.Attestor,
		Mode:     m.Setup.Mode,
		MimeType: m.Setup.MimeType,
		Env:      m.Setup.Env,
		Options:  m.Setup.Options,
		Expect:   m.Expect,
	}
	if m.Setup.Input != "" {
		fx.InputPath = filepath.Join(dir, m.Setup.Input)
		if _, err := os.Stat(fx.InputPath); err != nil {
			return nil, fmt.Errorf("%s: setup.input %q not found: %w", mpath, m.Setup.Input, err)
		}
	}
	for _, w := range m.Setup.Workdir {
		fx.Workdir = append(fx.Workdir, filepath.Join(dir, w))
	}
	if m.Expect.Golden != "" {
		fx.GoldenPath = filepath.Join(dir, m.Expect.Golden)
	}
	if fx.MimeType == "" {
		fx.MimeType = "application/json"
	}
	if fx.Expect.Subjects.Match == "" {
		fx.Expect.Subjects.Match = MatchPrefix
	}
	if m.Recording != nil {
		fx.Recording = &Recording{
			Tool:         m.Recording.Tool,
			Version:      m.Recording.Version,
			BinarySHA256: m.Recording.BinarySHA256,
			RecordedWith: m.Recording.RecordedWith,
			Argv:         m.Recording.Argv,
			RecordedAt:   m.Recording.RecordedAt,
		}
		if m.Recording.Attestation != "" {
			fx.Recording.AttestationPath = filepath.Join(dir, m.Recording.Attestation)
			if _, err := os.Stat(fx.Recording.AttestationPath); err != nil {
				return nil, fmt.Errorf("%s: recording.attestation %q not found: %w", mpath, m.Recording.Attestation, err)
			}
		}
	}
	return fx, nil
}

// LoadFixtures loads every <root>/*/fixture.yaml. Used by the harness to walk
// a plugin's testdata/fixtures/ directory.
func LoadFixtures(root string) ([]*Fixture, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []*Fixture
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if _, err := os.Stat(filepath.Join(dir, ManifestFile)); err != nil {
			continue // not a fixture dir
		}
		fx, err := LoadFixture(dir)
		if err != nil {
			return nil, err
		}
		out = append(out, fx)
	}
	return out, nil
}

func isKnownMode(m string) bool {
	switch m {
	case ModeProduct, ModeWorkdir, ModeEnv, ModeCommand, ModeAttestations, ModeHTTPMock:
		return true
	}
	return false
}
