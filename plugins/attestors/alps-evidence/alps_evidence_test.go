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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attestFixture(t *testing.T, src ProcessSource, selfPID int, opts ...Option) *Attestor {
	t.Helper()
	a := newFixtureAttestor(t, src, selfPID, opts...)
	ctx, err := attestation.NewContext("alps-evidence-test",
		[]attestation.Attestor{a},
		attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))
	return a
}

func newFixtureAttestor(t *testing.T, src ProcessSource, selfPID int, opts ...Option) *Attestor {
	t.Helper()
	all := append([]Option{WithProcessSource(src), WithSelfPID(selfPID)}, opts...)
	return New(all...)
}

func mustLiveContext(t *testing.T, a attestation.Attestor) *attestation.AttestationContext {
	t.Helper()
	ctx, err := attestation.NewContext("alps-evidence-live",
		[]attestation.Attestor{a}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	return ctx
}

func TestAttestorRegistrationMetadata(t *testing.T) {
	a := New()
	assert.Equal(t, "alps-evidence", a.Name())
	assert.Equal(t, "https://aflock.ai/attestations/alps-evidence/v0.1", a.Type())
	assert.Equal(t, attestation.PreMaterialRunType, a.RunType())
	assert.NotNil(t, a.Schema())
}

// TestAttestorIsResolvableFromTheRegistry proves the init() registration landed
// under the exact name and predicate type the rest of the system will look for.
func TestAttestorIsResolvableFromTheRegistry(t *testing.T) {
	byName, err := attestation.GetAttestor(Name)
	require.NoError(t, err)
	assert.Equal(t, Type, byName.Type())

	factory, ok := attestation.FactoryByType(Type)
	require.True(t, ok, "predicate type %q must resolve to a factory", Type)
	assert.Equal(t, Name, factory().Name())
}

// TestAttestorCannotContributeToPolicyResolution is a security property, not a
// style preference.
//
// Every field in this predicate is chosen by the process being described. If the
// attestor also implemented Subjecter, Materialer, Producer, BackReffer or
// Exporter, an agent could describe itself into satisfying an assertion —
// self-description as a way of talking past policy. Subjects are the sharpest
// case: they are how `cilock verify --artifactfile` selects a collection.
func TestAttestorCannotContributeToPolicyResolution(t *testing.T) {
	var a any = New()

	_, isSubjecter := a.(attestation.Subjecter)
	assert.False(t, isSubjecter, "alps-evidence must not publish subjects")

	_, isMaterialer := a.(attestation.Materialer)
	assert.False(t, isMaterialer, "alps-evidence must not publish materials")

	_, isProducer := a.(attestation.Producer)
	assert.False(t, isProducer, "alps-evidence must not publish products")

	_, isBackReffer := a.(attestation.BackReffer)
	assert.False(t, isBackReffer, "alps-evidence must not publish back-references")

	_, isExporter := a.(attestation.Exporter)
	assert.False(t, isExporter, "alps-evidence must not export a standalone attestation")
}

// TestAssuranceStatementIsAlwaysEmitted, including on a run that detects
// nothing. A reader must never receive this predicate without the caveat.
func TestAssuranceStatementIsAlwaysEmitted(t *testing.T) {
	// The tree includes its root: not-detected is a completed-walk claim, so
	// the walk must be able to reach init.
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 90, PPID: 1, Executable: "/bin/bash"},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init"},
	)
	a := attestFixture(t, src, 100)

	assert.Equal(t, StatusNotDetected, a.Status)
	assert.Nil(t, a.Invoker)
	assert.False(t, a.Assurance.Enforcement)
	assert.Equal(t, "process-ancestry-observation", a.Assurance.Mode)
	assert.Contains(t, a.Assurance.Caveat, "not as proof of which")
	assert.Contains(t, a.Assurance.Caveat, "misrepresents itself")
}

// TestAbsentFieldsAreAbsentNotEmpty. A consumer renders a missing model as "not
// observable"; an empty string would render as a claim that was never made.
func TestAbsentFieldsAreAbsentNotEmpty(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, claudeCodeMacOSDaemonChain(), pidCilock)

	body, err := json.Marshal(a)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))

	_, hasModel := doc["model"]
	assert.False(t, hasModel, "an unresolvable model must be absent, not empty")

	_, hasSession := doc["session"]
	assert.True(t, hasSession, "the session was resolvable in this fixture")

	invoker, ok := doc["invoker"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, invoker, "version")
	assert.Contains(t, invoker, "fingerprint")
}

// TestNotDetectedOmitsInvokerEntirely.
func TestNotDetectedOmitsInvokerEntirely(t *testing.T) {
	// The tree includes its root; see TestAssuranceStatementIsAlwaysEmitted.
	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 90, PPID: 1, Executable: "/bin/bash"},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init"},
	)
	a := attestFixture(t, src, 100)

	body, err := json.Marshal(a)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(body, &doc))

	assert.NotContains(t, doc, "invoker")
	assert.NotContains(t, doc, "model")
	assert.Equal(t, "not-detected", doc["status"])
}

// TestModelCarriesItsOwnAssuranceSeparateFromTheInvoker.
func TestModelCarriesItsOwnAssuranceSeparateFromTheInvoker(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, codexHomebrewCask(), 100)

	require.NotNil(t, a.Invoker)
	require.NotNil(t, a.Invoker.Version)
	require.NotNil(t, a.Model)

	assert.Equal(t, AssuranceProcessObserved, a.Model.Assurance)
	assert.NotEmpty(t, a.Model.Source)
	assert.NotEqual(t, a.Model.Source, a.Invoker.Fingerprint,
		"the model's provenance is its own, not the invoker's")
}

// TestUnavailableWhenAncestryCannotBeRead. "Could not look" is a successful
// observation of unavailability, not an error: the walk failure is recorded
// INSIDE the predicate (status + warning), and Attest returns nil so the leg
// is neither fatal nor dropped. See the unavailable branch of observe for why
// an error return would delete exactly the evidence this status exists to
// carry.
func TestUnavailableWhenAncestryCannotBeRead(t *testing.T) {
	a := newFixtureAttestor(t, newFixtureSource(), 100)
	ctx, err := attestation.NewContext("alps-evidence-test",
		[]attestation.Attestor{a}, attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.NoError(t, err, "unavailability is published in the predicate, never reported as an attestor error")
	assert.Equal(t, StatusUnavailable, a.Status)
	assert.NotEmpty(t, a.Warnings)
}

// TestUnavailablePredicateSurvivesTheWorkflow is the collection-level half of
// the contract above, and the regression test for the finding it fixes: the
// old shape returned a plain error on "could not look", which the workflow
// treats as fatal (exit 1 for the whole `cilock run`) AND excludes from the
// signed collection (see workflow.evidenceIsRecordable) — so on any platform
// where the ancestry walk cannot work (Windows, /proc hidden, sandboxed), the
// run failed and the StatusUnavailable predicate that explains why was
// deleted. The unavailable observation must reach the signed collection, and
// the run must not error.
func TestUnavailablePredicateSurvivesTheWorkflow(t *testing.T) {
	a := newFixtureAttestor(t, newFixtureSource(), 100)

	result, runErr := workflow.Run(
		"alps-evidence-test",
		workflow.RunWithInsecure(true),
		workflow.RunWithAttestors([]attestation.Attestor{a}),
	)
	require.NoError(t, runErr,
		"a platform where the walk cannot look must not fail the run")

	var found *attestation.CollectionAttestation
	for i := range result.Collection.Attestations {
		if result.Collection.Attestations[i].Type == Type {
			found = &result.Collection.Attestations[i]
			break
		}
	}
	require.NotNil(t, found, "the unavailable observation must survive into the signed collection")

	encoded, err := json.Marshal(result.Collection)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), string(StatusUnavailable),
		"the collection must carry the unavailable status as data")
}

// TestExecutableDigestIsCappedBySize. Agent binaries measured on macOS are
// 300MB+; digesting one on every invocation would tax every build.
func TestExecutableDigestIsCappedBySize(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "codex")
	require.NoError(t, os.WriteFile(binPath, make([]byte, 4096), 0o600))

	src := newFixtureSource(
		ProcessInfo{PID: 100, PPID: 80, Executable: "/usr/local/bin/cilock"},
		ProcessInfo{PID: 80, PPID: 1, Executable: binPath, Comm: "codex", Argv: []string{"codex"}},
	)

	under := attestFixture(t, src, 100)
	require.NotNil(t, under.Invoker)
	assert.NotEmpty(t, under.Invoker.Process.SHA256)
	assert.Equal(t, int64(4096), under.Invoker.Process.SizeBytes)
	assert.Empty(t, under.Invoker.Process.DigestSkipped)

	over := attestFixture(t, src, 100, WithDigestSizeLimit(1024))
	require.NotNil(t, over.Invoker)
	assert.Empty(t, over.Invoker.Process.SHA256)
	assert.Equal(t, int64(4096), over.Invoker.Process.SizeBytes)
	assert.Contains(t, over.Invoker.Process.DigestSkipped, "above the 1024 byte digest limit")
}

func TestMissingExecutableRecordsWhyTheDigestIsAbsent(t *testing.T) {
	withHomeDir(t, t.TempDir())
	a := attestFixture(t, claudeCodeMacOSDaemonChain(), pidCilock)

	require.NotNil(t, a.Invoker)
	assert.Empty(t, a.Invoker.Process.SHA256)
	assert.Equal(t, "executable not readable", a.Invoker.Process.DigestSkipped)
}

// TestSchemaReflects proves the predicate shape is expressible as JSON schema,
// which the CLI needs for `cilock attestors schema`.
func TestSchemaReflects(t *testing.T) {
	schema := New().Schema()
	require.NotNil(t, schema)

	body, err := json.Marshal(schema)
	require.NoError(t, err)
	assert.Contains(t, string(body), "assurance")
	assert.Contains(t, string(body), "invoker")
}

// TestNewUsesTheLivePlatformSourceByDefault. A regression guard against a
// refactor that leaves the attestor wired to a nil source in production.
func TestNewUsesTheLivePlatformSourceByDefault(t *testing.T) {
	a := New()
	assert.NotNil(t, a.source)
	assert.Equal(t, os.Getpid(), a.selfPID)
	assert.Equal(t, DefaultDigestSizeLimit, a.digestSizeLimit)
	assert.NotEmpty(t, a.providers)
}
