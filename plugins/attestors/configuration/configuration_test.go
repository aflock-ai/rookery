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

package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConstants(t *testing.T) {
	assert.Equal(t, "configuration", Name)
	assert.Equal(t, "https://aflock.ai/attestations/configuration/v0.1", Type)
	assert.Equal(t, attestation.PreMaterialRunType, RunType)
}

func TestAttestorMethods(t *testing.T) {
	a := New()
	assert.Equal(t, Name, a.Name())
	assert.Equal(t, Type, a.Type())
	assert.Equal(t, RunType, a.RunType())
	assert.Equal(t, a, a.Data())
	assert.NotNil(t, a.Schema())
}

func TestAttestorInterfaces(t *testing.T) {
	a := New()
	assert.Implements(t, (*attestation.Attestor)(nil), a)
}

func TestAttest_BasicFlagCapture(t *testing.T) {
	a := New(WithCustomArgs([]string{
		"witness", "run", "--step", "build", "-o", "output.json",
	}))

	ctx := &attestation.AttestationContext{}
	err := a.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, "build", a.Flags["step"])
	assert.Equal(t, "output.json", a.Flags["o"])
	assert.NotEmpty(t, a.WorkingDir)
}

func TestAttest_MixedFlagFormats(t *testing.T) {
	a := New(WithCustomArgs([]string{
		"witness", "run", "--step=build", "-a", "configuration", "--trace",
	}))

	ctx := &attestation.AttestationContext{}
	err := a.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, "build", a.Flags["step"])
	assert.Equal(t, "configuration", a.Flags["a"])
	assert.Equal(t, "true", a.Flags["trace"])
}

func TestAttest_FlagsWithCommandSeparator(t *testing.T) {
	a := New(WithCustomArgs([]string{
		"witness", "run", "--step", "test", "--", "go", "test", "./...",
	}))

	ctx := &attestation.AttestationContext{}
	err := a.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, "test", a.Flags["step"])
	// args after "--" should not be captured
	_, hasGo := a.Flags["go"]
	assert.False(t, hasGo)
}

func TestAttest_ConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".witness.yaml")

	configContent := `run:
  step: build
  attestations:
    - environment
    - git
  signer-file-key-path: testkey.pem
`
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0644))

	// Change to temp dir so default config file is found
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))
	defer func() { _ = os.Chdir(oldWd) }()

	a := New(WithCustomArgs([]string{"witness", "run", "--step", "build"}))
	ctx := &attestation.AttestationContext{}
	err = a.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, ".witness.yaml", a.ConfigPath)
	assert.NotNil(t, a.ConfigDigest)
	assert.NotNil(t, a.ConfigContent)

	// Verify config content was parsed
	run, ok := a.ConfigContent["run"]
	assert.True(t, ok, "config should have 'run' key")
	runMap, ok := run.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "build", runMap["step"])
}

func TestAttest_CustomConfigPath(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "custom.yaml")

	require.NoError(t, os.WriteFile(configPath, []byte("key: value\n"), 0644))

	a := New(WithCustomArgs([]string{"witness", "run", "-c", configPath}))
	ctx := &attestation.AttestationContext{}
	err := a.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, configPath, a.ConfigPath)
	assert.NotNil(t, a.ConfigDigest)
	assert.Equal(t, "value", a.ConfigContent["key"])
}

func TestAttest_CustomConfigPathLongFlag(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "custom.yaml")

	require.NoError(t, os.WriteFile(configPath, []byte("foo: bar\n"), 0644))

	a := New(WithCustomArgs([]string{"witness", "run", "--config", configPath}))
	ctx := &attestation.AttestationContext{}
	err := a.Attest(ctx)
	require.NoError(t, err)

	assert.Equal(t, configPath, a.ConfigPath)
	assert.Equal(t, "bar", a.ConfigContent["foo"])
}

func TestAttest_NoConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))
	defer func() { _ = os.Chdir(oldWd) }()

	a := New(WithCustomArgs([]string{"witness", "run", "--step", "build"}))
	ctx := &attestation.AttestationContext{}
	err = a.Attest(ctx)
	require.NoError(t, err)

	// No config file → no config data
	assert.Empty(t, a.ConfigPath)
	assert.Nil(t, a.ConfigDigest)
	assert.Nil(t, a.ConfigContent)
}

func TestExtractWitnessArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "no separator",
			args: []string{"witness", "--step", "build"},
			want: []string{"--step", "build"},
		},
		{
			name: "with separator",
			args: []string{"witness", "--step", "test", "--", "go", "test"},
			want: []string{"--step", "test"},
		},
		{
			name: "empty args",
			args: []string{},
			want: nil,
		},
		{
			name: "program name only",
			args: []string{"witness"},
			want: nil,
		},
		{
			name: "separator at start",
			args: []string{"witness", "--", "echo", "hello"},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractWitnessArgs(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want map[string]string
	}{
		{
			name: "long flag with value",
			args: []string{"--step", "build"},
			want: map[string]string{"step": "build"},
		},
		{
			name: "short flag with value",
			args: []string{"-o", "output.json"},
			want: map[string]string{"o": "output.json"},
		},
		{
			name: "equals format",
			args: []string{"--step=build"},
			want: map[string]string{"step": "build"},
		},
		{
			name: "boolean flag",
			args: []string{"--trace"},
			want: map[string]string{"trace": "true"},
		},
		{
			name: "mixed formats",
			args: []string{"--step=build", "-a", "config", "--trace", "-o", "out.json"},
			want: map[string]string{
				"step":  "build",
				"a":     "config",
				"trace": "true",
				"o":     "out.json",
			},
		},
		{
			name: "empty args",
			args: []string{},
			want: map[string]string{},
		},
		{
			name: "non-flag args ignored",
			args: []string{"run", "--step", "build"},
			want: map[string]string{"step": "build"},
		},
		{
			name: "short equals format",
			args: []string{"-o=output.json"},
			want: map[string]string{"o": "output.json"},
		},
		{
			name: "consecutive boolean flags",
			args: []string{"--trace", "--verbose"},
			want: map[string]string{"trace": "true", "verbose": "true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseFlags(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}
