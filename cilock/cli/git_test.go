// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitConfigureDefaultsToRepositoryAndMandatorySigningSettings(t *testing.T) {
	original := runGitConfig
	t.Cleanup(func() { runGitConfig = original })
	var calls [][]string
	runGitConfig = func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}
	cmd := gitConfigureCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	require.NoError(t, cmd.Execute())

	want := [][]string{
		{"rev-parse", "--git-dir"},
		{"config", "--local", "gpg.format", "x509"},
		{"config", "--local", "gpg.x509.program", "cilock"},
		{"config", "--local", "commit.gpgsign", "true"},
		{"config", "--local", "tag.gpgsign", "true"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
	require.Contains(t, stdout.String(), "Fulcio + mandatory TSA")
}

func TestGitConfigureGlobalDoesNotRequireRepository(t *testing.T) {
	original := runGitConfig
	t.Cleanup(func() { runGitConfig = original })
	var calls [][]string
	runGitConfig = func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return nil
	}
	cmd := gitConfigureCmd()
	cmd.SetArgs([]string{"--global"})
	require.NoError(t, cmd.Execute())
	require.Len(t, calls, 4)
	for _, call := range calls {
		require.Equal(t, []string{"config", "--global"}, call[:2])
	}
}
