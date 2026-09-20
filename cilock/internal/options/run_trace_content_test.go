// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package options

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestTraceFileContentConsentIsSeparate(t *testing.T) {
	var ro RunOptions
	cmd := &cobra.Command{}
	ro.AddFlags(cmd)
	require.False(t, ro.TraceFileContent)
	require.NoError(t, cmd.ParseFlags([]string{"--trace", "--script-capture=content"}))
	require.False(t, ro.TraceFileContent, "operand capture must not silently expand to workspace reads")
	require.NoError(t, cmd.ParseFlags([]string{"--trace-file-content"}))
	require.True(t, ro.TraceFileContent)
}
