// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"os"

	fulciosigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
	"github.com/spf13/cobra"
)

// osGetenv is the process environment, read by cilock itself (never the
// wrapped command's), for selectAmbientCIFulcio.
var osGetenv = os.Getenv

// selectAmbientCIFulcio selects the platform Fulcio signer on the non-GitHub
// CIs a Fulcio CA maps (GitLab CI, Buildkite, CircleCI; #9839), so a bare
// `cilock run --platform-url X` signs keyless there as it does on GitHub
// Actions. It only points the signer at fulcioURL; the signer itself fetches
// the job's OIDC token at signing time (plugins/signers/fulcio/ambient.go) and
// refuses with the fix when the job did not provide one.
//
// It never overrides a choice: an explicit non-fulcio signer or a
// user-supplied --signer-fulcio-url is left alone. Returns whether it selected
// the signer.
func selectAmbientCIFulcio(cmd *cobra.Command, fulcioURL string, getenv func(string) string) bool {
	if fulcioURL == "" || !fulciosigner.AmbientCIDetected(getenv) || nonFulcioSignerSelected(cmd) {
		return false
	}
	f := cmd.Flags().Lookup("signer-fulcio-url")
	if f == nil || f.Changed {
		return false
	}
	return cmd.Flags().Set("signer-fulcio-url", fulcioURL) == nil
}
