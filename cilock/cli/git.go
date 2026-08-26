// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

var runGitConfig = func(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // executable and argument grammar are fixed below.
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git %v: %w: %s", args, err, output)
	}
	return nil
}

// gitConfigTrue is git's boolean-true config VALUE. It is a git literal, not a
// Go bool rendered as text and not the POSIX `true` command cilock synthesizes
// elsewhere — those are separate concepts that happen to be spelled the same.
const gitConfigTrue = "true"

// GitCmd groups the Git-facing CI/lock integration. Signing and verification
// use Git's standard gpg.x509.program protocol and are intercepted before
// Cobra; this command provides the human-friendly configuration step.
func GitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git",
		Short: "Configure Git to sign commits and tags with CI/lock",
	}
	cmd.AddCommand(gitConfigureCmd())
	return cmd
}

func gitConfigureCmd() *cobra.Command {
	var global bool
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Use this CI/lock binary for keyless Git signing",
		Long: `Configure Git's standard X.509 signing protocol to use CI/lock.

The default changes only the current repository. Pass --global to configure
all repositories for the current user. CI/lock uses the hosted TestifySec
platform automatically, exchanges the current CI/lock session or registered
workflow identity for a short-lived Fulcio certificate, and always requires an
RFC 3161 timestamp from the platform TSA. Private installations use the same
protocol against their configured TestifySec appliance.`,
		Example: `  # Configure only the current repository (default)
  cilock git configure

  # Configure every repository for the current user
  cilock git configure --global

  git commit -S -m "feat: signed by CI/lock"
  git tag -s v1.2.3 -m "v1.2.3"
  git verify-commit HEAD
  git verify-tag v1.2.3`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			scope := "--local"
			if global {
				scope = "--global"
			} else if err := runGitConfig(cmd.Context(), "rev-parse", "--git-dir"); err != nil {
				return fmt.Errorf("configure current repository (use --global outside a repository): %w", err)
			}
			settings := [][2]string{
				{"gpg.format", "x509"},
				{"gpg.x509.program", binaryName},
				{"commit.gpgsign", gitConfigTrue},
				{"tag.gpgsign", gitConfigTrue},
			}
			for _, setting := range settings {
				if err := runGitConfig(cmd.Context(), "config", scope, setting[0], setting[1]); err != nil {
					return fmt.Errorf("set %s: %w", setting[0], err)
				}
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Git signing configured (%s): commits and annotated tags use CI/lock with Fulcio + mandatory TSA.\n", scope[2:])
			return err
		},
	}
	cmd.Flags().BoolVar(&global, "global", false, "Configure the current user's global Git settings instead of this repository")
	return cmd
}
