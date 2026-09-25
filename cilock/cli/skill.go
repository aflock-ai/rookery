// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/cilock/agentplugin"
	"github.com/spf13/cobra"
)

// SkillCmd serves the Pushgate agent skill embedded in this binary. Every
// subcommand is local: no network call, no child process. The group also
// replaces the root's post-run hook, so these commands send no usage
// telemetry, and skipUpdateCheckForArgs skips the release check for them.
func SkillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skill",
		Short: "Install the Pushgate skill for your coding agent (Claude Code, Codex, opencode)",
		Long: `The Pushgate skill teaches a coding agent the cilock and Pushgate loop:
enroll the agent, produce signed evidence, act on a refusal, and draft a policy
that a human signs. It ships inside this binary, so it matches this cilock's
commands.

The skill is deliberately thin. Flags, predicate fields and rule templates stay
in cilock's own help and output, where they cannot drift from the binary.

Claude Code users can also install it as a plugin:
  /plugin marketplace add aflock-ai/rookery
  /plugin install pushgate@rookery
Use one or the other, not both, or the skill loads twice.`,
		// No telemetry for a local file operation.
		PersistentPostRun: func(*cobra.Command, []string) {},
	}
	cmd.AddCommand(skillInstallCmd(), skillShowCmd(), skillPathCmd())
	return cmd
}

type skillTargetFlags struct {
	agent string
	scope string
	dir   string
}

func (f *skillTargetFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.agent, "agent", "auto", "Agent to install for: claude, codex, opencode, or auto (detect from the environment)")
	cmd.Flags().StringVar(&f.scope, "scope", "user", "user (every project on this machine) or project (this repository only)")
	cmd.Flags().StringVar(&f.dir, "dir", "", "Install into <dir>/pushgate instead of the agent's skills directory")
}

func (f *skillTargetFlags) resolve() (agentplugin.Target, error) {
	agent, err := agentplugin.ParseAgent(f.agent)
	if err != nil {
		return agentplugin.Target{}, err
	}
	scope, err := agentplugin.ParseScope(f.scope)
	if err != nil {
		return agentplugin.Target{}, err
	}
	if agent == "" && f.dir == "" {
		if agent, err = agentplugin.DetectAgent(os.Getenv); err != nil {
			return agentplugin.Target{}, err
		}
	}
	home, _ := os.UserHomeDir()
	wd, _ := os.Getwd()
	return agentplugin.ResolveTarget(agent, scope, f.dir, agentplugin.Env{Home: home, WorkDir: wd, Getenv: os.Getenv})
}

func skillInstallCmd() *cobra.Command {
	var flags skillTargetFlags
	var force bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Write the Pushgate skill where your agent discovers skills",
		Long: `Write the Pushgate skill where the chosen agent discovers skills:

  claude    user: ~/.claude/skills/pushgate          project: .claude/skills/pushgate
  codex     user: ~/.agents/skills/pushgate          project: .agents/skills/pushgate
  opencode  user: ~/.config/opencode/skills/pushgate project: .opencode/skills/pushgate

Project scope installs at the root of the Git repository you are in. opencode
also reads the claude and codex locations, so one install covers it.

Re-running is safe: files that already match are left alone. cilock records a
SHA-256 digest of each file it writes (.cilock-skill.json) and replaces only
files that still match that digest. It refuses to overwrite a file it did not
write, or one edited since, unless you pass --force. It writes only inside the
skill directory and never through a symbolic link.`,
		Example: `  cilock skill install                     # detect the agent, install for this user
  cilock skill install --agent codex --scope project
  cilock skill install --dir ./vendor-skills`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := flags.resolve()
			if err != nil {
				return err
			}
			results, err := agentplugin.Install(target, force, Version)
			var conflict *agentplugin.ConflictError
			if errors.As(err, &conflict) {
				return fmt.Errorf("%w\nNothing was written. `cilock skill show` prints the skill, if you want to compare it with the existing files", err)
			}
			if err != nil {
				printSkillResults(cmd.OutOrStdout(), target, results)
				return err
			}
			out := cmd.OutOrStdout()
			printSkillResults(out, target, results)
			_, _ = fmt.Fprintf(out, "\n%s\n", target.Rule)
			for _, also := range target.AlsoReadBy {
				_, _ = fmt.Fprintf(out, "%s also reads this directory; do not install a second copy for it.\n", also.DisplayName())
			}
			_, _ = fmt.Fprintf(out, "\nNext: start a new %s session so it loads the skill, then ask it to push through Pushgate.\nThe loop starts with `cilock enroll agent --repo <owner/name>`, which your human approves in the browser.\n", sessionName(target.Agent))
			return nil
		},
	}
	flags.add(cmd)
	cmd.Flags().BoolVar(&force, "force", false, "Replace files cilock did not write, or that were edited since")
	return cmd
}

func sessionName(a agentplugin.Agent) string {
	if a == agentplugin.AgentCustom {
		return agentCommandName
	}
	return a.DisplayName()
}

func printSkillResults(out io.Writer, target agentplugin.Target, results []agentplugin.Result) {
	scope := string(target.Scope) + " scope"
	if target.Explicit {
		scope = "--dir"
	}
	_, _ = fmt.Fprintf(out, "Pushgate skill for %s (%s): %s\n", target.Agent.DisplayName(), scope, target.Dir)
	for _, r := range results {
		note := ""
		if r.Note != "" {
			note = "  (" + r.Note + ")"
		}
		_, _ = fmt.Fprintf(out, "  %-9s %s%s\n", r.Action, r.Path, note)
	}
}

func skillShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [file]",
		Short: "Print the embedded skill (SKILL.md, or one of its reference files)",
		Long: `Print the Pushgate skill embedded in this cilock to stdout. With no argument it
prints SKILL.md; name a file, such as references/refusals.md, to print that.
This is the copy that matches this binary's commands.`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := "SKILL.md"
			if len(args) == 1 {
				name = strings.TrimPrefix(args[0], "./")
			}
			data, err := agentplugin.ReadFile(name)
			if err != nil {
				files, ferr := agentplugin.Files()
				if ferr != nil {
					return ferr
				}
				names := make([]string, len(files))
				for i, f := range files {
					names[i] = f.Path
				}
				return fmt.Errorf("the skill has no file %q; it has: %s", name, strings.Join(names, ", "))
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func skillPathCmd() *cobra.Command {
	var flags skillTargetFlags
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Print where `cilock skill install` would write the skill, and whether it is there",
		Long: `Print the directory ` + "`cilock skill install`" + ` would write for the same flags, on
the first line by itself, followed by whether the skill is installed there and
the discovery rule that makes the agent find it. Writes nothing.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := flags.resolve()
			if err != nil {
				return err
			}
			state, err := agentplugin.Inspect(target)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintln(out, target.Dir)
			_, _ = fmt.Fprintf(out, "  %s for %s\n  %s\n", state, target.Agent.DisplayName(), target.Rule)
			if state != agentplugin.StateCurrent {
				_, _ = fmt.Fprintln(out, "  Run `cilock skill install` with the same flags to install or update it.")
			}
			return nil
		},
	}
	flags.add(cmd)
	return cmd
}
