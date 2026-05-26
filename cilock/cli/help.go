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

package cli

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// helpAdvancedFlag is the opt-in to the full flag listing. Default help
// shows only the essential flags for a command; the long tail
// (attestor/signer/cache/env tuning) is collapsed behind this flag so an
// agent reading --help isn't forced to page through ~70 knobs it will
// never set.
const helpAdvancedFlag = "help-advanced"

// essentialFlags lists, per command name, the flags that belong in the
// default (concise) help view. Everything else for that command is
// treated as advanced. Commands absent from this map show all of their
// local flags (they're small enough not to need curation).
//
// Keep this in sync with the flags each command actually registers — the
// examples_test.go harness parses every documented example, and a stale
// name here only affects rendering, but a stale example fails CI.
var essentialFlags = map[string][]string{
	"run": {
		"step", "attestations", "outfile", "signer-file-key-path",
		"trace", "capture-mode", "enable-archivista", "workingdir", "workload",
	},
	"verify": {
		"policy", "publickey", "attestations", "artifactfile", "bundle",
		"enable-archivista", "platform-url", "directory-path",
	},
	"attest": {
		"step", "attestations", "outfile", "signer-file-key-path", "subjects",
	},
	"sign": {
		"signer-file-key-path", "outfile", "datatype",
	},
	"prove": {
		"file", "outfile", "signer-file-key-path",
	},
	"prove-chain": {
		"consumed", "source-envelope", "source-sidecar", "source-step", "outfile",
	},
}

// advancedPrefixes marks whole families of flags as advanced regardless
// of command. A flag explicitly listed in essentialFlags still wins.
var advancedPrefixes = []string{
	"attestor-", "signer-", "cache-", "env-", "archivista-",
	"policy-ca", "policy-fulcio-", "policy-timestamp", "verifier-",
	"debug-",
}

// isEssentialFlag reports whether a flag should appear in the concise
// (default) help view for the named command.
func isEssentialFlag(cmdName, flagName string) bool {
	if list, ok := essentialFlags[cmdName]; ok {
		if slices.Contains(list, flagName) {
			return true
		}
		// Command has a curated list and this flag isn't on it: advanced,
		// unless it's a short universal like help (handled by caller).
		return false
	}
	// No curated list for this command. Default to essential unless the
	// flag is in an advanced family.
	for _, p := range advancedPrefixes {
		if strings.HasPrefix(flagName, p) {
			return false
		}
	}
	return true
}

// wantAdvancedHelp scans the raw args for the opt-in. We scan os.Args
// rather than reading the parsed flag because the help func also runs on
// the -h/--help short-circuit path, where PersistentPreRunE (and thus
// flag binding for our purposes) is bypassed. Scanning is deterministic
// and order-independent.
func wantAdvancedHelp(args []string) bool {
	return slices.Contains(args, "--"+helpAdvancedFlag)
}

// conciseHelpFunc is installed on the root command and inherited by every
// subcommand. It renders: description, usage, examples, subcommands,
// essential flags (or all flags when --help-advanced is set), global
// flags, and the footer.
func conciseHelpFunc(cmd *cobra.Command, _ []string) {
	out := cmd.OutOrStdout()
	advanced := wantAdvancedHelp(os.Args)

	if long := strings.TrimSpace(cmd.Long); long != "" {
		fmt.Fprintln(out, long)
	} else if cmd.Short != "" {
		fmt.Fprintln(out, cmd.Short)
	}

	fmt.Fprintf(out, "\nUsage:\n  %s\n", cmd.UseLine())
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintf(out, "  %s [command]\n", cmd.CommandPath())
	}

	if len(cmd.Aliases) > 0 {
		fmt.Fprintf(out, "\nAliases:\n  %s\n", strings.Join(append([]string{cmd.Name()}, cmd.Aliases...), ", "))
	}

	// Examples are authored with their own (2-space) indentation, matching
	// cobra's default rendering — print them verbatim, only trimming the
	// surrounding blank lines.
	if ex := strings.Trim(cmd.Example, "\n"); strings.TrimSpace(ex) != "" {
		fmt.Fprintf(out, "\nExamples:\n%s\n", ex)
	}

	if cmd.HasAvailableSubCommands() {
		fmt.Fprintln(out, "\nAvailable Commands:")
		writeSubcommands(out, cmd)
	}

	writeFlagSections(out, cmd, advanced)

	if inherited := cmd.InheritedFlags().FlagUsages(); strings.TrimSpace(inherited) != "" {
		fmt.Fprintf(out, "\nGlobal Flags:\n%s", inherited)
	}

	if cmd.HasAvailableSubCommands() {
		fmt.Fprintf(out, "\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
	}
}

// writeFlagSections prints the local flags. In concise mode it prints the
// essential subset and a one-line pointer to --help-advanced for the
// rest; in advanced mode it prints everything.
func writeFlagSections(out io.Writer, cmd *cobra.Command, advanced bool) {
	local := cmd.LocalFlags()
	if !local.HasAvailableFlags() {
		return
	}

	if advanced {
		fmt.Fprintf(out, "\nFlags:\n%s", local.FlagUsages())
		return
	}

	essential := pflag.NewFlagSet("essential", pflag.ContinueOnError)
	advancedCount := 0
	local.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		if f.Name == "help" || isEssentialFlag(cmd.Name(), f.Name) {
			essential.AddFlag(f)
			return
		}
		advancedCount++
	})

	if usages := essential.FlagUsages(); strings.TrimSpace(usages) != "" {
		fmt.Fprintf(out, "\nFlags:\n%s", usages)
	}

	if advancedCount > 0 {
		fmt.Fprintf(out,
			"\n%d advanced flag(s) hidden (signing backends, attestor tuning, cache, env).\n"+
				"  See all:  %s --%s\n",
			advancedCount, cmd.CommandPath(), helpAdvancedFlag)
	}
}

// writeSubcommands prints the available subcommands, aligned, mirroring
// cobra's default layout.
func writeSubcommands(out io.Writer, cmd *cobra.Command) {
	width := 0
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() {
			continue
		}
		if len(c.Name()) > width {
			width = len(c.Name())
		}
	}
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() {
			continue
		}
		fmt.Fprintf(out, "  %-*s  %s\n", width, c.Name(), c.Short)
	}
}
