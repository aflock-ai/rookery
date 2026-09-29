// Copyright 2025 The Aflock Authors
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
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/keyguard"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/cilock/internal/telemetry"
	"github.com/spf13/cobra"
)

// binaryName is the program's own name. It is the cobra root's Use (so it
// drives every usage string), the cache-directory name, the update-check tool
// id, and the program git is told to invoke for x509 signing — all of which
// must agree, because a user who renames the binary breaks the git config and
// a mismatched cache dir silently re-downloads the update manifest.
const binaryName = "cilock"

// errHelpAdvanced is returned from PersistentPreRunE when the user passed
// --help-advanced (without -h). It signals "help has been printed; stop
// without running the command and without treating this as a failure".
// Execute recognizes it and exits 0.
var errHelpAdvanced = errors.New("help requested via --help-advanced")

func New() *cobra.Command {
	ro := &options.RootOptions{}
	var cpuProfileFile *os.File
	logger := newLogger()

	cmd := &cobra.Command{
		Use:   binaryName,
		Short: "Collect and verify attestations about your build environments",
		Long: `Collect and verify attestations about your build environments.

cilock checks cilock.dev at most once a day for a newer release and prints a
notice when one exists (never prompting, never blocking, never changing exit
codes). Set CILOCK_SKIP_VERSION_CHECK=1 to disable the check, e.g. in
air-gapped environments.

Set CILOCK_STATE_DIR to an existing canonical absolute 0700 directory to isolate
Cilock human-session and agent-credential stores without changing HOME. Explicit
state disables shared-session migration and jctl/keychain fallback, even when
the path is invalid. An invalid path fails; it never selects the default store.
Child Cilock processes (including Git signing) inherit this environment option.
The directory is credential state, not a general filesystem or network sandbox.`,
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// `<cmd> --help-advanced` (without -h) parses normally and would
			// otherwise fall through to RunE. Intercept it here, render the
			// full help, and return the sentinel so Execute stops cleanly
			// (exit 0) instead of running the command.
			if adv, _ := cmd.Flags().GetBool(helpAdvancedFlag); adv {
				if err := cmd.Help(); err != nil {
					return err
				}
				cmd.SilenceUsage = true
				return errHelpAdvanced
			}
			return preRoot(cmd, ro, logger, &cpuProfileFile)
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			postRoot(ro, logger, cpuProfileFile)
			// Best-effort cross-property usage telemetry. No-op unless the user is
			// authenticated to a platform (see internal/telemetry); the platform
			// session identity (Email) is the join key linking this CLI run to the
			// same user's cilock.dev / testifysec.com web activity in the hub.
			// PersistentPostRun only fires on a successful run, so outcome=success.
			telemetry.Report(cmd.Name(), Version, "success")
		},
	}

	log.SetLogger(logger)

	ro.AddFlags(cmd)
	cmd.PersistentFlags().Bool(helpAdvancedFlag, false, "Show the full flag listing, including advanced/rarely-used flags")
	_ = cmd.PersistentFlags().MarkHidden(helpAdvancedFlag)
	cmd.SetHelpFunc(conciseHelpFunc)
	cmd.AddCommand(LoginCmd())
	cmd.AddCommand(EnrollCmd())
	cmd.AddCommand(AgentCmd())
	cmd.AddCommand(LogoutCmd())
	cmd.AddCommand(WhoamiCmd())
	cmd.AddCommand(UseCmd())
	cmd.AddCommand(TrustCmd())
	cmd.AddCommand(DoctorCmd())
	cmd.AddCommand(SignCmd())
	cmd.AddCommand(VerifyCmd())
	cmd.AddCommand(VerifyBundleCmd())
	cmd.AddCommand(RunCmd())
	cmd.AddCommand(AttestCmd())
	cmd.AddCommand(CompletionCmd())
	cmd.AddCommand(VersionCmd())
	cmd.AddCommand(AttestorsCmd())
	cmd.AddCommand(PolicyCmd())
	cmd.AddCommand(LicenseCmd())
	cmd.AddCommand(KeyidCmd())
	cmd.AddCommand(BundleCmd())
	cmd.AddCommand(FetchCmd())
	cmd.AddCommand(PlanCmd())
	cmd.AddCommand(ToolsCmd())
	cmd.AddCommand(GetCmd())
	cmd.AddCommand(GitCmd())
	cmd.AddCommand(PushgateCmd())
	cmd.AddCommand(SkillCmd())
	return cmd
}

func Execute() {
	// Best-effort new-version check: runs concurrently with the command and
	// reports (stderr only) after the real output. It can neither prompt nor
	// change the exit code — see internal/updatecheck.
	upd := startUpdateCheck(os.Args[1:])
	err := New().Execute()
	failed := err != nil && !errors.Is(err, errHelpAdvanced)
	if failed {
		// Log the command's real error BEFORE waiting on / printing the
		// update notice, so a failure is never delayed or visually buried
		// by version-check output.
		reportCommandError(err, func(line string) { log.Error(line) }, os.Stderr)
	}
	if notice := upd.Notice(); notice != "" {
		fmt.Fprintln(os.Stderr, notice) //nolint:gosec // G705: CLI notice to stderr, not an HTTP/HTML sink; every interpolated part is semver-validated or constant.
	}
	if failed {
		// A policy verify distinguishes a denial (1) from a verification that
		// could not be made (2); every other failure exits 1.
		var coded interface{ ExitCode() int }
		if errors.As(err, &coded) {
			os.Exit(coded.ExitCode())
		}
		os.Exit(1)
	}
}

// reportCommandError writes a command failure to the terminal.
//
// Most cilock errors are one line and go through the logger, which stamps them
// level=error like every other failure. But a good number are structured —
// the attestation-size refusal lists the largest attestors with a remedy for
// each, and upload rejection, CI-trust registration and subject-candidate
// errors all end in an indented block of what to do next. logrus quotes the
// whole message, so a multi-line error arrives as one line with literal \n in
// it, which is the one rendering an operator cannot read. Since the block IS
// the message's value, the first line goes through the logger and the rest is
// written raw, unchanged and in order.
//
// logf and raw are injected so the split is testable without capturing the
// process's stderr; production passes log.Error and os.Stderr.
func reportCommandError(err error, logf func(string), raw io.Writer) {
	first, rest, found := strings.Cut(err.Error(), "\n")
	logf(first)
	if !found {
		return
	}
	// Best effort: stderr is already the failure channel, and a write error
	// here has nowhere left to be reported.
	_, _ = fmt.Fprintln(raw, rest)
}

func preRoot(cmd *cobra.Command, ro *options.RootOptions, logger *logrusLogger, cpuProfileFile **os.File) error {
	// Harden the process against extraction of in-memory secrets (the signing
	// key) by a same-UID local attacker — non-forgeable-provenance requires the
	// key to be unextractable while live. Applied as early as possible, before
	// any key is loaded, and process-wide. No-op on non-Linux dev machines.
	if st := keyguard.Protect(); st.Applied {
		log.Debugf("keyguard: process hardened (dumpable=%v yama=%d)", st.Dumpable, st.YamaPtraceScope)
	}

	if err := logger.SetLevel(ro.LogLevel); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	// Opt in to the #6266 policy-verification hardening (ENFORCE by default,
	// #6454) before any command logic can load, validate, or verify a policy.
	// The flag lives on the root persistent flag set; the executing subcommand
	// parses the same *pflag.Flag instance, so Changed is read there.
	mode := options.ResolveString(ro.PolicyHardening,
		cmd.Root().PersistentFlags().Changed(policyHardeningFlag),
		policyHardeningEnv, policyHardeningEnforce)
	if err := applyPolicyHardening(mode); err != nil {
		return err
	}

	if len(ro.CpuProfileFile) > 0 {
		f, err := os.Create(ro.CpuProfileFile)
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}
		*cpuProfileFile = f

		if err = pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("could not start CPU profile: %w", err)
		}
	}

	return nil
}

func postRoot(ro *options.RootOptions, logger *logrusLogger, cpuProfileFile *os.File) {
	if cpuProfileFile != nil {
		pprof.StopCPUProfile()
		if err := cpuProfileFile.Close(); err != nil {
			logger.l.Errorf("could not close cpu profile file: %v", err)
		}
	}

	if len(ro.MemProfileFile) > 0 {
		memProfileFile, err := os.Create(ro.MemProfileFile)
		if err != nil {
			logger.l.Errorf("could not create memory profile file: %v", err)
			return
		}

		defer func() {
			if err := memProfileFile.Close(); err != nil {
				logger.l.Errorf("failed to write memory profile to disk: %v", err)
			}
		}()

		runtime.GC()
		if err := pprof.WriteHeapProfile(memProfileFile); err != nil {
			logger.l.Errorf("could not write memory profile: %v", err)
		}
	}
}

func loadOutfile(outFilePath string) (*os.File, error) {
	if outFilePath == "" {
		return os.Stdout, nil
	}

	out, err := os.Create(outFilePath) //nolint:gosec // G304: outFilePath is from CLI flags
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	return out, nil
}

// closeOutfile closes the file if it is not stdout. Callers should use this
// instead of directly closing the return value of loadOutfile to avoid
// accidentally closing the process stdout descriptor. (Security: closing
// stdout can cause subsequent writes to go to a re-opened fd, potentially
// leaking data to an unrelated file descriptor.)
func closeOutfile(f *os.File) {
	if f == nil || f == os.Stdout {
		return
	}
	if err := f.Close(); err != nil {
		log.Errorf("failed to write result to disk: %v", err)
	}
}
