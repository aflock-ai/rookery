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

package cmd

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ro := &options.RootOptions{}
	var cpuProfileFile *os.File
	logger := newLogger()

	cmd := &cobra.Command{
		Use:               "cilock",
		Short:             "Collect and verify attestations about your build environments",
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return preRoot(cmd, ro, logger, &cpuProfileFile)
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			postRoot(ro, logger, cpuProfileFile)
		},
	}

	log.SetLogger(logger)

	ro.AddFlags(cmd)
	cmd.AddCommand(SignCmd())
	cmd.AddCommand(VerifyCmd())
	cmd.AddCommand(RunCmd())
	cmd.AddCommand(CompletionCmd())
	cmd.AddCommand(VersionCmd())
	cmd.AddCommand(AttestorsCmd())
	cmd.AddCommand(PolicyCmd())
	return cmd
}

func Execute() {
	if err := New().Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func preRoot(cmd *cobra.Command, ro *options.RootOptions, logger *logrusLogger, cpuProfileFile **os.File) error {
	if err := logger.SetLevel(ro.LogLevel); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	if err := initConfig(cmd, ro); err != nil {
		return fmt.Errorf("config error: %w", err)
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
