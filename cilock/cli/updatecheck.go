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
	"os"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/rookery/cilock/internal/updatecheck"
)

// skipVersionCheckEnv disables the daily new-version check entirely —
// documented in the root --help for air-gapped / locked-down environments.
const skipVersionCheckEnv = "CILOCK_SKIP_VERSION_CHECK"

// startUpdateCheck wires the environment into the updatecheck package and
// kicks off the background check. It returns nil (never notify) for opted-out
// runs, shell-completion invocations, and unstamped/pre-release builds.
// The base URL honors CILOCK_DIST_BASE, the same override install.sh uses.
//
// Env access is direct os.Getenv by design: the cilock module does not use
// Viper anywhere (see CILOCK_NO_EMBEDDED_TRUST in verify.go and the CILOCK_*
// reads in run.go for the established pattern) — the Viper-only registry rule
// applies to judge-api configuration, not to this standalone CLI module.
func startUpdateCheck(args []string) *updatecheck.Check {
	if v := os.Getenv(skipVersionCheckEnv); v == "1" || strings.EqualFold(v, "true") {
		return nil
	}
	if skipUpdateCheckForArgs(args) {
		return nil
	}

	base := strings.TrimRight(os.Getenv("CILOCK_DIST_BASE"), "/")
	if base == "" {
		base = "https://cilock.dev"
	}
	cacheDir := ""
	if d, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(d, "cilock")
	}
	return updatecheck.Start(updatecheck.Config{
		Tool:          "cilock",
		Current:       Version,
		ManifestURL:   base + "/dl/manifest.json",
		CacheDir:      cacheDir,
		UpdateCommand: "curl -fsSL " + base + "/install.sh | bash",
		SkipEnvVar:    skipVersionCheckEnv,
		IsTTY:         isCharDevice(os.Stderr),
		InCI:          os.Getenv("CI") != "",
	})
}

// skipUpdateCheckForArgs suppresses the check for shell-completion plumbing,
// where any stray stderr output pollutes the completion machinery, and for
// bare help rendering.
//
// Cobra permits persistent flags BEFORE the subcommand (`cilock --log-level
// debug completion bash`), so this scans every bare (non-flag) token rather
// than just args[0]. Scanning stops at "--": later tokens are the wrapped
// command's argv (`cilock run -- make ...`), never cobra subcommands. The
// scan is deliberately conservative — a flag VALUE that happens to equal a
// sensitive word suppresses a nicety, never breaks a command.
func skipUpdateCheckForArgs(args []string) bool {
	sawCommandWord := false
	for _, a := range args {
		if a == "--" {
			break
		}
		// Help flags anywhere before "--" mean help rendering, not real work
		// (`cilock verify --help`) — checked before the generic flag skip.
		switch a {
		case "--help", "-h", "--" + helpAdvancedFlag:
			return true
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		switch a {
		case "completion", cobraCompleteCmd, cobraCompleteNoDescCmd, "help":
			return true
		}
		sawCommandWord = true
	}
	// No bare token at all (bare `cilock`): help rendering only.
	return !sawCommandWord
}

// Cobra's hidden completion entry points (cobra.ShellCompRequestCmd /
// ShellCompNoDescRequestCmd), inlined to avoid importing cobra here.
const (
	cobraCompleteCmd       = "__complete"
	cobraCompleteNoDescCmd = "__completeNoDesc"
)

// isCharDevice reports whether f is a terminal, stdlib-only (no isatty dep).
func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
