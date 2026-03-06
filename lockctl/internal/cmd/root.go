package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lockctl",
	Short: "Rookery development tooling",
	Long:  "lockctl — local CI, testing, and development tooling for the Rookery monorepo.",
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		root, err := findRepoRoot()
		if err != nil {
			return fmt.Errorf("not in a git repository: %w", err)
		}
		return os.Chdir(root)
	},
	SilenceUsage: true,
}

func findRepoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Execute runs the root command and returns an error if any subcommand fails.
func Execute() error {
	return rootCmd.Execute()
}
