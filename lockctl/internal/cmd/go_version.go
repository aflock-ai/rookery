package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var goVersionCmd = &cobra.Command{
	Use:   "go-version",
	Short: "Check or set Go version across all modules",
}

var goVersionCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Verify Go version consistency",
	Long: `Check that .go-version, go.work, and all go.mod files use the same Go version.

Exits non-zero if any mismatches are found.
Use --fix to auto-repair inconsistencies.`,
	RunE: runGoVersionCheckCmd,
}

var goVersionSetCmd = &cobra.Command{
	Use:   "set <version>",
	Short: "Set Go version everywhere",
	Long: `Update .go-version and propagate to go.work and all go.mod files.

Example:
  lockctl go-version set 1.26.0`,
	Args: cobra.ExactArgs(1),
	RunE: runGoVersionSetCmd,
}

func init() {
	rootCmd.AddCommand(goVersionCmd)
	goVersionCmd.AddCommand(goVersionCheckCmd)
	goVersionCmd.AddCommand(goVersionSetCmd)

	goVersionCheckCmd.Flags().Bool("fix", false, "Auto-fix inconsistencies")
}

func runGoVersionCheckCmd(cmd *cobra.Command, _ []string) error { //nolint:gocognit // orchestrates version check across workspace files
	fix, _ := cmd.Flags().GetBool("fix")

	expected, err := readGoVersion()
	if err != nil {
		return err
	}

	fmt.Printf("Expected Go version: %s\n\n", expected)

	goDirective := regexp.MustCompile(`(?m)^go\s+(\S+)`)
	var mismatches []string

	// Check go.work
	if data, err := os.ReadFile("go.work"); err == nil { //nolint:nestif // checking go.work version requires nested conditionals
		re := regexp.MustCompile(`^go\s+(\S+)`)
		if m := re.FindSubmatch(data); m != nil {
			ver := string(m[1])
			if ver != expected {
				if fix {
					updated := re.ReplaceAll(data, []byte("go "+expected))
					_ = os.WriteFile("go.work", updated, 0644) //nolint:gosec // G306: go.work is not sensitive, 0644 is appropriate
					fmt.Printf("  fixed go.work: %s -> %s\n", ver, expected)
				} else {
					mismatches = append(mismatches, fmt.Sprintf("go.work: %s", ver))
				}
			}
		}
	}

	// Check all go.mod files
	mods, _ := findGoMods()
	for _, mod := range mods {
		data, err := os.ReadFile(mod) //nolint:gosec // G304: mod paths come from filesystem walk, not user input
		if err != nil {
			continue
		}
		if m := goDirective.FindSubmatch(data); m != nil { //nolint:nestif // checking go.mod version requires nested conditionals
			ver := string(m[1])
			if ver != expected {
				if fix {
					updated := goDirective.ReplaceAll(data, []byte("go "+expected))
					_ = os.WriteFile(mod, updated, 0644) //nolint:gosec // G306: go.mod is not sensitive, 0644 is appropriate
					fmt.Printf("  fixed %s: %s -> %s\n", mod, ver, expected)
				} else {
					mismatches = append(mismatches, fmt.Sprintf("%s: %s", mod, ver))
				}
			}
		}
	}

	if len(mismatches) > 0 {
		fmt.Println("Mismatches found:")
		for _, m := range mismatches {
			fmt.Printf("  ✗ %s\n", m)
		}
		fmt.Printf("\nRun 'lockctl go-version check --fix' to auto-repair\n")
		return fmt.Errorf("%d version mismatches found", len(mismatches))
	}

	if fix {
		fmt.Println("All inconsistencies fixed")
	} else {
		fmt.Println("All Go versions consistent")
	}
	return nil
}

func runGoVersionSetCmd(_ *cobra.Command, args []string) error { //nolint:gocognit,gocyclo // orchestrates version set across workspace files
	version := args[0]

	if !regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`).MatchString(version) {
		return fmt.Errorf("invalid version format: %s (expected X.Y or X.Y.Z)", version)
	}

	fmt.Printf("Setting Go version to %s...\n\n", version)

	// Update .go-version
	if err := os.WriteFile(".go-version", []byte(version+"\n"), 0644); err != nil { //nolint:gosec // G306: .go-version is not sensitive, 0644 is appropriate
		return fmt.Errorf("writing .go-version: %w", err)
	}
	fmt.Println("  ✓ .go-version")

	// Update go.work
	goDirective := regexp.MustCompile(`(?m)^go\s+\S+`)
	if data, err := os.ReadFile("go.work"); err == nil {
		updated := goDirective.ReplaceAll(data, []byte("go "+version))
		if err := os.WriteFile("go.work", updated, 0644); err == nil { //nolint:gosec // G306: go.work is not sensitive, 0644 is appropriate
			fmt.Println("  ✓ go.work")
		}
	}

	// Update all go.mod files
	mods, _ := findGoMods()
	for _, mod := range mods {
		data, err := os.ReadFile(mod) //nolint:gosec // G304: mod paths come from filesystem walk, not user input
		if err != nil {
			continue
		}
		updated := goDirective.ReplaceAll(data, []byte("go "+version))
		if err := os.WriteFile(mod, updated, 0644); err == nil { //nolint:gosec // G306: go.mod is not sensitive, 0644 is appropriate
			fmt.Printf("  ✓ %s\n", mod)
		}
	}

	// Also check workflows for hardcoded versions
	fmt.Println("\nChecking workflows...")
	workflowDir := ".github/workflows"
	entries, err := os.ReadDir(workflowDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
				continue
			}
			path := filepath.Join(workflowDir, e.Name())
			data, err := os.ReadFile(path) //nolint:gosec // G304: path is constructed from os.ReadDir, not user input
			if err != nil {
				continue
			}
			content := string(data)
			if strings.Contains(content, "go-version:") && !strings.Contains(content, "go-version-file:") {
				fmt.Printf("  ⚠ %s has hardcoded go-version — consider using go-version-file\n", path)
			}
		}
	}

	fmt.Printf("\n✓ Go version set to %s everywhere\n", version)
	return nil
}
