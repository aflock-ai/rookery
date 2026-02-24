package cmd

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

var tidyCmd = &cobra.Command{
	Use:   "tidy",
	Short: "Tidy all module dependencies",
	Long: `Run go mod tidy on all modules in the workspace.

Runs in parallel with limited concurrency for speed.

Examples:
  lockctl tidy            # Tidy all modules
  lockctl tidy -m cilock  # Tidy only cilock module`,
	RunE: runTidy,
}

func init() {
	rootCmd.AddCommand(tidyCmd)
	tidyCmd.Flags().StringP("module", "m", "", "Tidy only a specific module")
}

func runTidy(cmd *cobra.Command, _ []string) error {
	module, _ := cmd.Flags().GetString("module")
	start := time.Now()

	mods, err := findGoMods()
	if err != nil {
		return err
	}

	if module != "" {
		modPath := filepath.Join(module, "go.mod")
		found := false
		for _, m := range mods {
			if m == modPath {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("module %s not found", module)
		}
		mods = []string{modPath}
	}

	fmt.Printf("Tidying %d module(s)...\n", len(mods))

	var failures []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for _, mod := range mods {
		dir := filepath.Dir(mod)
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := exec.Command("go", "mod", "tidy")
			c.Dir = d
			if out, err := c.CombinedOutput(); err != nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("%s: %s", d, string(out)))
				mu.Unlock()
				fmt.Printf("  ✗ %s\n", d)
			} else {
				fmt.Printf("  ✓ %s\n", d)
			}
		}(dir)
	}
	wg.Wait()

	if len(failures) > 0 {
		fmt.Printf("\n%d module(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Println(f)
		}
		return fmt.Errorf("%d modules failed go mod tidy", len(failures))
	}

	fmt.Printf("\nAll modules tidied (%s)\n", time.Since(start).Round(time.Millisecond))
	return nil
}
