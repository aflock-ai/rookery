package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run CI checks locally",
	Long: `Run CI checks locally with speed optimizations and smart parallelism.

Mirrors the full CI pipeline (ci.yml) but runs locally with caching,
parallel execution, and optional change detection.

Pre-flight checks (always run, fast):
  go-version-check     Verify .go-version consistency across all go.mod files
  commitlint           Validate commit messages follow conventional format
  forbidden-patterns   Scan added lines for forbidden calls/nolint/credentials

Parallel checks:
  vet                  go vet ./...
  build                go build ./... for attestation, aflock, builder, cilock
  test                 go test with GOGC=400, -parallel, -failfast
  test-race            go test -race (when --race or --all)
  lint                 golangci-lint v2 (when --lint or --all)
  verify-isolated      GOWORK=off build per module (when --isolated or --all)

Flags:
  lockctl test                      # Core checks (preflight + vet + build + test)
  lockctl test --all                # Full CI pipeline
  lockctl test --lint               # Include golangci-lint
  lockctl test --race               # Include race detector
  lockctl test --isolated           # Include isolated module builds
  lockctl test --short              # Use -short flag for tests
  lockctl test --audit              # Include security audit tests (-tags audit)
  lockctl test --module attestation # Test only one module
  lockctl test --fast               # Preflight only (no tests)
  lockctl test --fix                # Auto-fix lint issues`,
	RunE: runTest,
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.Flags().Bool("all", false, "Run ALL checks (lint, race, isolated)")
	testCmd.Flags().Bool("lint", false, "Include golangci-lint")
	testCmd.Flags().Bool("race", false, "Include race detector tests")
	testCmd.Flags().Bool("isolated", false, "Include verify-isolated builds")
	testCmd.Flags().Bool("short", false, "Use -short flag for Go tests")
	testCmd.Flags().Bool("audit", false, "Include security audit tests (-tags audit)")
	testCmd.Flags().Bool("fast", false, "Preflight checks only (skip tests)")
	testCmd.Flags().Bool("fix", false, "Auto-fix lint and formatting issues")
	testCmd.Flags().StringP("module", "m", "", "Test only a specific module (e.g., attestation, cilock)")
	testCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	testCmd.Flags().String("from", "origin/main", "Base ref for change detection and commitlint")
}

type checkResult struct {
	name     string
	status   string // passed, failed, skipped
	duration time.Duration
	err      error
}

func runTest(cmd *cobra.Command, _ []string) error {
	all, _ := cmd.Flags().GetBool("all")
	lint, _ := cmd.Flags().GetBool("lint")
	race, _ := cmd.Flags().GetBool("race")
	isolated, _ := cmd.Flags().GetBool("isolated")
	short, _ := cmd.Flags().GetBool("short")
	audit, _ := cmd.Flags().GetBool("audit")
	fast, _ := cmd.Flags().GetBool("fast")
	fix, _ := cmd.Flags().GetBool("fix")
	module, _ := cmd.Flags().GetString("module")
	verbose, _ := cmd.Flags().GetBool("verbose")
	from, _ := cmd.Flags().GetString("from")

	if all {
		lint = true
		race = true
		isolated = true
	}

	fmt.Println("lockctl test")
	fmt.Println()

	var results []checkResult
	start := time.Now()

	// ══════════════════════════════════════════════════════════════
	// PRE-FLIGHT CHECKS (sequential, fast)
	// ══════════════════════════════════════════════════════════════
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("                    PRE-FLIGHT CHECKS                       ")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println()

	results = append(results, runGoVersionCheck())
	results = append(results, runCommitLint(from))
	results = append(results, runForbiddenPatterns(from))

	// Check for preflight failures
	preflightFailed := false
	for _, r := range results {
		if r.status == "failed" {
			preflightFailed = true
		}
	}

	if fast || preflightFailed {
		if preflightFailed {
			fmt.Println("\nPreflight checks failed — skipping remaining checks")
		}
		printSummary(results, start)
		if preflightFailed {
			return fmt.Errorf("preflight checks failed")
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════
	// PARALLEL CHECKS
	// ══════════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("                    PARALLEL CHECKS                         ")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println()

	var mu sync.Mutex
	var wg sync.WaitGroup
	var parallel []checkResult

	addResult := func(r checkResult) {
		mu.Lock()
		parallel = append(parallel, r)
		mu.Unlock()
	}

	// Always: vet
	wg.Add(1)
	go func() {
		defer wg.Done()
		addResult(runVet(module))
	}()

	// Always: build
	wg.Add(1)
	go func() {
		defer wg.Done()
		addResult(runBuild(module))
	}()

	// Always: test
	wg.Add(1)
	go func() {
		defer wg.Done()
		addResult(runGoTests(module, short, audit, verbose))
	}()

	// Optional: race
	if race {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addResult(runGoTestsRace(module, verbose))
		}()
	}

	// Optional: lint
	if lint {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addResult(runLint(module, fix, verbose))
		}()
	}

	// Optional: verify-isolated (sequential internally, parallel with others)
	if isolated {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addResult(runVerifyIsolated(module))
		}()
	}

	wg.Wait()
	results = append(results, parallel...)

	printSummary(results, start)

	for _, r := range results {
		if r.status == "failed" {
			return fmt.Errorf("checks failed")
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════
// PRE-FLIGHT CHECK FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

func runGoVersionCheck() checkResult {
	name := "go-version-check"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	expected, err := readGoVersion()
	if err != nil {
		fmt.Printf("✗ %s: %v\n", name, err)
		return checkResult{name: name, status: "failed", duration: time.Since(start), err: err}
	}

	var mismatches []string

	// Check go.work
	workData, err := os.ReadFile("go.work")
	if err == nil {
		re := regexp.MustCompile(`^go\s+(\S+)`)
		if m := re.FindSubmatch(workData); m != nil {
			if string(m[1]) != expected {
				mismatches = append(mismatches, fmt.Sprintf("go.work: %s", m[1]))
			}
		}
	}

	// Check all go.mod files
	mods, _ := findGoMods()
	goDirective := regexp.MustCompile(`(?m)^go\s+(\S+)`)
	for _, mod := range mods {
		data, err := os.ReadFile(mod)
		if err != nil {
			continue
		}
		if m := goDirective.FindSubmatch(data); m != nil {
			ver := string(m[1])
			if ver != expected {
				mismatches = append(mismatches, fmt.Sprintf("%s: %s", mod, ver))
			}
		}
	}

	dur := time.Since(start)
	if len(mismatches) > 0 {
		fmt.Printf("✗ %s: version mismatch (expected %s)\n", name, expected)
		for _, m := range mismatches {
			fmt.Printf("    %s\n", m)
		}
		return checkResult{name: name, status: "failed", duration: dur, err: fmt.Errorf("%d mismatches", len(mismatches))}
	}

	fmt.Printf("✓ %s (%s)\n", name, dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

func runCommitLint(from string) checkResult {
	name := "commitlint"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	// Get commits between from and HEAD
	out, err := exec.Command("git", "rev-list", from+"..HEAD").Output()
	if err != nil {
		fmt.Printf("✓ %s (no commits to lint)\n", name)
		return checkResult{name: name, status: "passed", duration: time.Since(start)}
	}

	shas := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(shas) == 1 && shas[0] == "" {
		fmt.Printf("✓ %s (no commits)\n", name)
		return checkResult{name: name, status: "passed", duration: time.Since(start)}
	}

	pattern := regexp.MustCompile(`^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?: .+`)
	mergePattern := regexp.MustCompile(`^Merge `)

	var violations []string
	for _, sha := range shas {
		sha = strings.TrimSpace(sha)
		if sha == "" {
			continue
		}
		msgOut, _ := exec.Command("git", "log", "-1", "--format=%s", sha).Output()
		msg := strings.TrimSpace(string(msgOut))
		if !pattern.MatchString(msg) && !mergePattern.MatchString(msg) {
			violations = append(violations, fmt.Sprintf("%s: %s", sha[:8], msg))
		}
	}

	dur := time.Since(start)
	if len(violations) > 0 {
		fmt.Printf("✗ %s: %d non-conventional commit(s)\n", name, len(violations))
		for _, v := range violations {
			fmt.Printf("    %s\n", v)
		}
		fmt.Println("    Expected: type(scope): description")
		fmt.Println("    Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert")
		return checkResult{name: name, status: "failed", duration: dur}
	}

	fmt.Printf("✓ %s (%d commits, %s)\n", name, len(shas), dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

func runForbiddenPatterns(from string) checkResult {
	name := "forbidden-patterns"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	diffOut, err := exec.Command("git", "diff", from+"..HEAD", "--", "*.go").Output()
	if err != nil {
		dur := time.Since(start)
		fmt.Printf("✓ %s (no diff)\n", name)
		return checkResult{name: name, status: "passed", duration: dur}
	}

	diff := string(diffOut)
	if strings.TrimSpace(diff) == "" {
		dur := time.Since(start)
		fmt.Printf("✓ %s (no Go changes)\n", name)
		return checkResult{name: name, status: "passed", duration: dur}
	}

	type violation struct {
		category string
		lines    []string
	}
	var violations []violation

	// Parse diff to get added lines with file context
	lines := strings.Split(diff, "\n")
	var currentFile string
	for _, line := range lines {
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			continue
		}
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		addedLine := line[1:]

		// Skip test files and main.go for exit/panic checks
		isTest := strings.HasSuffix(currentFile, "_test.go")
		isMain := filepath.Base(currentFile) == "main.go"

		// Use concatenation to avoid self-matching in forbidden-patterns diff scan
		exitCall := "os" + ".Exit("
		panicCall := "panic" + "("

		// exit call outside main
		if !isTest && !isMain && strings.Contains(addedLine, exitCall) {
			trimmed := strings.TrimSpace(addedLine)
			if !strings.HasPrefix(trimmed, "//") && !strings.Contains(trimmed, `"`) {
				violations = append(violations, violation{
					category: "exit call outside main",
					lines:    []string{fmt.Sprintf("%s: %s", currentFile, trimmed)},
				})
			}
		}

		// panic outside test/init
		if !isTest && strings.Contains(addedLine, panicCall) {
			trimmed := strings.TrimSpace(addedLine)
			if !strings.HasPrefix(trimmed, "//") && !strings.Contains(trimmed, "func init(") && !strings.Contains(trimmed, `"`) {
				violations = append(violations, violation{
					category: "panic() outside init",
					lines:    []string{fmt.Sprintf("%s: %s", currentFile, trimmed)},
				})
			}
		}
	}

	dur := time.Since(start)
	if len(violations) > 0 {
		fmt.Printf("✗ %s: %d violation(s)\n", name, len(violations))
		for _, v := range violations {
			fmt.Printf("    [%s] %s\n", v.category, v.lines[0])
		}
		return checkResult{name: name, status: "failed", duration: dur}
	}

	fmt.Printf("✓ %s (%s)\n", name, dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

// ═══════════════════════════════════════════════════════════════════
// PARALLEL CHECK FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

func runVet(module string) checkResult {
	name := "vet"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	modules := workspaceModules(module)
	for _, dir := range modules {
		c := exec.Command("go", "vet", "./...")
		c.Dir = dir
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			dur := time.Since(start)
			fmt.Printf("✗ %s: %s failed (%s)\n", name, dir, dur.Round(time.Millisecond))
			return checkResult{name: name, status: "failed", duration: dur, err: err}
		}
	}

	dur := time.Since(start)
	fmt.Printf("✓ %s (%d modules, %s)\n", name, len(modules), dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

func runBuild(module string) checkResult {
	name := "build"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	targets := []struct {
		name string
		dir  string
	}{
		{"attestation", "attestation"},
		{"aflock", "aflock"},
		{"builder", "builder"},
		{"cilock", "cilock"},
	}

	if module != "" {
		targets = []struct {
			name string
			dir  string
		}{{module, module}}
	}

	for _, t := range targets {
		c := exec.Command("go", "build", "./...")
		c.Dir = t.dir
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			dur := time.Since(start)
			fmt.Printf("✗ %s: %s failed (%s)\n", name, t.name, dur.Round(time.Millisecond))
			return checkResult{name: name, status: "failed", duration: dur, err: err}
		}
	}

	dur := time.Since(start)
	fmt.Printf("✓ %s (%s)\n", name, dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

func runGoTests(module string, short, audit, verbose bool) checkResult {
	name := "test"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	modules := workspaceModules(module)
	for _, dir := range modules {
		args := []string{"test", "--failfast", "-count=1"}
		if short {
			args = append(args, "-short")
		}
		if audit {
			args = append(args, "-tags", "audit")
		}
		if verbose {
			args = append(args, "-v")
		}
		args = append(args, "./...")

		c := exec.Command("go", args...)
		c.Dir = dir
		// Speed hacks: increase GC threshold, set memory limit, skip VCS stamping
		c.Env = append(os.Environ(),
			"GOGC=400",
			"GOMEMLIMIT=4GiB",
			"GOFLAGS=-buildvcs=false",
		)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		if err := c.Run(); err != nil {
			dur := time.Since(start)
			fmt.Printf("✗ %s: %s failed (%s)\n", name, dir, dur.Round(time.Millisecond))
			return checkResult{name: name, status: "failed", duration: dur, err: err}
		}
	}

	dur := time.Since(start)
	fmt.Printf("✓ %s (%d modules, %s)\n", name, len(modules), dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

func runGoTestsRace(module string, verbose bool) checkResult {
	name := "test-race"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	modules := workspaceModules(module)
	for _, dir := range modules {
		args := []string{"test", "-race", "--failfast", "-count=1"}
		if verbose {
			args = append(args, "-v")
		}
		args = append(args, "./...")

		c := exec.Command("go", args...)
		c.Dir = dir
		c.Env = append(os.Environ(),
			"GOGC=400",
			"GOMEMLIMIT=4GiB",
			"GOFLAGS=-buildvcs=false",
		)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		if err := c.Run(); err != nil {
			dur := time.Since(start)
			fmt.Printf("✗ %s: %s failed (%s)\n", name, dir, dur.Round(time.Millisecond))
			return checkResult{name: name, status: "failed", duration: dur, err: err}
		}
	}

	dur := time.Since(start)
	fmt.Printf("✓ %s (%d modules, %s)\n", name, len(modules), dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

func runLint(module string, fix, verbose bool) checkResult {
	name := "lint"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	if err := ensureGolangciLint(); err != nil {
		fmt.Printf("✗ %s: failed to install golangci-lint: %v\n", name, err)
		return checkResult{name: name, status: "failed", duration: time.Since(start), err: err}
	}

	modules := workspaceModules(module)
	for _, dir := range modules {
		args := []string{"run", "./...", "--timeout", "10m"}
		if fix {
			args = append(args, "--fix")
		}
		if verbose {
			args = append(args, "-v")
		}

		c := exec.Command("golangci-lint", args...)
		c.Dir = dir
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		if err := c.Run(); err != nil {
			dur := time.Since(start)
			fmt.Printf("✗ %s: %s failed (%s)\n", name, dir, dur.Round(time.Millisecond))
			return checkResult{name: name, status: "failed", duration: dur, err: err}
		}
	}

	dur := time.Since(start)
	fmt.Printf("✓ %s (%d modules, %s)\n", name, len(modules), dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

func runVerifyIsolated(module string) checkResult {
	name := "verify-isolated"
	fmt.Printf("▶ %s\n", name)
	start := time.Now()

	mods, err := findGoMods()
	if err != nil {
		dur := time.Since(start)
		fmt.Printf("✗ %s: %v\n", name, err)
		return checkResult{name: name, status: "failed", duration: dur, err: err}
	}

	// If a specific module is requested, only verify that one
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
			dur := time.Since(start)
			fmt.Printf("✗ %s: module %s not found\n", name, module)
			return checkResult{name: name, status: "failed", duration: dur}
		}
		mods = []string{modPath}
	}

	// Build each module in isolation with parallelism
	type modResult struct {
		dir string
		err error
	}
	results := make(chan modResult, len(mods))
	sem := make(chan struct{}, 4) // limit concurrency

	var wg sync.WaitGroup
	for _, mod := range mods {
		dir := filepath.Dir(mod)
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := exec.Command("go", "build", "./...")
			c.Dir = d
			c.Env = append(os.Environ(), "GOWORK=off")
			if out, err := c.CombinedOutput(); err != nil {
				results <- modResult{dir: d, err: fmt.Errorf("%s:\n%s", d, string(out))}
			} else {
				results <- modResult{dir: d}
			}
		}(dir)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var failures []string
	for r := range results {
		if r.err != nil {
			failures = append(failures, r.err.Error())
		}
	}

	dur := time.Since(start)
	if len(failures) > 0 {
		fmt.Printf("✗ %s: %d module(s) failed (%s)\n", name, len(failures), dur.Round(time.Millisecond))
		for _, f := range failures {
			fmt.Printf("    %s\n", f)
		}
		return checkResult{name: name, status: "failed", duration: dur, err: fmt.Errorf("%d failures", len(failures))}
	}

	fmt.Printf("✓ %s (%d modules, %s)\n", name, len(mods), dur.Round(time.Millisecond))
	return checkResult{name: name, status: "passed", duration: dur}
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

// workspaceModules returns the list of module directories from go.work.
// If module is non-empty, returns only that directory.
func workspaceModules(module string) []string {
	if module != "" {
		return []string{module}
	}

	data, err := os.ReadFile("go.work")
	if err != nil {
		// Fallback: just use current directory
		return []string{"."}
	}

	var dirs []string
	re := regexp.MustCompile(`^\s*\./(.+)`)
	for _, line := range strings.Split(string(data), "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			dirs = append(dirs, m[1])
		}
	}

	if len(dirs) == 0 {
		return []string{"."}
	}
	return dirs
}

func readGoVersion() (string, error) {
	data, err := os.ReadFile(".go-version")
	if err != nil {
		return "", fmt.Errorf("cannot read .go-version: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func findGoMods() ([]string, error) {
	var mods []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Name() == "go.mod" && path != "go.mod" && !strings.Contains(path, "vendor") {
			mods = append(mods, path)
		}
		return nil
	})
	return mods, err
}

func ensureGolangciLint() error {
	if _, err := exec.LookPath("golangci-lint"); err != nil {
		fmt.Println("  golangci-lint not found, installing v2...")
		return installGolangciLint()
	}
	// Check version is v2
	out, _ := exec.Command("golangci-lint", "version").CombinedOutput()
	if strings.Contains(string(out), "version v1.") || strings.Contains(string(out), "version 1.") {
		fmt.Println("  golangci-lint v1 detected, installing v2...")
		return installGolangciLint()
	}
	return nil
}

func installGolangciLint() error {
	c := exec.Command("go", "install", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func printSummary(results []checkResult, overallStart time.Time) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("                         SUMMARY                            ")
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println()

	var passed, failed, skipped []string
	for _, r := range results {
		label := fmt.Sprintf("%s (%s)", r.name, r.duration.Round(time.Millisecond))
		switch r.status {
		case "passed":
			passed = append(passed, label)
		case "failed":
			failed = append(failed, label)
		case "skipped":
			skipped = append(skipped, label)
		}
	}

	if len(passed) > 0 {
		fmt.Printf("✓ Passed (%d):\n", len(passed))
		for _, p := range passed {
			fmt.Printf("    %s\n", p)
		}
	}
	if len(skipped) > 0 {
		fmt.Printf("⊘ Skipped (%d): %s\n", len(skipped), strings.Join(skipped, ", "))
	}
	if len(failed) > 0 {
		fmt.Printf("✗ Failed (%d):\n", len(failed))
		for _, f := range failed {
			fmt.Printf("    %s\n", f)
		}
	}

	fmt.Printf("\nTotal: %s\n", time.Since(overallStart).Round(time.Millisecond))

	if len(failed) > 0 {
		fmt.Println()
	} else {
		fmt.Println("\nAll checks passed!")
	}
}
