// Package attestation provides attestor integration for aflock.
package attestation

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/environment"
	"github.com/aflock-ai/rookery/plugins/attestors/git"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
)

// RunResult contains the result of running attestors around a command.
type RunResult struct {
	// CompletedAttestors contains all attestor results
	CompletedAttestors []attestation.CompletedAttestor
	// Collection is the attestation collection
	Collection attestation.Collection
	// Output is the command stdout/stderr
	Output []byte
	// ExitCode is the command exit code
	ExitCode int
	// Error is any error from command execution
	Error error
	// Duration is how long the command took
	Duration time.Duration
}

// RunAttestors executes attestors around a command and returns the collection.
// This captures:
// - Environment variables (filtered for security)
// - Git state (commit, branch, remotes)
// - Materials (file hashes before command)
// - Command execution (command, exit code, stdout/stderr)
// - Products (file hashes after command, diff from materials)
func RunAttestors(ctx context.Context, stepName string, cmd []string, workdir string) (*RunResult, error) {
	if workdir == "" {
		var err error
		workdir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("get working directory: %w", err)
		}
	}

	// Configure attestors for this step
	// Order matters: environment and git run in Setup phase,
	// material runs before cmd, commandrun executes cmd,
	// product runs after cmd
	attestors := []attestation.Attestor{
		environment.New(),
		git.New(),
		material.New(),
		commandrun.New(
			commandrun.WithCommand(cmd),
		),
		product.New(),
	}

	// Create attestation context with step name and working directory
	attCtx, err := attestation.NewContext(stepName, attestors,
		attestation.WithWorkingDir(workdir),
		attestation.WithHashes([]cryptoutil.DigestValue{
			{Hash: crypto.SHA256, GitOID: false},
		}),
		attestation.WithEnvFilterVarsEnabled(),
		attestation.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("create attestation context: %w", err)
	}

	// Run all attestors through their lifecycle phases
	start := time.Now()
	runErr := attCtx.RunAttestors()
	completed := attCtx.CompletedAttestors()
	collection := attestation.NewCollection(stepName, completed)

	result := &RunResult{
		CompletedAttestors: completed,
		Collection:         collection,
		Duration:           time.Since(start),
	}

	// Extract command run results for output and exit code
	for _, comp := range completed {
		if cmdRun, ok := comp.Attestor.(*commandrun.CommandRun); ok {
			result.Output = []byte(cmdRun.Stdout + cmdRun.Stderr)
			result.ExitCode = cmdRun.ExitCode
			if cmdRun.ExitCode != 0 {
				result.Error = fmt.Errorf("command exited with code %d", cmdRun.ExitCode)
			}
			break
		}
	}

	// Return error from attestor run if any
	if runErr != nil {
		if result.Error == nil {
			result.Error = runErr
		}
		return result, fmt.Errorf("run attestors: %w", runErr)
	}

	return result, nil
}

// RunWithGlobs runs attestors with specific include/exclude globs for materials and products.
func RunWithGlobs(ctx context.Context, stepName string, cmd []string, workdir string, includeGlobs, excludeGlobs []string) (*RunResult, error) {
	if workdir == "" {
		var err error
		workdir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("get working directory: %w", err)
		}
	}

	// Configure product attestor with globs
	var productOpts []product.Option
	for _, glob := range includeGlobs {
		productOpts = append(productOpts, product.WithIncludeGlob(glob))
	}
	for _, glob := range excludeGlobs {
		productOpts = append(productOpts, product.WithExcludeGlob(glob))
	}

	attestors := []attestation.Attestor{
		environment.New(),
		git.New(),
		material.New(),
		commandrun.New(
			commandrun.WithCommand(cmd),
		),
		product.New(productOpts...),
	}

	attCtx, err := attestation.NewContext(stepName, attestors,
		attestation.WithWorkingDir(workdir),
		attestation.WithHashes([]cryptoutil.DigestValue{
			{Hash: crypto.SHA256, GitOID: false},
		}),
		attestation.WithEnvFilterVarsEnabled(),
		attestation.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("create attestation context: %w", err)
	}

	start := time.Now()
	runErr := attCtx.RunAttestors()
	completed := attCtx.CompletedAttestors()
	collection := attestation.NewCollection(stepName, completed)

	result := &RunResult{
		CompletedAttestors: completed,
		Collection:         collection,
		Duration:           time.Since(start),
	}

	// Extract command run results
	for _, comp := range completed {
		if cmdRun, ok := comp.Attestor.(*commandrun.CommandRun); ok {
			result.Output = []byte(cmdRun.Stdout + cmdRun.Stderr)
			result.ExitCode = cmdRun.ExitCode
			if cmdRun.ExitCode != 0 {
				result.Error = fmt.Errorf("command exited with code %d", cmdRun.ExitCode)
			}
			break
		}
	}

	if runErr != nil {
		if result.Error == nil {
			result.Error = runErr
		}
		return result, fmt.Errorf("run attestors: %w", runErr)
	}

	return result, nil
}

// GetGitTreeHash returns the current git tree hash for the working directory.
func GetGitTreeHash(workdir string) (string, error) {
	if workdir == "" {
		var err error
		workdir, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
	}

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = workdir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// GetGitWorkTreeHash returns the git work-tree hash (staged files) for the working directory.
func GetGitWorkTreeHash(workdir string) (string, error) {
	if workdir == "" {
		var err error
		workdir, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
	}

	cmd := exec.Command("git", "write-tree")
	cmd.Dir = workdir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git write-tree: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// AttestationPath returns the path where attestations should be stored for a given tree hash and step.
func AttestationPath(baseDir, treeHash, stepName string) string {
	return filepath.Join(baseDir, treeHash, stepName+".intoto.json")
}

// EnsureAttestationDir ensures the attestation directory exists for a given tree hash.
func EnsureAttestationDir(baseDir, treeHash string) error {
	dir := filepath.Join(baseDir, treeHash)
	return os.MkdirAll(dir, 0750)
}

// ListAttestations returns all attestation files for a given tree hash.
func ListAttestations(baseDir, treeHash string) ([]string, error) {
	dir := filepath.Join(baseDir, treeHash)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var attestations []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".intoto.json") {
			attestations = append(attestations, filepath.Join(dir, entry.Name()))
		}
	}
	return attestations, nil
}
