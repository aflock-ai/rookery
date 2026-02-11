package test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/aflock/internal/attestation"
	"github.com/aflock-ai/rookery/aflock/internal/policy"
	"github.com/aflock-ai/rookery/aflock/internal/verify"
)

func TestE2EAttestation(t *testing.T) {
	// Create a temporary test directory with git
	testDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = testDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git init failed: %v", err)
	}

	// Configure git user
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = testDir
	cmd.Run()
	cmd = exec.Command("git", "config", "user.name", "Test")
	cmd.Dir = testDir
	cmd.Run()

	// Create a test file
	testFile := filepath.Join(testDir, "main.go")
	if err := os.WriteFile(testFile, []byte("package main\nfunc main() { println(\"hello\") }\n"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Git add and commit
	cmd = exec.Command("git", "add", "main.go")
	cmd.Dir = testDir
	cmd.Run()
	cmd = exec.Command("git", "commit", "-m", "Initial commit")
	cmd.Dir = testDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("git commit failed: %v", err)
	}

	// Create test policy
	policyContent := `{
  "version": "1.0",
  "name": "e2e-test-policy",
  "expires": "2026-12-31T00:00:00Z",
  "steps": {
    "build": {
      "name": "build",
      "functionaries": [{"type": "root", "certConstraint": {"uris": ["spiffe://aflock.ai/*"]}}],
      "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}]
    },
    "test": {
      "name": "test",
      "functionaries": [{"type": "root", "certConstraint": {"uris": ["spiffe://aflock.ai/*"]}}],
      "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1"}],
      "artifactsFrom": ["build"]
    }
  },
  "tools": {"allow": ["Bash", "Read", "Write"]}
}`
	policyFile := filepath.Join(testDir, ".aflock")
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	ctx := context.Background()
	attestDir := filepath.Join(testDir, "attestations")

	// Get git tree hash
	treeHash, err := attestation.GetGitTreeHash(testDir)
	if err != nil {
		t.Fatalf("get tree hash: %v", err)
	}
	t.Logf("Git tree hash: %s", treeHash)

	// Run attestors for "build" step
	t.Log("Running 'build' step attestors...")
	buildResult, err := attestation.RunAttestors(ctx, "build", []string{"echo", "Building..."}, testDir)
	if err != nil {
		t.Fatalf("build attestors: %v", err)
	}
	t.Logf("Build output: %s", string(buildResult.Output))
	t.Logf("Build exit code: %d", buildResult.ExitCode)
	t.Logf("Collection name: %s", buildResult.Collection.Name)
	t.Logf("Attestor count: %d", len(buildResult.CompletedAttestors))

	if buildResult.Collection.Name != "build" {
		t.Errorf("Expected collection name 'build', got '%s'", buildResult.Collection.Name)
	}

	// List attestor types
	for _, ca := range buildResult.CompletedAttestors {
		t.Logf("  - Attestor: %s (type: %s)", ca.Attestor.Name(), ca.Attestor.Type())
	}

	// Store build attestation
	if err := attestation.EnsureAttestationDir(attestDir, treeHash); err != nil {
		t.Fatalf("create attestation dir: %v", err)
	}

	buildAttestPath := attestation.AttestationPath(attestDir, treeHash, "build")
	buildData, _ := json.MarshalIndent(buildResult.Collection, "", "  ")
	if err := os.WriteFile(buildAttestPath, buildData, 0644); err != nil {
		t.Fatalf("write build attestation: %v", err)
	}
	t.Logf("Build attestation stored: %s", buildAttestPath)

	// Run attestors for "test" step
	t.Log("Running 'test' step attestors...")
	testResult, err := attestation.RunAttestors(ctx, "test", []string{"echo", "All tests passed!"}, testDir)
	if err != nil {
		t.Fatalf("test attestors: %v", err)
	}
	t.Logf("Test output: %s", string(testResult.Output))
	t.Logf("Test exit code: %d", testResult.ExitCode)

	if testResult.Collection.Name != "test" {
		t.Errorf("Expected collection name 'test', got '%s'", testResult.Collection.Name)
	}

	testAttestPath := attestation.AttestationPath(attestDir, treeHash, "test")
	testData, _ := json.MarshalIndent(testResult.Collection, "", "  ")
	if err := os.WriteFile(testAttestPath, testData, 0644); err != nil {
		t.Fatalf("write test attestation: %v", err)
	}
	t.Logf("Test attestation stored: %s", testAttestPath)

	// List attestations
	attestations, err := attestation.ListAttestations(attestDir, treeHash)
	if err != nil {
		t.Fatalf("list attestations: %v", err)
	}
	t.Logf("Found %d attestations:", len(attestations))
	for _, a := range attestations {
		t.Logf("  - %s", filepath.Base(a))
	}

	if len(attestations) != 2 {
		t.Errorf("Expected 2 attestations, got %d", len(attestations))
	}

	// Load policy and verify
	t.Log("Loading policy and running verification...")
	pol, _, err := policy.Load(policyFile)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	verifier := verify.NewVerifier()
	result, err := verifier.VerifySteps(pol, attestDir, treeHash)
	if err != nil {
		t.Fatalf("verify steps: %v", err)
	}

	t.Logf("Verification result: success=%v", result.Success)
	t.Logf("Policy: %s", result.PolicyName)
	t.Logf("Tree hash: %s", result.TreeHash)

	for stepName, stepResult := range result.Steps {
		t.Logf("Step '%s': found=%v", stepName, stepResult.Found)
		if len(stepResult.Errors) > 0 {
			for _, e := range stepResult.Errors {
				t.Logf("  Error: %s", e)
			}
		}
	}

	// Both steps should be found
	if !result.Steps["build"].Found {
		t.Error("Build step attestation not found")
	}
	if !result.Steps["test"].Found {
		t.Error("Test step attestation not found")
	}

	t.Log("E2E Test Complete!")
}
