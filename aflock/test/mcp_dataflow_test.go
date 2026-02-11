package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/aflock/internal/policy"
	"github.com/aflock-ai/rookery/aflock/internal/state"
	"github.com/aflock-ai/rookery/aflock/pkg/aflock"
)

// TestMCPDataFlowEnforcement simulates the MCP server's dataFlow enforcement
// by manually tracking session state like the server does.
func TestMCPDataFlowEnforcement(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "bank-account.csv")
	if err := os.WriteFile(testFile, []byte("date,amount\n2026-01-15,5420.00"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create policy similar to demo
	pol := &aflock.Policy{
		Name:    "test-exfil-prevention",
		Version: "1.0",
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"financial": {"Read:**/bank-*.csv"},
				"public":    {"Bash:*bird*", "Bash:*tweet*"},
				"private":   {"Bash:*imsg*"},
			},
			FlowRules: []aflock.DataFlowRule{
				{
					Deny:    "financial->public",
					Message: "BLOCKED: Cannot post financial data to public channels",
				},
			},
		},
	}

	// Initialize session state
	stateManager := state.NewManager(tmpDir)
	sessionID := "test-session"
	sessionState := stateManager.Initialize(sessionID, pol, "")

	evaluator := policy.NewEvaluator(pol)

	// Step 1: Simulate read_file of bank-account.csv
	t.Run("read sensitive file", func(t *testing.T) {
		readInput := json.RawMessage(`{"file_path": "` + testFile + `"}`)

		// Check dataFlow for read operation
		_, _, newMaterial := evaluator.EvaluateDataFlow("Read", readInput, sessionState.Materials)
		if newMaterial == nil {
			t.Fatal("Expected new material classification, got nil")
		}
		if newMaterial.Label != "financial" {
			t.Errorf("Expected label 'financial', got '%s'", newMaterial.Label)
		}

		// Track the material (like server does)
		newMaterial.Timestamp = time.Now()
		sessionState.Materials = append(sessionState.Materials, *newMaterial)
		if err := stateManager.Save(sessionState); err != nil {
			t.Fatal(err)
		}

		t.Logf("Tracked material: %s from %s", newMaterial.Label, newMaterial.Source)
	})

	// Step 2: Simulate bash command to tweet - should be BLOCKED
	t.Run("tweet blocked after reading financial data", func(t *testing.T) {
		bashInput := json.RawMessage(`{"command": "bird tweet 'My balance is $10111'"}`)

		// Reload session to simulate separate request
		sessionState, err := stateManager.Load(sessionID)
		if err != nil {
			t.Fatal(err)
		}
		if len(sessionState.Materials) == 0 {
			t.Fatal("Session should have materials tracked")
		}

		// Check dataFlow for bash operation
		decision, reason, _ := evaluator.EvaluateDataFlow("Bash", bashInput, sessionState.Materials)
		if decision != aflock.DecisionDeny {
			t.Errorf("Expected DecisionDeny, got %s (reason: %s)", decision, reason)
		}
		if reason == "" {
			t.Error("Expected non-empty reason")
		}

		t.Logf("BLOCKED: %s", reason)
	})

	// Step 3: Simulate bash command to imsg - should be ALLOWED
	t.Run("imsg allowed after reading financial data", func(t *testing.T) {
		bashInput := json.RawMessage(`{"command": "imsg send --to wife 'Check our balance'"}`)

		// Reload session
		sessionState, err := stateManager.Load(sessionID)
		if err != nil {
			t.Fatal(err)
		}

		// Check dataFlow for bash operation (imsg is private, not public)
		decision, reason, _ := evaluator.EvaluateDataFlow("Bash", bashInput, sessionState.Materials)
		if decision != aflock.DecisionAllow {
			t.Errorf("Expected DecisionAllow, got %s (reason: %s)", decision, reason)
		}

		t.Log("ALLOWED: imsg to private contact")
	})
}

// TestDataFlowSequencing verifies that when requests are processed sequentially,
// materials are properly tracked and exfiltration is blocked.
func TestDataFlowSequencing(t *testing.T) {
	pol := &aflock.Policy{
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"financial": {"Read:**/bank-*.csv", "read_file:**/bank-*.csv"},
				"public":    {"Bash:*bird*", "Bash:*curl*twitter*"},
			},
			FlowRules: []aflock.DataFlowRule{
				{Deny: "financial->public"},
			},
		},
	}

	evaluator := policy.NewEvaluator(pol)
	var materials []aflock.MaterialClassification

	// Sequence: read -> bash(tweet) should be blocked
	t.Run("sequential read then tweet", func(t *testing.T) {
		// 1. Read financial file
		readInput := json.RawMessage(`{"file_path": "/data/bank-account.csv"}`)
		_, _, newMaterial := evaluator.EvaluateDataFlow("Read", readInput, materials)
		if newMaterial != nil {
			newMaterial.Timestamp = time.Now()
			materials = append(materials, *newMaterial)
		}

		// 2. Attempt to tweet
		bashInput := json.RawMessage(`{"command": "bird tweet hello"}`)
		decision, _, _ := evaluator.EvaluateDataFlow("Bash", bashInput, materials)

		if decision != aflock.DecisionDeny {
			t.Errorf("Expected tweet to be DENIED after reading financial data, got %s", decision)
		}
	})

	// Without reading financial data first, tweet should be allowed
	t.Run("tweet without prior financial read", func(t *testing.T) {
		emptyMaterials := []aflock.MaterialClassification{}
		bashInput := json.RawMessage(`{"command": "bird tweet hello"}`)
		decision, _, _ := evaluator.EvaluateDataFlow("Bash", bashInput, emptyMaterials)

		if decision != aflock.DecisionAllow {
			t.Errorf("Expected tweet to be ALLOWED without prior financial read, got %s", decision)
		}
	})
}
