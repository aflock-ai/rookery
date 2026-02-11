// Package test provides integration tests for aflock MCP server.
package test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jsonRPCRequest represents a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// jsonRPCResponse represents a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPTestClient wraps the aflock server for testing.
type MCPTestClient struct {
	cmd     *exec.Cmd
	stdin   *json.Encoder
	stdout  *bufio.Scanner
	nextID  int
	t       *testing.T
	workdir string
}

// NewMCPTestClient starts the aflock server and returns a test client.
func NewMCPTestClient(t *testing.T, workdir string) (*MCPTestClient, error) {
	// Find the aflock binary
	aflockBin, err := exec.LookPath("aflock")
	if err != nil {
		// Try to build it first
		buildCmd := exec.Command("go", "build", "-o", "/tmp/aflock-test", "./cmd/aflock")
		buildCmd.Dir = filepath.Join(workdir, "..")
		if out, err := buildCmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("build aflock: %s: %w", out, err)
		}
		aflockBin = "/tmp/aflock-test"
	}

	cmd := exec.Command(aflockBin, "serve", "--policy", filepath.Join(workdir, ".aflock"))
	cmd.Dir = workdir
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start aflock: %w", err)
	}

	client := &MCPTestClient{
		cmd:     cmd,
		stdin:   json.NewEncoder(stdin),
		stdout:  bufio.NewScanner(stdout),
		nextID:  1,
		t:       t,
		workdir: workdir,
	}

	// Give server time to start
	time.Sleep(500 * time.Millisecond)

	// Initialize MCP connection
	if err := client.initialize(); err != nil {
		client.Close()
		return nil, fmt.Errorf("initialize: %w", err)
	}

	return client, nil
}

// Close stops the aflock server.
func (c *MCPTestClient) Close() {
	if c.cmd != nil && c.cmd.Process != nil {
		c.cmd.Process.Kill()
		c.cmd.Wait()
	}
}

// call sends a JSON-RPC request and returns the response.
func (c *MCPTestClient) call(method string, params any) (json.RawMessage, error) {
	id := c.nextID
	c.nextID++

	var paramsJSON json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		paramsJSON = data
	}

	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  paramsJSON,
	}

	if err := c.stdin.Encode(req); err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	// Read response
	for c.stdout.Scan() {
		line := c.stdout.Text()
		if line == "" {
			continue
		}

		var resp jsonRPCResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			c.t.Logf("Skipping non-JSON line: %s", line)
			continue
		}

		if resp.ID == id {
			if resp.Error != nil {
				return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			return resp.Result, nil
		}
	}

	return nil, fmt.Errorf("no response received")
}

// initialize performs MCP handshake.
func (c *MCPTestClient) initialize() error {
	_, err := c.call("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]string{
			"name":    "aflock-test",
			"version": "1.0.0",
		},
	})
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}

	// Send initialized notification
	c.stdin.Encode(jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	})

	return nil
}

// CallTool calls an MCP tool.
func (c *MCPTestClient) CallTool(name string, args map[string]any) (string, error) {
	result, err := c.call("tools/call", map[string]any{
		"name":      name,
		"arguments": args,
	})
	if err != nil {
		return "", err
	}

	var callResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(result, &callResult); err != nil {
		return "", fmt.Errorf("unmarshal result: %w", err)
	}

	if len(callResult.Content) > 0 {
		return callResult.Content[0].Text, nil
	}
	return "", nil
}

func TestMCPBashWithAttestation(t *testing.T) {
	// Find test-project directory
	workdir := filepath.Join("..", "test-project")
	if _, err := os.Stat(workdir); os.IsNotExist(err) {
		t.Skip("test-project directory not found")
	}

	absWorkdir, _ := filepath.Abs(workdir)
	client, err := NewMCPTestClient(t, absWorkdir)
	if err != nil {
		t.Fatalf("Failed to create MCP client: %v", err)
	}
	defer client.Close()

	// Test bash with attestation
	result, err := client.CallTool("bash", map[string]any{
		"command": "echo 'Running tests' && go version",
		"attest":  true,
		"step":    "test",
		"reason":  "E2E test verification",
	})
	if err != nil {
		t.Fatalf("bash tool call failed: %v", err)
	}

	t.Logf("Bash result: %s", result)

	// Parse result to check attestation path
	var bashResult struct {
		Output      string `json:"output"`
		ExitCode    int    `json:"exitCode"`
		Step        string `json:"step"`
		Attestation string `json:"attestation"`
	}
	if err := json.Unmarshal([]byte(result), &bashResult); err != nil {
		t.Fatalf("Failed to parse bash result: %v", err)
	}

	if bashResult.Step != "test" {
		t.Errorf("Expected step 'test', got '%s'", bashResult.Step)
	}

	if bashResult.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", bashResult.ExitCode)
	}

	// Check if attestation was created (may not be signed if SPIRE is not available)
	t.Logf("Attestation path: %s", bashResult.Attestation)
}

func TestMCPBashWithoutAttestation(t *testing.T) {
	workdir := filepath.Join("..", "test-project")
	if _, err := os.Stat(workdir); os.IsNotExist(err) {
		t.Skip("test-project directory not found")
	}

	absWorkdir, _ := filepath.Abs(workdir)
	client, err := NewMCPTestClient(t, absWorkdir)
	if err != nil {
		t.Fatalf("Failed to create MCP client: %v", err)
	}
	defer client.Close()

	// Test regular bash without attestation
	result, err := client.CallTool("bash", map[string]any{
		"command": "echo 'Hello from aflock'",
	})
	if err != nil {
		t.Fatalf("bash tool call failed: %v", err)
	}

	t.Logf("Bash result: %s", result)

	if !strings.Contains(result, "Hello from aflock") {
		t.Errorf("Expected output to contain 'Hello from aflock'")
	}
}

func TestMCPGetPolicy(t *testing.T) {
	workdir := filepath.Join("..", "test-project")
	if _, err := os.Stat(workdir); os.IsNotExist(err) {
		t.Skip("test-project directory not found")
	}

	absWorkdir, _ := filepath.Abs(workdir)
	client, err := NewMCPTestClient(t, absWorkdir)
	if err != nil {
		t.Fatalf("Failed to create MCP client: %v", err)
	}
	defer client.Close()

	result, err := client.CallTool("get_policy", nil)
	if err != nil {
		t.Fatalf("get_policy tool call failed: %v", err)
	}

	t.Logf("Policy result: %s", result)

	if !strings.Contains(result, "test-policy") {
		t.Errorf("Expected policy to contain 'test-policy'")
	}
}

// TestDockerE2E tests the full E2E flow in Docker with SPIRE.
// This test requires docker-compose to be running.
func TestDockerE2E(t *testing.T) {
	// Skip if not running in integration mode
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Set INTEGRATION_TEST=true to run Docker E2E tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Check docker-compose is running
	checkCmd := exec.CommandContext(ctx, "docker-compose", "ps", "--quiet", "aflock-test")
	if output, err := checkCmd.CombinedOutput(); err != nil || len(output) == 0 {
		t.Skip("docker-compose is not running or aflock-test container not found")
	}

	// Execute MCP test inside the container
	testScript := `
	cd /workspace

	# Create a simple JSON-RPC test
	cat > /tmp/mcp-test.sh << 'SCRIPT'
#!/bin/bash
set -e

# Start aflock serve in background and capture its PID
aflock serve --policy /workspace/.aflock &
AFLOCK_PID=$!
sleep 1

# Send initialize request
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | timeout 5 head -1

# Send bash tool call with attestation
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bash","arguments":{"command":"echo test","attest":true,"step":"test","reason":"docker e2e"}}}' | timeout 5 head -1

# Cleanup
kill $AFLOCK_PID 2>/dev/null || true

# Check attestation was created
if ls ~/.aflock/attestations/*/*.intoto.json 2>/dev/null; then
    echo "SUCCESS: Attestation files found"
    cat ~/.aflock/attestations/*/*.intoto.json | head -50
else
    echo "FAIL: No attestation files found"
    exit 1
fi
SCRIPT
chmod +x /tmp/mcp-test.sh
/tmp/mcp-test.sh
`

	cmd := exec.CommandContext(ctx, "docker-compose", "exec", "-T", "aflock-test", "bash", "-c", testScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Docker E2E test failed: %v\nOutput: %s", err, output)
	}

	t.Logf("Docker E2E output:\n%s", output)

	if !strings.Contains(string(output), "SUCCESS") {
		t.Errorf("Expected SUCCESS in output")
	}
}
