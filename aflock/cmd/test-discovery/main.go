// Quick test for PID-based model discovery
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/aflock/internal/identity"
)

func main() {
	fmt.Println("=== PID-based Model Discovery Test ===")
	fmt.Printf("My PID: %d, Parent PID: %d\n\n", os.Getpid(), os.Getppid())

	// Use the comprehensive discovery function
	model, meta, err := identity.DiscoverFromMCPSocket()
	if err != nil {
		fmt.Printf("Discovery error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Discovery Results ===")
	fmt.Printf("Model: %s\n", model)
	fmt.Printf("Session ID: %s\n", meta.SessionID)
	fmt.Printf("Session Path: %s\n", meta.SessionPath)
	fmt.Printf("Claude PID: %d\n", meta.ClaudePID)
	fmt.Printf("Working Dir: %s\n", meta.WorkingDir)
	fmt.Printf("Discovery Method: %s\n", meta.DiscoveryMethod)

	fmt.Println("\n=== Process Chain ===")
	for _, p := range meta.ProcessChain {
		claude := ""
		if p.IsClaude {
			claude = " [CLAUDE]"
		}
		fmt.Printf("  PID %d: %s%s\n", p.PID, truncate(p.Command, 70), claude)
		if p.WorkingDir != "" {
			fmt.Printf("    cwd: %s\n", p.WorkingDir)
		}
	}

	fmt.Println("\n=== Environment ===")
	for k, v := range meta.Environment {
		if len(v) > 50 {
			v = v[:50] + "..."
		}
		fmt.Printf("  %s=%s\n", k, v)
	}

	fmt.Println("\n=== Full Metadata (JSON) ===")
	data, _ := json.MarshalIndent(meta, "", "  ")
	fmt.Println(string(data))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
