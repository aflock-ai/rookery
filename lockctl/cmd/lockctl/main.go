package main

import (
	"os"

	"github.com/aflock-ai/rookery/lockctl/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
