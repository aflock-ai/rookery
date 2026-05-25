//go:debug fips140=on

// cilock-all-cat builds cilock with every attestor (incl. trivy/nessus/falco)
// + the detection catalog loaded so the test harness can exercise them.
package main

import (
	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/cli"

	_ "github.com/aflock-ai/rookery/presets/all"
)

func main() {
	attestation.RegisterLegacyAliases()
	cli.Execute()
}
