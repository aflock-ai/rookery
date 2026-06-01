// Package main is a synthetic gosec target for the sarif fixture recording.
// It deliberately uses math/rand for a "token" so gosec emits a G404 finding,
// giving the recorded SARIF report at least one result to wrap. Nothing here is
// real or sensitive — it exists only to produce a deterministic scanner report.
package main

import (
	"fmt"
	"math/rand"
)

func weakToken() string {
	return fmt.Sprintf("%d", rand.Int()) // gosec G404: weak random source
}

func main() {
	fmt.Println(weakToken())
}
