// Package junitgen is a throwaway target whose `go test` output is converted to
// JUnit XML by go-junit-report and recorded under cilock as the REAL input for
// the test-results attestor fixture. It has no dependencies and does no I/O.
package junitgen

// Add returns the sum of two integers.
func Add(a, b int) int { return a + b }

// Sub returns the difference of two integers.
func Sub(a, b int) int { return a - b }

// Mul returns the product of two integers.
func Mul(a, b int) int { return a * b }
