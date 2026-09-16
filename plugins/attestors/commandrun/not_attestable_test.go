// jade:ring local
package commandrun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The sentinel is the decision, not a wording, and a setup failure is not it.
func TestNotAttestableIsTheDecisionNotTheWording(t *testing.T) {
	cause := errors.New("pid 4242 is a zombie")
	for _, err := range []error{
		notAttestable("macOS process tracing: the kernel's pid counter wrapped while the command ran"),
		notAttestablef("macOS process tracing: %d descendant(s) were still running", 3),
		notAttestablef("macOS process tracing: liveness unknown: %w", cause),
	} {
		if !errors.Is(err, ErrNotAttestable) {
			t.Errorf("a refusal to sign must satisfy errors.Is(ErrNotAttestable): %v", err)
		}
	}
	if !errors.Is(notAttestablef("x: %w", cause), cause) {
		t.Error("notAttestablef must preserve %w chains")
	}
	if got := notAttestable("exact words").Error(); got != "exact words" {
		t.Errorf("message changed: %q", got)
	}
	// A setup failure looks similar on the wire and must NOT be the decision,
	// or a tracer that never ran would satisfy every "refuses to sign" test.
	for _, err := range []error{
		fmt.Errorf("macOS process tracing: could not start the log stream: %w", cause),
		errors.New("macOS process tracing needs sandbox-exec, which is not usable"),
	} {
		if errors.Is(err, ErrNotAttestable) {
			t.Errorf("a setup failure must not read as a refusal to attest: %v", err)
		}
	}
}

// The pid-wrap refusal names its cause for errors.Is while keeping the
// operator's wording, and it is still the decision.
func TestPIDWrapRefusalNamesItsCause(t *testing.T) {
	err := notAttestableFor(ErrPIDCounterWrapped, "macOS process tracing: the kernel's pid counter wrapped while the command ran")
	if !errors.Is(err, ErrPIDCounterWrapped) || !errors.Is(err, ErrNotAttestable) {
		t.Fatalf("the pid-wrap refusal must satisfy both sentinels: %v", err)
	}
	if got := err.Error(); got != "macOS process tracing: the kernel's pid counter wrapped while the command ran" {
		t.Fatalf("message changed: %q", got)
	}
	if errors.Is(notAttestable("macOS process tracing: 3 descendant(s) were still running"), ErrPIDCounterWrapped) {
		t.Fatal("a different refusal must not read as the pid wrap")
	}
}

// A pid-counter wrap says nothing about the property a Darwin trace test is
// checking, so every such test asks whether its run was testable before it
// asserts anything: each Attest in a Darwin test is followed by
// skipIfUntestable within two lines. Three ring gates were lost to this on
// 2026-09-16 in three different files; the next file must not be a fourth.
func TestEveryDarwinTraceAsksWhetherTheRunWasTestable(t *testing.T) {
	files, err := filepath.Glob("*darwin*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no darwin test files found: %v", err)
	}
	var bare []string
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(src), "\n")
		for i, line := range lines {
			if !strings.Contains(line, ".Attest(") {
				continue
			}
			window := strings.Join(lines[i:min(i+3, len(lines))], "\n")
			if !strings.Contains(window, "skipIfUntestable(t, ") {
				bare = append(bare, fmt.Sprintf("%s:%d", f, i+1))
			}
		}
	}
	if len(bare) > 0 {
		t.Fatalf("Attest calls in Darwin tests that never ask whether the run was testable (call skipIfUntestable(t, err) right after):\n  %s",
			strings.Join(bare, "\n  "))
	}
}

// Every refusal to sign in this package goes through the sentinel. A new
// site written as a bare fmt.Errorf(... "not attestable") would be a refusal
// the decision cannot see, and the first test to enumerate its wording would
// re-create the defect this file closes. Scans the source so the boundary is
// held by the suite rather than by review.
func TestEveryRefusalToAttestCarriesTheSentinel(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	call := regexp.MustCompile(`(fmt\.Errorf|errors\.New)\(`)
	var bare []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "not_attestable.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		for _, loc := range call.FindAllStringIndex(s, -1) {
			end := matchingParen(s, loc[1])
			if strings.Contains(s[loc[0]:end], "not attestable") {
				bare = append(bare, fmt.Sprintf("%s:%d", f, 1+strings.Count(s[:loc[0]], "\n")))
			}
		}
	}
	if len(bare) > 0 {
		t.Fatalf("refusals to attest built without the sentinel (use notAttestable/notAttestablef so errors.Is(ErrNotAttestable) sees them):\n  %s",
			strings.Join(bare, "\n  "))
	}
}

// matchingParen returns the index just past the ')' closing the call whose
// '(' precedes start, skipping parens inside string literals.
func matchingParen(s string, start int) int {
	depth, instr, esc := 1, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case instr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				instr = false
			}
		case c == '"':
			instr = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}
