// jade:ring local
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCommandRunEnvelope writes an unsigned DSSE envelope whose statement
// carries one command-run attestation with the given exit code.
func writeCommandRunEnvelope(t *testing.T, exitcode int) string {
	t.Helper()
	stmt := map[string]any{"predicate": map[string]any{"attestations": []any{
		map[string]any{"type": typeCommandRun, "attestation": map[string]any{"cmd": []string{"npm", "run", "check"}, "exitcode": exitcode}},
	}}}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "step.good.json")
	if err := os.WriteFile(path, env, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// mx-commander-l4-muh1lia3: prove reported "quality: real run REFUSED (wrapped
// command exited 127, not 0)" for `npm run check` and stopped there. `cilock
// run` already explains 126 and 127; prove's step line now says the same,
// read from the recorded command-run evidence rather than from a deny message
// a policy author may word any way they like.
func TestProveExplainsARealRunTheShellCouldNotRun(t *testing.T) {
	refusals := []string{"wrapped command exited 127, not 0"}
	line := realRunOutcome(refusals, writeCommandRunEnvelope(t, 127))
	for _, want := range []string{"real run REFUSED (wrapped command exited 127, not 0)", "not found", "installed", "PATH"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %q", want, line)
		}
	}
	if line := realRunOutcome([]string{"command must be npm test"}, writeCommandRunEnvelope(t, 126)); !strings.Contains(line, "not executable") {
		t.Errorf("exit 126 is explained whatever the deny message says: %q", line)
	}
	if line := realRunOutcome(refusals, writeCommandRunEnvelope(t, 1)); strings.Contains(line, "not found") || strings.Contains(line, "not executable") {
		t.Errorf("exit 1 carries no could-not-run hint: %q", line)
	}
	if line := realRunOutcome(nil, writeCommandRunEnvelope(t, 127)); line != "real run admitted" {
		t.Errorf("an admitted run is reported as admitted, hint or not: %q", line)
	}
	if line := realRunOutcome(refusals, filepath.Join(t.TempDir(), "missing.json")); line != "real run REFUSED (wrapped command exited 127, not 0)" {
		t.Errorf("unreadable evidence adds nothing rather than guessing: %q", line)
	}
}
