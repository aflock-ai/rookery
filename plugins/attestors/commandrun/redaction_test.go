package commandrun

import (
	"strings"
	"testing"
)

// TestRedactProcessCmdlines is the PoC for the sibling SIGNED sink that the
// stdout/stderr redaction missed. Each traced process's Cmdline is read verbatim
// from /proc/<pid>/cmdline and interned into the v0.2 predicate's signed
// Cmdlines[] table (uploaded to Archivista). A build step like
// `mytool --token=$MY_API_TOKEN` expands the secret into argv, so it would land
// unredacted there even with stdout/stderr scrubbed. This asserts the secret is
// gone from the Cmdline AND from the marshaled v0.2 Cmdlines[] (the actual signed
// bytes), across ALL processes — not just the top one. Revert
// redactProcessCmdlines and this goes red (the secret leaks into Cmdlines[]).
func TestRedactProcessCmdlines(t *testing.T) {
	secret := "FAKEsecret-abcdef0123456789"
	t.Setenv("MY_API_TOKEN", secret)

	innocent := "/usr/bin/make -j4 build" // a non-secret cmdline, must be unchanged
	procs := []ProcessInfo{
		{ProcessID: 100, Cmdline: "mytool --token=" + secret + " --verbose"},
		{ProcessID: 101, Cmdline: "child --auth=" + secret}, // a DESCENDANT also carries it
		{ProcessID: 102, Cmdline: innocent},
	}

	redactProcessCmdlines(procs)

	for _, p := range procs {
		if strings.Contains(p.Cmdline, secret) {
			t.Errorf("pid %d Cmdline still contains the secret: %q", p.ProcessID, p.Cmdline)
		}
	}
	if procs[0].Cmdline == "" || !strings.Contains(procs[0].Cmdline, redactedOutputValue) {
		t.Errorf("expected redaction placeholder in pid 100 Cmdline: %q", procs[0].Cmdline)
	}
	if procs[2].Cmdline != innocent {
		t.Errorf("a non-secret cmdline must be left intact: got %q want %q", procs[2].Cmdline, innocent)
	}

	// End-to-end: prove the secret never reaches the SIGNED v0.2 bytes —
	// covering BOTH the per-process Cmdlines[] and the top-level cmd argv.
	cmd := []string{"mytool", "--token=" + secret} // shell-expanded before cilock saw it
	redactArgv(cmd)
	rc := &CommandRun{Cmd: cmd, Processes: procs}
	body, _, err := MarshalV02WithSections(rc.ToV02())
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}
	if strings.Contains(string(body), secret) {
		t.Errorf("secret leaked into the signed v0.2 predicate body")
	}
}

// TestRedactArgv is the PoC for the top-level signed `cmd` sink. The operator's
// shell expands a secret env var into the command argv before cilock starts
// (`cilock run -- mytool --token=$MY_API_TOKEN` arrives expanded), and ToV02
// signs r.Cmd verbatim as the predicate's `cmd`. Revert redactArgv and this goes
// red. The program path (argv[0]) must survive untouched.
func TestRedactArgv(t *testing.T) {
	secret := "FAKEsecret-abcdef0123456789"
	t.Setenv("MY_API_TOKEN", secret)

	argv := []string{"/usr/bin/mytool", "--token=" + secret, "--verbose"}
	redactArgv(argv)

	if argv[0] != "/usr/bin/mytool" {
		t.Errorf("program path (argv[0]) must be left intact, got %q", argv[0])
	}
	for i, a := range argv {
		if strings.Contains(a, secret) {
			t.Errorf("argv[%d] still contains the secret: %q", i, a)
		}
	}
	if !strings.Contains(argv[1], redactedOutputValue) {
		t.Errorf("expected redaction placeholder in argv[1]: %q", argv[1])
	}
}

// TestRedactSensitiveEnvValues verifies that a secret carried in the
// environment is masked wherever it appears in captured command output — the
// common "secret env var echoed into the logs" leak. command-run is always-run
// and signs stdout/stderr into evidence, so this must not re-publish the secret.
// Value is an obviously-fake placeholder (real tokens trip push protection).
func TestRedactSensitiveEnvValues(t *testing.T) {
	secret := "FAKEsecret-abcdef0123456789"
	t.Setenv("MY_API_TOKEN", secret)
	t.Setenv("BUILD_NUMBER", "12345") // non-sensitive, must survive

	out := "build 12345 used token=" + secret + " then exited"
	got := redactSensitiveEnvValues(out)

	if strings.Contains(got, secret) {
		t.Errorf("captured output still contains the secret value: %q", got)
	}
	if !strings.Contains(got, redactedOutputValue) {
		t.Errorf("expected the redaction placeholder in output: %q", got)
	}
	if !strings.Contains(got, "12345") {
		t.Errorf("a non-sensitive env value must be left intact: %q", got)
	}
}

// TestIsSensitiveEnvKey is the false-positive guard: output redaction must be
// conservative, because flagging a non-secret var would scrub innocent text
// (e.g. PATH, AUTHOR) from the signed logs.
func TestIsSensitiveEnvKey(t *testing.T) {
	for _, k := range []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "MY_PASSPHRASE", "NPM_API_KEY"} {
		if !isSensitiveEnvKey(k) {
			t.Errorf("%q should be treated as sensitive", k)
		}
	}
	for _, k := range []string{"PATH", "HOME", "AUTHOR", "MONKEY_NAME", "PWD", "SHELL", "GOPATH"} {
		if isSensitiveEnvKey(k) {
			t.Errorf("%q must NOT be flagged sensitive — it would scrub innocent log content", k)
		}
	}
}
