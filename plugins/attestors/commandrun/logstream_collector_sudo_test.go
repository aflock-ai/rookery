// jade:ring local
//go:build unix

package commandrun

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// These tests run the chooser against a fake sudo executable, so the exec,
// its arguments and its environment are the real ones defaultCollectorHost
// uses. The fake models sudo 1.9.13p2 on macOS as found on mint-1: `-n -l`
// with a command never matches a rule that has arguments (exit 1), while
// `-n -l` with no command lists the user's rules verbatim.

type fakeSudo struct {
	listing    string // what `-n -l` prints
	listExit   int    // its exit status
	argvExit   int    // exit status of `-n -l <command>`
	path, logf string
}

func (f *fakeSudo) install(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	f.path = filepath.Join(dir, "sudo")
	f.logf = filepath.Join(dir, "calls")
	listingFile := filepath.Join(dir, "listing")
	if err := os.WriteFile(listingFile, []byte(f.listing), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"{ echo \"ARGS $*\"; env | sed 's/^/ENV /'; } >> '" + f.logf + "'\n" +
		"if [ \"$#\" -eq 2 ] && [ \"$1\" = -n ] && [ \"$2\" = -l ]; then\n" +
		"  cat '" + listingFile + "'\n" +
		"  exit " + strconv.Itoa(f.listExit) + "\n" +
		"fi\n" +
		"echo 'fake sudo: command not matched' >&2\n" +
		"exit " + strconv.Itoa(f.argvExit) + "\n"
	if err := os.WriteFile(f.path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := sudoToolPath
	sudoToolPath = f.path
	t.Cleanup(func() { sudoToolPath = old })
}

func (f *fakeSudo) calls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.logf)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// nonAdminHost is the real host with only the identity answers faked.
func nonAdminHost() collectorHost {
	h := defaultCollectorHost()
	h.userName = func() string { return "ci" }
	h.isRoot = func() bool { return false }
	h.isAdmin = func() (bool, error) { return false, nil }
	return h
}

func listingWith(rules ...string) string {
	var b strings.Builder
	b.WriteString("Matching Defaults entries for ci on mint-1:\n" +
		"    env_reset, env_keep+=BLOCKSIZE, env_keep+=\"COLORFGBG COLORTERM\"\n\n" +
		"User ci may run the following commands on mint-1:\n")
	for _, r := range rules {
		b.WriteString("    " + r + "\n")
	}
	return b.String()
}

func chooseWithFake(t *testing.T, f *fakeSudo) (collectorLaunch, error) {
	t.Helper()
	f.install(t)
	return chooseCollector(nonAdminHost(), testLogPath, f.path, testPredicate)
}

func wantSudoLaunch(t *testing.T, f *fakeSudo, got collectorLaunch, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("chooseCollector refused: %v", err)
	}
	want := append([]string{f.path, "-n"}, wantDirect()...)
	if !got.viaSudo || !slices.Equal(got.argv, want) {
		t.Fatalf("launch = %+v, want sudo argv %q", got, want)
	}
}

func wantRefused(t *testing.T, got collectorLaunch, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("must refuse, got launch %+v", got)
	}
	if !strings.Contains(err.Error(), `ci ALL=(root) NOPASSWD: /usr/bin/log stream --style ndjson --predicate senderImagePath CONTAINS\[c\] "sandbox"`) {
		t.Fatalf("refusal must name the exact sudoers line:\n%v", err)
	}
}

// The case that broke every customer: this sudo answers `-l <argv>` with exit
// 1 even though the rule is installed and `sudo -n <argv>` runs.
func TestCollectorSudoListingShowsRuleWhileArgvCheckFails(t *testing.T) {
	f := &fakeSudo{listing: listingWith(exactRuleListed), argvExit: 1}
	got, err := chooseWithFake(t, f)
	wantSudoLaunch(t, f, got, err)
}

func TestCollectorSudoExactRuleListed(t *testing.T) {
	f := &fakeSudo{listing: listingWith("(root) NOPASSWD: /usr/bin/true", exactRuleListed), argvExit: 0}
	got, err := chooseWithFake(t, f)
	wantSudoLaunch(t, f, got, err)
}

// A broader grant does not count even where sudo itself would run our argv
// under it. The listing is compared as text, and only the rule cilock
// documents is known, by construction, to grant exactly this command.
func TestCollectorSudoBroaderRulesRefused(t *testing.T) {
	for name, rule := range map[string]string{
		"wildcard args":    `(root) NOPASSWD: /usr/bin/log stream *`,
		"any log command":  `(root) NOPASSWD: /usr/bin/log`,
		"everything":       `(ALL) NOPASSWD: ALL`,
		"any runas":        `(ALL) NOPASSWD: /usr/bin/log stream --style ndjson --predicate senderImagePath CONTAINS\[c\] "sandbox"`,
		"password needed":  `(root) /usr/bin/log stream --style ndjson --predicate senderImagePath CONTAINS\[c\] "sandbox"`,
		"unescaped class":  `(root) NOPASSWD: /usr/bin/log stream --style ndjson --predicate senderImagePath CONTAINS[c] "sandbox"`,
		"joined with more": exactRuleListed + `, /usr/bin/log show`,
		"prefix only":      `(root) NOPASSWD: /usr/bin/log stream --style ndjson --predicate senderImagePath`,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeSudo{listing: listingWith(rule), argvExit: 0}
			got, err := chooseWithFake(t, f)
			wantRefused(t, got, err)
		})
	}
}

func TestCollectorSudoNoRuleRefused(t *testing.T) {
	t.Run("listing without the rule", func(t *testing.T) {
		f := &fakeSudo{listing: listingWith("(root) NOPASSWD: /usr/bin/true"), argvExit: 1}
		got, err := chooseWithFake(t, f)
		wantRefused(t, got, err)
	})
	t.Run("listing refused", func(t *testing.T) {
		f := &fakeSudo{listing: "sudo: a password is required\n", listExit: 1, argvExit: 1}
		got, err := chooseWithFake(t, f)
		wantRefused(t, got, err)
		if !strings.Contains(err.Error(), "a password is required") {
			t.Fatalf("refusal must carry sudo's own answer:\n%v", err)
		}
	})
	// Exit status is part of the answer: a listing that fails is no listing,
	// whatever it printed.
	t.Run("rule printed but listing failed", func(t *testing.T) {
		f := &fakeSudo{listing: listingWith(exactRuleListed), listExit: 1, argvExit: 1}
		got, err := chooseWithFake(t, f)
		wantRefused(t, got, err)
	})
}

// The listing is asked for with no command, and with an environment cilock
// sets rather than inherits.
func TestCollectorSudoListingCallIsBareAndSanitized(t *testing.T) {
	t.Setenv("CILOCK_SUDO_SENTINEL", "leaked")
	t.Setenv("COLUMNS", "20")
	f := &fakeSudo{listing: listingWith(exactRuleListed), argvExit: 1}
	got, err := chooseWithFake(t, f)
	wantSudoLaunch(t, f, got, err)
	calls := f.calls(t)
	if !strings.Contains(calls, "ARGS -n -l\n") || strings.Count(calls, "ARGS ") != 1 {
		t.Fatalf("want exactly one call, `-n -l` with no command, got:\n%s", calls)
	}
	for _, leaked := range []string{"CILOCK_SUDO_SENTINEL", "COLUMNS=", "HOME="} {
		if strings.Contains(calls, "ENV "+leaked) {
			t.Fatalf("sudo saw inherited %s:\n%s", leaked, calls)
		}
	}
	if !strings.Contains(calls, "ENV LC_ALL=C\n") {
		t.Fatalf("listing must run under LC_ALL=C:\n%s", calls)
	}
}

func TestSudoListsExactRuleMatchesWholeLinesOnly(t *testing.T) {
	cmd := logStreamSudoersCommand(testLogPath, testPredicate)
	if !sudoListsExactRule(listingWith(exactRuleListed), cmd) {
		t.Fatal("exact rule not recognised")
	}
	if sudoListsExactRule("    # "+exactRuleListed+"\n", cmd) {
		t.Fatal("a line that merely contains the rule must not count")
	}
}
