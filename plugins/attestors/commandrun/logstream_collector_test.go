// jade:ring local
package commandrun

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const (
	testLogPath   = "/usr/bin/log"
	testSudoPath  = "/usr/bin/sudo"
	testPredicate = `senderImagePath CONTAINS[c] "sandbox"`
)

// exactRuleListed is the documented rule as `sudo -l` prints it.
const exactRuleListed = `(root) NOPASSWD: /usr/bin/log stream --style ndjson --predicate senderImagePath CONTAINS\[c\] "sandbox"`

// fakeCollectorHost is the fake exec: it answers the membership question and
// the sudo listing, and counts how often the listing was asked for.
type fakeCollectorHost struct {
	root     bool
	admin    bool
	adminErr error
	listing  string
	sudoErr  error
	asked    int
}

func (f *fakeCollectorHost) host() collectorHost {
	return collectorHost{
		userName: func() string { return "ci" },
		isRoot:   func() bool { return f.root },
		isAdmin:  func() (bool, error) { return f.admin, f.adminErr },
		sudoList: func() (string, error) {
			f.asked++
			return f.listing, f.sudoErr
		},
	}
}

func wantDirect() []string {
	return []string{testLogPath, "stream", "--style", "ndjson", "--predicate", testPredicate}
}

func TestCollectorAdminRunsLogDirectly(t *testing.T) {
	f := &fakeCollectorHost{admin: true}
	got, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err != nil {
		t.Fatalf("chooseCollector: %v", err)
	}
	if got.viaSudo || !slices.Equal(got.argv, wantDirect()) {
		t.Fatalf("admin launch = %+v, want direct %q", got, wantDirect())
	}
	if f.asked != 0 {
		t.Fatalf("an admin must not consult sudo, asked %d times", f.asked)
	}
}

func TestCollectorRootRunsLogDirectly(t *testing.T) {
	f := &fakeCollectorHost{root: true, adminErr: errors.New("must not be asked")}
	got, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err != nil {
		t.Fatalf("chooseCollector: %v", err)
	}
	if got.viaSudo || !slices.Equal(got.argv, wantDirect()) || f.asked != 0 {
		t.Fatalf("root launch = %+v (sudo asked %d times), want direct", got, f.asked)
	}
}

func TestCollectorNonAdminWithRuleRunsThroughSudo(t *testing.T) {
	f := &fakeCollectorHost{listing: "User ci may run the following commands on mint-1:\n    " + exactRuleListed + "\n"}
	got, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err != nil {
		t.Fatalf("chooseCollector: %v", err)
	}
	want := append([]string{testSudoPath, "-n"}, wantDirect()...)
	if !got.viaSudo || !slices.Equal(got.argv, want) {
		t.Fatalf("launch = %+v, want sudo argv %q", got, want)
	}
	if f.asked != 1 {
		t.Fatalf("sudo listing asked %d times, want once", f.asked)
	}
}

func TestCollectorNeitherPathRefusesNamingBothFixes(t *testing.T) {
	f := &fakeCollectorHost{sudoErr: errors.New("exit status 1: a password is required")}
	_, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err == nil {
		t.Fatal("a non-admin with no sudo rule must be refused before anything runs")
	}
	msg := err.Error()
	for _, want := range []string{
		`user "ci" is not one`,
		"dseditgroup -o edit -a ci -t user admin",
		"visudo -f /etc/sudoers.d/cilock-logstream",
		`ci ALL=(root) NOPASSWD: /usr/bin/log stream --style ndjson --predicate senderImagePath CONTAINS\[c\] "sandbox"`,
		"a password is required",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal is missing %q:\n%s", want, msg)
		}
	}
}

// An error reading membership is not an answer. Guessing "not admin" would
// route an admin through sudo; guessing "admin" would hide the real cause
// behind log's refusal. Refuse and say why.
func TestCollectorMembershipErrorRefuses(t *testing.T) {
	f := &fakeCollectorHost{adminErr: errors.New("opendirectoryd unavailable")}
	_, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err == nil || !strings.Contains(err.Error(), "opendirectoryd unavailable") {
		t.Fatalf("membership lookup failure must refuse and carry the cause, got %v", err)
	}
	if f.asked != 0 {
		t.Fatalf("sudo must not be consulted on an unknown membership, asked %d times", f.asked)
	}
}

// The documented line, byte for byte. `[` and `]` MUST be escaped: sudoers
// matches arguments with fnmatch, where a bare [c] is a class matching the
// letter c, so an unescaped rule would admit CONTAINSc and not our predicate.
func TestLogStreamSudoersLineIsPinned(t *testing.T) {
	got := logStreamSudoersLine("ci", testLogPath, testPredicate)
	want := `ci ALL=(root) NOPASSWD: /usr/bin/log stream --style ndjson --predicate senderImagePath CONTAINS\[c\] "sandbox"`
	if got != want {
		t.Fatalf("sudoers line\n got %s\nwant %s", got, want)
	}
}

func TestSudoersArgEscapesEverySpecial(t *testing.T) {
	got := sudoersEscapeArg(`a\b,c:d=e*f?g[h]i!j#k`)
	want := `a\\b\,c\:d\=e\*f\?g\[h\]i\!j\#k`
	if got != want {
		t.Fatalf("escape\n got %s\nwant %s", got, want)
	}
}

func TestCollectorRefusalHintOnlyForAdminRefusal(t *testing.T) {
	if h := collectorRefusalHint("log: Must be admin to run 'stream' command", "ci", testLogPath, testPredicate); !strings.Contains(h, "dseditgroup") || !strings.Contains(h, `CONTAINS\[c\]`) {
		t.Fatalf("admin refusal must carry both fixes, got %q", h)
	}
	if h := collectorRefusalHint("some other failure", "ci", testLogPath, testPredicate); h != "" {
		t.Fatalf("unrelated stderr must add nothing, got %q", h)
	}
}

// Inside another sandbox, starting sudo at all is refused (EPERM). That is the
// nesting case, and the refusal must say so, not only name the sudoers fixes.
func TestCollectorSudoExecNotPermittedNamesNesting(t *testing.T) {
	f := &fakeCollectorHost{sudoErr: fmt.Errorf("wrapped: %w", &fs.PathError{Op: "fork/exec", Path: testSudoPath, Err: syscall.EPERM})}
	_, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err == nil || !strings.Contains(err.Error(), "sandboxes do not nest") {
		t.Fatalf("EPERM starting sudo must explain nesting, got %v", err)
	}
	f = &fakeCollectorHost{sudoErr: errors.New("exit status 1: a password is required")}
	if _, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate); err == nil || strings.Contains(err.Error(), "nest") {
		t.Fatalf("an ordinary sudo refusal must not blame nesting, got %v", err)
	}
}
