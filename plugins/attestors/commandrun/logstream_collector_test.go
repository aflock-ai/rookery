// jade:ring local
package commandrun

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const (
	testLogPath   = "/usr/bin/log"
	testSudoPath  = "/usr/bin/sudo"
	testPredicate = `senderImagePath CONTAINS[c] "sandbox"`
)

// fakeCollectorHost is the fake exec: it answers the membership question and
// records every argv the chooser asked sudo about.
type fakeCollectorHost struct {
	root     bool
	admin    bool
	adminErr error
	sudoErr  error
	asked    [][]string
}

func (f *fakeCollectorHost) host() collectorHost {
	return collectorHost{
		userName: func() string { return "ci" },
		isRoot:   func() bool { return f.root },
		isAdmin:  func() (bool, error) { return f.admin, f.adminErr },
		sudoAllows: func(argv []string) error {
			f.asked = append(f.asked, slices.Clone(argv))
			return f.sudoErr
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
	if len(f.asked) != 0 {
		t.Fatalf("an admin must not consult sudo, asked %q", f.asked)
	}
}

func TestCollectorRootRunsLogDirectly(t *testing.T) {
	f := &fakeCollectorHost{root: true, adminErr: errors.New("must not be asked")}
	got, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err != nil {
		t.Fatalf("chooseCollector: %v", err)
	}
	if got.viaSudo || !slices.Equal(got.argv, wantDirect()) || len(f.asked) != 0 {
		t.Fatalf("root launch = %+v (sudo asked %q), want direct", got, f.asked)
	}
}

func TestCollectorNonAdminWithRuleRunsThroughSudo(t *testing.T) {
	f := &fakeCollectorHost{}
	got, err := chooseCollector(f.host(), testLogPath, testSudoPath, testPredicate)
	if err != nil {
		t.Fatalf("chooseCollector: %v", err)
	}
	want := append([]string{testSudoPath, "-n"}, wantDirect()...)
	if !got.viaSudo || !slices.Equal(got.argv, want) {
		t.Fatalf("launch = %+v, want sudo argv %q", got, want)
	}
	// The check asks about exactly the command it will run, predicate as ONE
	// element: sudo -n -l is given the same argv the launch uses.
	if len(f.asked) != 1 || !slices.Equal(f.asked[0], wantDirect()) {
		t.Fatalf("sudo was asked about %q, want exactly [%q]", f.asked, wantDirect())
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
	if len(f.asked) != 0 {
		t.Fatalf("sudo must not be consulted on an unknown membership, asked %q", f.asked)
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
