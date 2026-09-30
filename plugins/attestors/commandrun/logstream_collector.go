package commandrun

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strings"
	"time"
)

// How the macOS tracer starts `log stream`. /usr/bin/log refuses `stream` to
// anyone outside the group named admin, and it is SIP-protected, so it cannot
// be wrapped. A non-admin can still run it through a NOPASSWD sudoers rule for
// exactly that command. Design: docs/design/cilock-macos-trace-non-admin.md.
//
// This file is platform-neutral so the choice is unit-tested everywhere; only
// the darwin tracer calls it.

// sudoToolPath is absolute for the same reason logToolPath is: a PATH-resolved
// sudo would let anything earlier on PATH become the collector.
var sudoToolPath = "/usr/bin/sudo"

// sudoCheckTimeout bounds `sudo -n -l`, which never prompts but does consult
// the directory service.
const sudoCheckTimeout = 10 * time.Second

// collectorLaunch is the argv the tracer execs for the collector.
type collectorLaunch struct {
	argv    []string
	viaSudo bool
}

// collectorHost is the seam the chooser reads the machine through.
type collectorHost struct {
	userName   func() string
	isRoot     func() bool
	isAdmin    func() (bool, error)
	sudoAllows func(argv []string) error
}

func logStreamArgv(logPath, predicate string) []string {
	return []string{logPath, "stream", "--style", "ndjson", "--predicate", predicate}
}

// chooseCollector picks direct, sudo, or refusal, before anything is started.
func chooseCollector(h collectorHost, logPath, sudoPath, predicate string) (collectorLaunch, error) {
	direct := logStreamArgv(logPath, predicate)
	if h.isRoot() {
		return collectorLaunch{argv: direct}, nil
	}
	admin, err := h.isAdmin()
	if err != nil {
		return collectorLaunch{}, fmt.Errorf("macOS process tracing: could not tell whether user %q is in the admin "+
			"group, which decides how %s can be run: %w", h.userName(), logPath, err)
	}
	if admin {
		return collectorLaunch{argv: direct}, nil
	}
	sudoErr := h.sudoAllows(direct)
	if sudoErr == nil {
		return collectorLaunch{argv: append([]string{sudoPath, "-n"}, direct...), viaSudo: true}, nil
	}
	return collectorLaunch{}, fmt.Errorf("%s (%s -n -l said: %w)",
		nonAdminFixes(h.userName(), logPath, predicate), sudoPath, sudoErr)
}

// nonAdminFixes names both ways out, with the exact sudoers line.
func nonAdminFixes(userName, logPath, predicate string) string {
	return fmt.Sprintf("macOS process tracing reads kernel sandbox reports with `%s stream`, which macOS runs only "+
		"for members of the admin group, and user %q is not one. Fix either way: add the user to admin "+
		"(dseditgroup -o edit -a %s -t user admin), or let it run exactly that command as root with this "+
		"sudoers rule, installed with `visudo -f /etc/sudoers.d/cilock-logstream`:\n%s",
		logPath, userName, userName, logStreamSudoersLine(userName, logPath, predicate))
}

// collectorRefusalHint turns log's own admin refusal, seen on the collector's
// stderr, into the same two fixes. It covers a membership answer that
// disagrees with log's check; any other stderr adds nothing.
func collectorRefusalHint(stderr, userName, logPath, predicate string) string {
	if !strings.Contains(stderr, "Must be admin") {
		return ""
	}
	return " " + nonAdminFixes(userName, logPath, predicate)
}

// logStreamSudoersLine is the narrowest rule sudoers can express: the full
// argument list pinned, so no other log subcommand or predicate matches.
func logStreamSudoersLine(userName, logPath, predicate string) string {
	argv := logStreamArgv(logPath, predicate)
	args := make([]string, 0, len(argv)-1)
	for _, a := range argv[1:] {
		args = append(args, sudoersEscapeArg(a))
	}
	return fmt.Sprintf("%s ALL=(root) NOPASSWD: %s %s", userName, logPath, strings.Join(args, " "))
}

// sudoersEscapeArg backslash-escapes what sudoers reads specially in a command
// argument: its own separators and fnmatch's wildcards. An unescaped [c] is a
// character class matching the letter c, not the text "[c]". Spaces are left
// alone: sudoers compares the space-joined argument string.
func sudoersEscapeArg(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\,:=*?[]!#`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// defaultCollectorHost reads the real machine.
func defaultCollectorHost() collectorHost {
	return collectorHost{
		userName: func() string {
			if u, err := user.Current(); err == nil {
				return u.Username
			}
			return fmt.Sprintf("uid %d", os.Getuid())
		},
		isRoot:  func() bool { return os.Geteuid() == 0 },
		isAdmin: currentUserInAdmin,
		sudoAllows: func(argv []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), sudoCheckTimeout)
			defer cancel()
			// #nosec G204 -- fixed sudo path; argv is the tracer's own constants.
			c := exec.CommandContext(ctx, sudoToolPath, append([]string{"-n", "-l"}, argv...)...)
			var out bytes.Buffer
			c.Stdout, c.Stderr = &out, &out
			if err := c.Run(); err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
			}
			return nil
		},
	}
}

// currentUserInAdmin asks the directory service (os/user on darwin calls
// getgrouplist); /etc/group does not list admin's members on macOS.
func currentUserInAdmin() (bool, error) {
	u, err := user.Current()
	if err != nil {
		return false, err
	}
	g, err := user.LookupGroup("admin")
	if err != nil {
		return false, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, g.Gid), nil
}
