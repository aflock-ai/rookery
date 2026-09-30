package commandrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
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
	userName func() string
	isRoot   func() bool
	isAdmin  func() (bool, error)
	// sudoList returns what `sudo -n -l` (no command) prints, or an error
	// when it does not exit 0.
	sudoList func() (string, error)
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
	listing, err := h.sudoList()
	if err != nil {
		nest := ""
		if errors.Is(err, fs.ErrPermission) {
			// Not a sudo answer: the kernel would not start sudo at all, which
			// is what running inside another sandbox looks like.
			nest = " Starting sudo was not permitted, which is what an outer sandbox does: sandboxes do " +
				"not nest, so cilock cannot trace a command that is itself already sandboxed. Re-run " +
				"outside the outer sandbox, or disable tracing for this step."
		}
		return collectorLaunch{}, fmt.Errorf("%s (%s -n -l said: %w)%s",
			nonAdminFixes(h.userName(), logPath, predicate), sudoPath, err, nest)
	}
	if !sudoListsExactRule(listing, logStreamSudoersCommand(logPath, predicate)) {
		return collectorLaunch{}, fmt.Errorf("%s (%s -n -l lists no rule equal to it)",
			nonAdminFixes(h.userName(), logPath, predicate), sudoPath)
	}
	return collectorLaunch{argv: append([]string{sudoPath, "-n"}, direct...), viaSudo: true}, nil
}

// sudoListsExactRule reports whether the listing has a line that is exactly
// the rule cilock documents, as sudo -l prints it: "(root) NOPASSWD: <cmd>".
//
// Why not ask sudo about the argv (`sudo -n -l <argv>`)? sudo 1.9.13p2 on
// macOS never matches a rule that has arguments that way (exit 1), although
// `sudo -n <argv>` itself runs under the same rule. So cilock reads the bare
// listing and compares text.
//
// Why only the exact line? A text comparison cannot evaluate sudoers
// matching, and it should not try: a wildcard (`/usr/bin/log stream *`), an
// argument-less `/usr/bin/log`, `(ALL)` or `ALL` would each run our argv, but
// they grant root far more than the one command, and reproducing fnmatch,
// aliases and last-match-wins to decide they cover us would be a second
// sudoers parser to get wrong. The exact line is known, by construction and
// by proof on a worker, to grant this command and nothing else, so it is the
// only one cilock relies on. Anything else is refused with the exact line
// named, which is the fix. A whole-line match also rejects the rule joined
// with other commands on one line, and a password-requiring or non-root form.
func sudoListsExactRule(listing, cmd string) bool {
	want := "(root) NOPASSWD: " + cmd
	for _, line := range strings.Split(listing, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
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
	return fmt.Sprintf("%s ALL=(root) NOPASSWD: %s", userName, logStreamSudoersCommand(logPath, predicate))
}

// logStreamSudoersCommand is the command part of that rule, escaped as
// sudoers source, which is also how sudo -l prints it back.
func logStreamSudoersCommand(logPath, predicate string) string {
	argv := logStreamArgv(logPath, predicate)
	args := make([]string, 0, len(argv)-1)
	for _, a := range argv[1:] {
		args = append(args, sudoersEscapeArg(a))
	}
	return logPath + " " + strings.Join(args, " ")
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
		sudoList: func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), sudoCheckTimeout)
			defer cancel()
			// #nosec G204 -- the pinned sudo path and fixed flags, nothing else.
			c := exec.CommandContext(ctx, sudoToolPath, "-n", "-l")
			// Set, not inherited: nothing in the caller's environment
			// reaches sudo. LC_ALL=C keeps the listing untranslated; no
			// COLUMNS, so a piped listing is never wrapped.
			c.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
			var out, errOut bytes.Buffer
			c.Stdout, c.Stderr = &out, &errOut
			if err := c.Run(); err != nil {
				return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(errOut.String()+" "+out.String()))
			}
			return out.String(), nil
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
