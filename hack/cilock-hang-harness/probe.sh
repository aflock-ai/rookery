#!/usr/bin/env bash
# Runs ONE cilock attest invocation inside this (Linux) container under a
# watchdog. If cilock runs longer than WATCHDOG_SECS, dump the full process
# tree plus each process's State and kernel stack to stderr, then SIGKILL the
# whole group. The State letter is the answer:
#   D = uninterruptible sleep (SIGKILL-immune — fanotify/IO/NFS strand)
#   S = interruptible sleep   (a normal network wait — SIGKILL works; the
#                              bug is then "no client timeout", not D-state)
#   R = running               (a busy loop)
#
# This is the fast-iteration core: rebuild cilock on the Mac, re-run this in
# the container, read the State in <WATCHDOG_SECS instead of a 15-min CI cycle.
set -uo pipefail

WATCHDOG_SECS="${WATCHDOG_SECS:-90}"
LABEL="${LABEL:-attest}"
# Binary name to match in ps/pgrep. The colima harness runs `cilock-linux`; the
# GitHub-Actions workflow runs `.local/bin/cilock`. Default matches both.
PROBE_MATCH="${PROBE_MATCH:-cilock}"

# hang_pids enumerates the process tree to dump. Keying off the watched
# CILOCK_PID plus its descendants is name-agnostic (works for cilock-linux AND
# cilock); the PROBE_MATCH pgrep is the fallback when the root already reaped.
hang_pids() {
  local root="$1"
  { [ -n "$root" ] && kill -0 "$root" 2>/dev/null && { echo "$root"; pgrep -P "$root" 2>/dev/null; }
    pgrep -f "$PROBE_MATCH" 2>/dev/null
  } | grep -E '^[0-9]+$' | sort -un
}

# Dump process state for the cilock tree rooted at $1.
dump_state() {
  local root="$1"
  echo "================ HANG DUMP ($LABEL) ================" >&2
  echo "-- process tree --" >&2
  ps -eo pid,ppid,pgid,stat,wchan:32,comm 2>/dev/null | grep -E "${PROBE_MATCH}|PID" >&2
  for pid in $(hang_pids "$root"); do
    echo "-- pid $pid --" >&2
    awk '/^(State|Name):/' "/proc/$pid/status" 2>/dev/null >&2
    echo "  wchan: $(cat /proc/$pid/wchan 2>/dev/null)" >&2
    echo "  kernel stack:" >&2
    sed 's/^/    /' "/proc/$pid/stack" 2>/dev/null >&2 || echo "    (stack unavailable — need CAP_SYS_ADMIN/kptr)" >&2
    echo "  open sockets/files (network FDs):" >&2
    ls -l "/proc/$pid/fd" 2>/dev/null | grep -E 'socket|TCP' | sed 's/^/    /' >&2
  done
  echo "===================================================" >&2
}

# Verdict is recorded to a file by whichever party decides first. The watchdog
# writes "HUNG" BEFORE it signals cilock — otherwise `wait` could unblock (cilock
# dies on TERM) and the parent could kill the watchdog before it ever recorded
# the hang, letting a real hang pass as OK (the race Codex caught). The parent
# reads this file as the source of truth and emits the single WATCHDOG_RESULT
# line, so the marker can never be lost to a killed subshell.
VERDICT_FILE="$(mktemp)"
trap 'rm -f "$VERDICT_FILE"' EXIT

echo "▶ [$LABEL] launching cilock under ${WATCHDOG_SECS}s watchdog" >&2
"$@" &
CILOCK_PID=$!

( sleep "$WATCHDOG_SECS"
  if kill -0 "$CILOCK_PID" 2>/dev/null; then
    # Record the verdict FIRST — before any signal can let `wait` return.
    echo "HUNG" > "$VERDICT_FILE"
    echo "✗ [$LABEL] still alive after ${WATCHDOG_SECS}s — HUNG. Dumping state." >&2
    dump_state "$CILOCK_PID"
    # Try graceful, then group-kill (negative pid).
    kill -TERM "$CILOCK_PID" 2>/dev/null
    sleep 2
    kill -KILL -"$CILOCK_PID" 2>/dev/null || kill -KILL "$CILOCK_PID" 2>/dev/null
  fi
) &
WATCHDOG_PID=$!

wait "$CILOCK_PID"
RC=$?
kill "$WATCHDOG_PID" 2>/dev/null
wait "$WATCHDOG_PID" 2>/dev/null

# Parent owns the verdict line — it always runs to completion.
if [ "$(cat "$VERDICT_FILE" 2>/dev/null)" = "HUNG" ]; then
  echo "✗ [$LABEL] HUNG (watchdog-killed after ${WATCHDOG_SECS}s)" >&2
  echo "WATCHDOG_RESULT=HUNG" >&2
  exit 124
elif [ "$RC" -eq 0 ]; then
  echo "✓ [$LABEL] completed cleanly (rc=0) in <${WATCHDOG_SECS}s" >&2
  echo "WATCHDOG_RESULT=OK" >&2
else
  echo "• [$LABEL] exited rc=$RC" >&2
  echo "WATCHDOG_RESULT=EXIT_$RC" >&2
fi
exit "$RC"
