package commandrun

import (
	"errors"
	"fmt"
)

// ErrNotAttestable is the one answer every process-tracing refusal shares:
// the trace saw something it cannot vouch for, so it will not sign around it.
//
// A descendant still running at exit, one that left the process group, a
// kernel pid counter that wrapped mid-run, a sandbox report no pid could be
// read from -- each names a different cause, and each ends in the same
// decision. Callers and tests that want the DECISION ask for it here with
// errors.Is, rather than enumerating the wordings of the causes. A test that
// lists acceptable wordings fails on the next correct refusal it did not
// anticipate (the pid-wrap one did exactly that inside a 250-suite ring on
// 2026-09-16), and it pressures the next author to phrase a new refusal in
// familiar words rather than true ones.
//
// What this is NOT: a setup failure. "sandbox-exec is not usable", "could not
// start the log stream", "the collector exited during the probe" mean the
// trace never ran, and they deliberately do not carry this sentinel, so a
// test asserting the sentinel cannot be satisfied by a broken tracer.
var ErrNotAttestable = errors.New("this run is not attestable")

// ErrPIDCounterWrapped is the one cause of refusal that says nothing about
// the command: the kernel's pid counter wrapped while it ran, so pid identity
// is unprovable for that session and the trace correctly will not sign. It
// is a property of the machine at that moment (a loaded box spawning tens of
// thousands of processes wraps it in seconds), and a re-run reproduces the
// evidence. A test whose run drew this refusal has learned nothing about the
// property it was testing; it skips on this sentinel and fails on any other
// refusal. errors.Is(err, ErrNotAttestable) still holds for it.
var ErrPIDCounterWrapped = errors.New("the kernel's pid counter wrapped while the command ran")

// notAttestableError keeps the refusal's own message byte-for-byte and adds
// the sentinel identity for errors.Is. Unwrap exposes any wrapped cause so
// errors.Is and errors.As keep walking past it.
type notAttestableError struct{ err error }

func (e *notAttestableError) Error() string        { return e.err.Error() }
func (e *notAttestableError) Unwrap() error        { return e.err }
func (e *notAttestableError) Is(target error) bool { return target == ErrNotAttestable }

// notAttestable is errors.New for a refusal to sign.
// notAttestableFor is a refusal that also names its cause for errors.Is,
// with the message kept byte-for-byte for the operator.
func notAttestableFor(cause error, msg string) error {
	return &notAttestableError{err: &causedError{msg: msg, cause: cause}}
}

// causedError is a message with a cause behind it for errors.Is, without
// the cause's wording appearing in the message.
type causedError struct {
	msg   string
	cause error
}

func (e *causedError) Error() string { return e.msg }
func (e *causedError) Unwrap() error { return e.cause }

func notAttestable(msg string) error { return &notAttestableError{err: errors.New(msg)} }

// notAttestablef is fmt.Errorf for a refusal to sign; %w wrapping is preserved.
func notAttestablef(format string, a ...any) error {
	return &notAttestableError{err: fmt.Errorf(format, a...)}
}
