// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

const (
	defaultPushgateWaitTimeout = 15 * time.Minute
	defaultPushgatePoll        = 5 * time.Second
	maxPushgateStatusBody      = 64 << 10
)

// Pushgate delivery states, exactly as the delivery-status endpoint reports
// them. They are wire values, so they are compared and never localized.
const (
	pushgateStateNotFound   = "not_found"
	pushgateStateQueued     = "queued"
	pushgateStateProcessing = "processing"
	pushgateStateDelivered  = "delivered"
	pushgateStateConflict   = "conflict"
	pushgateStateFailed     = "failed"
	pushgateStateRefused    = "refused"
	pushgateStateUnknown    = "unknown"
)

// Pushgate admission verdicts. The refusal verdict is deliberately an alias of
// the refused STATE rather than a second literal: the ledger records a single
// refusal, and the status endpoint echoes that one token in both fields.
const (
	pushgateVerdictAccepted = "accepted"
	pushgateVerdictRefused  = pushgateStateRefused
)

var (
	runPushgateGit = func(ctx context.Context, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "git", args...).Output() //nolint:gosec // executable is fixed; callers validate the only user-provided argument.
		if err != nil {
			// A Git push URL may contain a repository credential. Never include
			// arguments, stdout, or stderr in the returned error.
			return "", errors.New("git metadata is unavailable")
		}
		return strings.TrimSpace(string(out)), nil
	}
	discoverPushgateOrigin = func(platformURL string) (string, error) {
		disc, err := platformconfig.Discover(platformURL)
		if err != nil {
			return "", err
		}
		if disc.PushgateURL == "" {
			return "", errors.New("platform discovery does not advertise Pushgate")
		}
		return disc.PushgateURL, nil
	}
	pushgateStatusHTTPClient = &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Never forward the repository credential to a redirect target.
			return http.ErrUseLastResponse
		},
	}
)

type pushgateStatusOptions struct {
	remote       string
	ref          string
	commit       string
	wait         bool
	timeout      time.Duration
	pollInterval time.Duration
	json         bool
}

// pushgateStatusReportedError means the terminal status was already written to
// stdout, but the command must still exit non-zero. RunE uses the type to avoid
// appending a second JSON document after the status object.
type pushgateStatusReportedError struct {
	state string
}

func (e *pushgateStatusReportedError) Error() string {
	return fmt.Sprintf("Pushgate delivery ended in state %s", e.state)
}

type pushgateDeliveryStatus struct {
	Version            string  `json:"version"`
	PushID             string  `json:"push_id,omitempty"`
	Ref                string  `json:"ref"`
	Commit             string  `json:"commit"`
	Verdict            string  `json:"verdict,omitempty"`
	State              string  `json:"state"`
	Terminal           bool    `json:"terminal"`
	Attempts           int     `json:"attempts,omitempty"`
	AdmittedAt         *string `json:"admitted_at,omitempty"`
	DeliveredAt        *string `json:"delivered_at,omitempty"`
	RetentionExpiresAt *string `json:"retention_expires_at,omitempty"`
	Detail             *string `json:"detail,omitempty"`
	Remediation        *string `json:"remediation,omitempty"`
}

// PushgateCmd groups the read-only Pushgate delivery operations. Evidence
// creation remains under run/attest; this domain answers what happened after
// an authenticated Git push was admitted.
func PushgateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "pushgate", Short: "Inspect delivery of pushes accepted by Pushgate"}
	cmd.AddCommand(pushgateStatusCmd())
	return cmd
}

func pushgateStatusCmd() *cobra.Command {
	o := &pushgateStatusOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show whether the current commit was accepted and delivered",
		Long: `Read the exact Pushgate delivery record for a Git ref and commit.

By default CI/lock discovers the current branch, HEAD commit, selected platform,
and configured Pushgate Git remote. A checked-out tag or any other detached HEAD
has no branch to discover, so it needs an explicit --ref. Use --wait to remain
attached until Git-provider delivery finishes or the timeout expires. This
command is read-only.`,
		Example: `  cilock pushgate status
  cilock pushgate status --wait
  cilock pushgate status --wait --timeout 20m --json`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := runPushgateStatus(cmd, o)
			var reported *pushgateStatusReportedError
			if err != nil && o.json && !errors.As(err, &reported) {
				_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"version": "v1",
					"error": map[string]string{
						"code": "pushgate_status_failed", "message": err.Error(),
					},
				})
			}
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.remote, "remote", "", "Git remote name (default: infer the configured Pushgate remote)")
	// Default discovery is `git symbolic-ref HEAD`, which resolves a BRANCH and
	// nothing else. A checked-out tag is a detached HEAD, so it needs --ref --
	// promising to infer one would be a claim this cannot keep, and guessing
	// among the several tags that may point at one commit would be worse.
	f.StringVar(&o.ref, "ref", "", "Fully-qualified Git ref (default: current branch; a tag or detached HEAD needs --ref)")
	f.StringVar(&o.commit, "commit", "", "Exact lowercase 40-character commit (default: HEAD)")
	f.BoolVar(&o.wait, "wait", false, "Wait until the push is delivered or reaches a terminal failure")
	f.DurationVar(&o.timeout, "timeout", defaultPushgateWaitTimeout, "Maximum time to wait for delivery")
	f.DurationVar(&o.pollInterval, "poll-interval", defaultPushgatePoll, "Status polling interval")
	_ = f.MarkHidden("poll-interval")
	f.BoolVar(&o.json, "json", false, "Emit the final status as one JSON object")
	return cmd
}

func runPushgateStatus(cmd *cobra.Command, o *pushgateStatusOptions) error {
	if o.timeout <= 0 || o.pollInterval <= 0 {
		return errors.New("--timeout and --poll-interval must be greater than zero")
	}
	ref, commit, endpoint, username, password, err := resolvePushgateStatusTarget(cmd.Context(), o)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	cancel := func() {}
	if o.wait {
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
	}
	defer cancel()

	previous := ""
	for {
		status, fetchErr := fetchPushgateStatus(ctx, endpoint, username, password, ref, commit)
		if fetchErr != nil {
			return fetchErr
		}
		if !o.wait || status.Terminal {
			return reportFinalPushgateStatus(cmd, status, o)
		}
		var err error
		previous, err = reportPushgateProgress(cmd, status, o, previous)
		if err != nil {
			return err
		}
		if err := waitForNextPushgatePoll(ctx, o.pollInterval); err != nil {
			return err
		}
	}
}

// reportFinalPushgateStatus writes the terminal status and converts a
// non-delivered outcome into an error, but ONLY when the caller asked to wait.
// A plain `status` query reports what it found and exits zero; it is a question,
// not an assertion that delivery succeeded.
func reportFinalPushgateStatus(cmd *cobra.Command, status *pushgateDeliveryStatus, o *pushgateStatusOptions) error {
	if err := writePushgateStatus(cmd.OutOrStdout(), status, o.json); err != nil {
		return err
	}
	if o.wait && status.State != pushgateStateDelivered {
		return &pushgateStatusReportedError{state: status.State}
	}
	return nil
}

// reportPushgateProgress prints a line only when the state actually CHANGED,
// so a long wait does not scroll the same word past the operator, and returns
// the state to compare against next time. JSON mode stays silent: its consumer
// wants one object, not a progress narration.
func reportPushgateProgress(cmd *cobra.Command, status *pushgateDeliveryStatus, o *pushgateStatusOptions, previous string) (string, error) {
	if o.json || status.State == previous {
		return previous, nil
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Pushgate: %s (attempts %d)\n", status.State, status.Attempts); err != nil {
		return previous, err
	}
	return status.State, nil
}

// waitForNextPushgatePoll sleeps between polls, and stops the timer on the
// cancellation path so a caller that gives up does not leak it.
func waitForNextPushgatePoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	select {
	case <-ctx.Done():
		timer.Stop()
		return fmt.Errorf("timed out waiting for Pushgate delivery: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func resolvePushgateStatusTarget(ctx context.Context, o *pushgateStatusOptions) (ref, commit, endpoint, username, password string, err error) {
	ref = strings.TrimSpace(o.ref)
	if ref == "" {
		ref, err = runPushgateGit(ctx, "symbolic-ref", "--quiet", "HEAD")
		if err != nil {
			return "", "", "", "", "", errors.New("detached HEAD: pass --ref with the exact pushed ref")
		}
	}
	if !validPushgateRef(ref) {
		return "", "", "", "", "", errors.New("--ref must be a fully-qualified refs/heads/* or refs/tags/* ref")
	}
	commit = strings.TrimSpace(o.commit)
	if commit == "" {
		commit, err = runPushgateGit(ctx, "rev-parse", "HEAD^{commit}")
		if err != nil {
			return "", "", "", "", "", errors.New("could not resolve HEAD; pass --commit")
		}
	}
	if !validPushgateCommit(commit) {
		return "", "", "", "", "", errors.New("--commit must be an exact lowercase 40-character commit")
	}

	platformURL := auth.ActivePlatformURL()
	if platformURL == "" {
		platformURL = platformconfig.DefaultPlatformURL
	}
	trustedOrigin, err := discoverPushgateOrigin(platformURL)
	if err != nil {
		return "", "", "", "", "", errors.New("could not discover the Pushgate origin from the selected platform")
	}
	remoteURL, err := resolvePushgateRemote(ctx, o.remote, ref, trustedOrigin)
	if err != nil {
		return "", "", "", "", "", err
	}
	endpoint, username, password, err = parsePushgateRemote(remoteURL, trustedOrigin)
	if err != nil {
		return "", "", "", "", "", err
	}
	return ref, commit, endpoint, username, password, nil
}

func resolvePushgateRemote(ctx context.Context, explicit, ref, trustedOrigin string) (string, error) {
	if explicit != "" {
		if !validRemoteName(explicit) {
			return "", errors.New("--remote must be a Git remote name")
		}
		u, err := runPushgateGit(ctx, "remote", "get-url", "--push", explicit)
		if err != nil {
			return "", errors.New("the requested Git remote has no push URL")
		}
		return u, nil
	}
	candidates := pushgateRemoteCandidates(ctx, ref)
	seen := map[string]bool{}
	var matches []string
	for _, name := range candidates {
		if !validRemoteName(name) || seen[name] {
			continue
		}
		seen[name] = true
		rawURL, err := runPushgateGit(ctx, "remote", "get-url", "--push", name)
		if err != nil {
			continue
		}
		if _, _, _, err = parsePushgateRemote(rawURL, trustedOrigin); err == nil {
			matches = append(matches, rawURL)
		}
	}
	if len(matches) == 0 {
		return "", errors.New("no Git remote matches the Pushgate origin advertised by the selected platform")
	}
	if len(matches) > 1 {
		return "", errors.New("multiple Pushgate Git remotes found; select one with --remote")
	}
	return matches[0], nil
}

// pushgateRemoteCandidates lists the Git remotes worth testing against the
// platform's advertised Pushgate origin, in the order a user would expect them
// tried: the conventional name first, then whatever this branch is actually
// configured to push to, then origin, then everything else.
//
// Order matters only for readability -- the caller requires exactly one MATCH
// and refuses on ambiguity, so a wrong guess here cannot silently select the
// wrong remote.
func pushgateRemoteCandidates(ctx context.Context, ref string) []string {
	candidates := []string{"pushgate"}
	if branch := strings.TrimPrefix(ref, "refs/heads/"); branch != ref {
		for _, key := range []string{
			"branch." + branch + ".pushRemote",
			"remote.pushDefault",
			"branch." + branch + ".remote",
		} {
			if value, err := runPushgateGit(ctx, "config", "--get", key); err == nil && validRemoteName(value) {
				candidates = append(candidates, value)
			}
		}
	}
	candidates = append(candidates, "origin")
	if names, err := runPushgateGit(ctx, "remote"); err == nil {
		candidates = append(candidates, strings.Fields(names)...)
	}
	return candidates
}

// allowedIdentifierRunes reports whether every rune in value is an ASCII
// alphanumeric or one of the punctuation runes in extra. Pushgate identifiers,
// Git remote names, and ref names each allow a slightly different punctuation
// set but share this ASCII-only rule, which keeps a status document from
// smuggling control characters or non-ASCII homoglyphs past validation.
func allowedIdentifierRunes(value, extra string) bool {
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(extra, r)) {
			return false
		}
	}
	return true
}

func validRemoteName(name string) bool {
	if name == "" || strings.HasPrefix(name, "-") || len(name) > 200 || strings.Contains(name, "..") {
		return false
	}
	return allowedIdentifierRunes(name, "._/-")
}

// parseTrustedPushgateOrigin validates the origin that platform discovery
// handed us BEFORE it is ever used to authorize a Git remote's credential. A
// discovery document that is not a bare, secure origin cannot be trusted to
// vouch for anything, so it is rejected rather than normalized.
func parseTrustedPushgateOrigin(trustedOrigin string) (*url.URL, error) {
	trusted, err := url.Parse(strings.TrimSpace(trustedOrigin))
	if err != nil || trusted.Host == "" || trusted.User != nil || trusted.RawQuery != "" || trusted.Fragment != "" || (trusted.Path != "" && trusted.Path != "/") {
		return nil, errors.New("platform discovery returned an invalid Pushgate origin")
	}
	if err := platformconfig.RequireSecurePlatformURL(trusted.String()); err != nil {
		return nil, errors.New("platform discovery returned an insecure Pushgate origin")
	}
	return trusted, nil
}

// validPushgateRepoPath reports whether the URL path is one of the two Pushgate
// repository shapes: /gh/<owner>/<repo>.git or /r/<a>/<b>/<repo>.git.
func validPushgateRepoPath(u *url.URL) bool {
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	return len(parts) == 3 && parts[0] == "gh" && strings.HasSuffix(parts[2], ".git") ||
		len(parts) == 4 && parts[0] == "r" && strings.HasSuffix(parts[3], ".git")
}

func parsePushgateRemote(raw, trustedOrigin string) (endpoint, username, password string, err error) {
	trusted, err := parseTrustedPushgateOrigin(trustedOrigin)
	if err != nil {
		return "", "", "", err
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || !platformconfig.SameOrigin(u.String(), trusted.String()) {
		return "", "", "", errors.New("the selected Git remote does not match the platform's discovered Pushgate origin")
	}
	if !validPushgateRepoPath(u) || u.RawQuery != "" || u.Fragment != "" || u.User == nil {
		return "", "", "", errors.New("the selected Git remote is not a credentialed Pushgate repository URL")
	}
	username = u.User.Username()
	password, _ = u.User.Password()
	if username == "" && password == "" {
		return "", "", "", errors.New("the selected Pushgate remote has no repository credential")
	}
	u.User = nil
	u.Path = strings.TrimSuffix(u.Path, "/") + "/delivery-status"
	u.RawPath = ""
	return u.String(), username, password, nil
}

func fetchPushgateStatus(ctx context.Context, endpoint, username, password, ref, commit string) (*pushgateDeliveryStatus, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("invalid Pushgate status endpoint")
	}
	q := u.Query()
	q.Set("ref", ref)
	q.Set("commit", commit)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("could not create Pushgate status request")
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/json")
	resp, err := pushgateStatusHTTPClient.Do(req)
	if err != nil {
		return nil, errors.New("the Pushgate status endpoint is unavailable")
	}
	// The close error is deliberately discarded: the response has already been
	// read by the time it fires, so it cannot change the verdict, and errcheck
	// wants the intent stated rather than implied.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxPushgateStatusBody))
		return nil, fmt.Errorf("the Pushgate status request failed (HTTP %d)", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPushgateStatusBody+1))
	if err != nil || len(body) > maxPushgateStatusBody {
		return nil, errors.New("the Pushgate status response was unreadable")
	}
	var status pushgateDeliveryStatus
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&status); err != nil {
		return nil, errors.New("the Pushgate status response was invalid")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("the Pushgate status response held more than one document")
	}
	if err := validatePushgateStatus(&status, ref, commit); err != nil {
		return nil, err
	}
	return &status, nil
}

func validatePushgateStatus(s *pushgateDeliveryStatus, ref, commit string) error {
	if s.Version != "v1" || s.Ref != ref || s.Commit != commit {
		return errors.New("the Pushgate status did not match the requested ref and commit")
	}
	if s.Attempts < 0 || !validStatusIdentifier(s.PushID) ||
		!validStatusTime(s.AdmittedAt) || !validStatusTime(s.DeliveredAt) || !validStatusTime(s.RetentionExpiresAt) ||
		!validStatusText(s.Detail, 300) || !validStatusText(s.Remediation, 500) {
		return errors.New("the Pushgate status contained unsafe or malformed fields")
	}
	if err := validatePushgateTerminalFlag(s); err != nil {
		return err
	}
	return validatePushgateStateVerdict(s)
}

// validatePushgateTerminalFlag refuses a status whose `terminal` flag disagrees
// with its own state name. The two are reported independently, so a server that
// gets them out of step is either buggy or lying, and a caller polling on
// `terminal` would otherwise spin forever or stop early.
func validatePushgateTerminalFlag(s *pushgateDeliveryStatus) error {
	terminal := map[string]bool{
		pushgateStateDelivered: true, pushgateStateConflict: true, pushgateStateFailed: true,
		pushgateStateRefused: true, pushgateStateUnknown: true,
	}
	nonterminal := map[string]bool{
		pushgateStateNotFound: true, pushgateStateQueued: true, pushgateStateProcessing: true,
	}
	if terminal[s.State] && s.Terminal || nonterminal[s.State] && !s.Terminal {
		return nil
	}
	if terminal[s.State] || nonterminal[s.State] {
		return errors.New("the Pushgate status disagrees with its own terminal flag")
	}
	return errors.New("the Pushgate status reported an unsupported delivery state")
}

// validatePushgateStateVerdict refuses a status whose verdict cannot go with its
// state -- most importantly a `not_found` that nonetheless carries authority,
// which would let a push that was never admitted read as one that was.
func validatePushgateStateVerdict(s *pushgateDeliveryStatus) error {
	switch s.State {
	case pushgateStateNotFound:
		if s.Verdict != "" || s.PushID != "" {
			return errors.New("the Pushgate status carries authority for a push it did not find")
		}
	case pushgateStateRefused:
		if s.Verdict != pushgateVerdictRefused {
			return errors.New("the Pushgate status reported a refused state without a refusal verdict")
		}
	case pushgateStateQueued, pushgateStateDelivered, pushgateStateConflict, pushgateStateFailed:
		if s.Verdict != pushgateVerdictAccepted {
			return errors.New("the Pushgate status reported a delivery state without an accepted verdict")
		}
	case pushgateStateProcessing, pushgateStateUnknown:
		if s.Verdict != pushgateVerdictAccepted && s.Verdict != pushgateVerdictRefused {
			return errors.New("the Pushgate status reported a ledger state without a known verdict")
		}
	}
	return nil
}

func validStatusIdentifier(value string) bool {
	if len(value) > 128 {
		return false
	}
	return allowedIdentifierRunes(value, "._:-")
}

func validStatusTime(value *string) bool {
	if value == nil {
		return true
	}
	if len(*value) > 40 {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, *value)
	return err == nil
}

func validStatusText(value *string, limit int) bool {
	if value == nil {
		return true
	}
	// The protocol limits UTF-8 bytes, not Go runes or JavaScript UTF-16 code
	// units. This matches the Worker and keeps multibyte status text portable.
	if len([]byte(*value)) > limit {
		return false
	}
	for _, r := range *value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func writePushgateStatus(w io.Writer, status *pushgateDeliveryStatus, jsonOut bool) error {
	if jsonOut {
		return json.NewEncoder(w).Encode(status)
	}
	if _, err := fmt.Fprintf(w, "Pushgate delivery\n  ref:       %s\n  commit:    %s\n  state:     %s\n", status.Ref, status.Commit, status.State); err != nil {
		return err
	}
	if status.Attempts > 0 {
		_, _ = fmt.Fprintf(w, "  attempts:  %d\n", status.Attempts)
	}
	for _, item := range []struct {
		label string
		value *string
	}{
		{"admitted", status.AdmittedAt}, {"delivered", status.DeliveredAt}, {"expires", status.RetentionExpiresAt},
		{"detail", status.Detail}, {"next", status.Remediation},
	} {
		if item.value != nil && *item.value != "" {
			if _, err := fmt.Fprintf(w, "  %-10s %s\n", item.label+":", *item.value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validPushgateCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// pushgateRefPunctuation is the punctuation a Pushgate ref may carry beyond
// ASCII alphanumerics.
//
// This is deliberately NARROWER than `git check-ref-format`, which also accepts
// & | < > $ ' " ( ) { } ! # % , ; = @ and more. A ref reaching this function is
// a status LOOKUP KEY: it goes into a URL query, a log line, and a rendered
// status page, and admitting shell- and markup-active characters widens what
// every one of those consumers must survive, in exchange for ref shapes that do
// not occur in practice. A caller holding such a ref is not stuck; it is asked
// to pass --ref, and the refusal is explicit rather than silent.
//
// `+` IS accepted, because SemVer build metadata (refs/tags/v1.2.3+build.5) is
// an ordinary tag shape that git accepts and Pushgate delivers -- rejecting it
// made status unreadable for pushes the gate itself had admitted.
//
// The edge worker enforces the SAME set (validDeliveryRef in deliverystatus.js).
// The two are kept in step by a shared table in their respective tests, so the
// client can never send a ref the server would refuse.
const pushgateRefPunctuation = "._/-+"

func validPushgateRef(value string) bool {
	prefix := ""
	for _, candidate := range []string{"refs/heads/", "refs/tags/"} {
		if strings.HasPrefix(value, candidate) {
			prefix = candidate
			break
		}
	}
	name := strings.TrimPrefix(value, prefix)
	if prefix == "" || name == "" || len(value) > 256 || strings.Contains(value, "..") {
		return false
	}
	return validRefShape(name) && allowedIdentifierRunes(name, pushgateRefPunctuation)
}

// validRefShape applies git's own STRUCTURAL rules to the part of a ref after
// its refs/heads/ or refs/tags/ prefix -- the rules that are about the shape of
// the name rather than which characters it may contain. git rejects each of
// these itself, so a ref failing here was never one git could have pushed.
func validRefShape(name string) bool {
	// Lead with an alphanumeric or an underscore. The restriction exists so a
	// ref can never arrive looking like a FLAG to anything downstream that
	// forgets to use "--", which is a property of a leading "-", not of
	// punctuation in general: refs/heads/_release is an ordinary ref git
	// accepts, and refusing it bought nothing.
	first := rune(name[0])
	if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z' || first >= '0' && first <= '9' || first == '_') {
		return false
	}
	if strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		// An empty component is the "//" case; the other two are git's rules
		// against a leading dot and a ".lock" suffix on any component.
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}
