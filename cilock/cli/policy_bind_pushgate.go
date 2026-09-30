// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// `cilock policy bind pushgate`: hand a repository assignment to its human.
//
// Turning a release on for a repository is the human's act (the Pushgate
// contract, "Activation actor"): a tenant owner or admin reviews the exact
// before/after change and completes a fresh platform approval bound to it.
// This command prepares that review and opens it. It never calls a mutation,
// never carries a credential, and never reports the assignment as done: it
// cannot read a repository's assignment back, so success is the page's to
// show (docs/design/cilock-publish-and-assign.md).

var (
	bindPushgateReleaseRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// The connection id the Gates page links by: an exact, lowercase GitHub
	// route, the same form the platform binds repository evaluation to.
	bindPushgateRepoRe = regexp.MustCompile(`^github\.com/[a-z0-9][a-z0-9-]*/[a-z0-9_.-]+$`)
)

// pushgateCommandName is the command word both Pushgate domains use, and the
// remote name `cilock pushgate status` looks for first.
const pushgateCommandName = "pushgate"

// openReviewURL opens the review page; a var so tests never launch a browser.
var openReviewURL = auth.OpenURL

type bindPushgateOpts struct {
	release     string
	repo        string
	mode        string
	reason      string
	platformURL string
}

// PolicyBindPushgateCmd is `cilock policy bind pushgate`.
func PolicyBindPushgateCmd() *cobra.Command {
	var o bindPushgateOpts
	cmd := &cobra.Command{
		Use:   pushgateCommandName,
		Short: "Open the Pushgate review that turns a published release on for a repository",
		Long: `pushgate prepares a repository assignment and opens its review on Pushgate.

It prints the exact change and a link to the Gates page with the assign sheet
open for this release on this repository. The ONLY act that changes anything is
the human's: a tenant owner or admin picks the mode, gives the reason, presses
Sign and apply, and completes the fresh platform approval bound to that exact
change. An agent may run this command; it cannot complete the assignment.

This command does not wait for the assignment and does not report it done: no
credential it holds can read a repository's assignment back. Confirm on the page.`,
		Example: `  # Turn judge-push-gate v1 on for testifysec/judge, Warn first
  cilock policy bind pushgate --release 11111111-1111-4111-8111-111111111111 \
    --repo github.com/testifysec/judge --mode warn --reason "one-day side by side"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runBindPushgate(cmd.OutOrStdout(), o) },
	}
	f := cmd.Flags()
	f.StringVar(&o.release, "release", "", "Exact PolicyRelease id to assign (required)")
	f.StringVar(&o.repo, "repo", "", "Repository route, e.g. github.com/owner/name (required)")
	f.StringVar(&o.mode, "mode", "warn", "Mode the human should choose in the review: warn or block")
	f.StringVar(&o.reason, "reason", "", "Reason to give in the review (shown to the human; they type the final one)")
	f.StringVar(&o.platformURL, "platform-url", "", "Platform whose discovery names the Pushgate origin (default: selected login)")
	_ = cmd.MarkFlagRequired("release")
	_ = cmd.MarkFlagRequired("repo")
	return cmd
}

// assignReviewURL builds the Gates deep link. Every value goes through
// url.Values; the origin is the discovered one, already checked to be a bare
// secure origin.
func assignReviewURL(origin, release, repo string) string {
	q := url.Values{}
	q.Set("view", "policies")
	q.Set("assign", release)
	if repo != "" {
		q.Set("repo", repo)
	}
	return origin + "/gates?" + q.Encode()
}

func validateBindPushgate(o bindPushgateOpts) error {
	if !bindPushgateReleaseRe.MatchString(o.release) {
		return errors.New("--release must be an exact lowercase release UUID; a name, tag or latest never selects a release")
	}
	if !bindPushgateRepoRe.MatchString(o.repo) {
		return errors.New("--repo must be an exact lowercase github.com/<owner>/<name> route")
	}
	if o.mode != "warn" && o.mode != "block" {
		return errors.New("--mode must be warn or block")
	}
	if len(o.reason) > 1000 {
		return errors.New("--reason is longer than the review accepts (1000 characters)")
	}
	return nil
}

func runBindPushgate(out io.Writer, o bindPushgateOpts) error {
	if err := validateBindPushgate(o); err != nil {
		return err
	}
	platformURL := o.platformURL
	if platformURL == "" {
		platformURL = auth.ActivePlatformURL()
	}
	if platformURL == "" {
		platformURL = platformconfig.DefaultPlatformURL
	}
	if err := platformconfig.RequireSecurePlatformURL(platformURL); err != nil {
		return errors.New("invalid selected platform URL")
	}
	origin := publishNextStepPushgateOrigin(platformURL)
	if origin == "" {
		return errors.New("the platform does not advertise a Pushgate origin; nothing to open")
	}
	review := assignReviewURL(origin, o.release, o.repo)
	_, _ = fmt.Fprintf(out, "Repository assignment for your human to review and apply:\n")
	_, _ = fmt.Fprintf(out, "  repository: %s\n  release:    %s\n  mode:       %s\n", o.repo, o.release, o.mode)
	if r := strings.TrimSpace(o.reason); r != "" {
		_, _ = fmt.Fprintf(out, "  reason:     %s\n", r)
	}
	_, _ = fmt.Fprintf(out, "\nOpen: %s\n", review)
	if openReviewURL(review) {
		_, _ = fmt.Fprintln(out, "(opened in your browser)")
	}
	_, _ = fmt.Fprintf(out, "\nIn the sheet: choose %s, enter the reason, press Sign and apply, and complete the approval.\n", strings.ToUpper(o.mode[:1])+o.mode[1:])
	_, _ = fmt.Fprintln(out, "Nothing has changed yet. This command cannot see the result; confirm it on the page.")
	return nil
}
