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
	"context"
	"fmt"
	"regexp"

	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

// PolicyBindCmd is `cilock policy bind`. It binds a PolicyDefinition (and
// optionally a specific release) to a product so the platform enforces the
// policy against that product's evidence.
//
// Flow: sign (`cilock sign`) → push (`cilock policy push`) → bind (this).
func PolicyBindCmd() *cobra.Command {
	var (
		definition  string
		release     string
		tag         string
		product     string
		platformURL string
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:   "bind",
		Short: "Bind a policy definition/release to a product",
		Long: "Bind a published policy to a product on the TestifySec platform.\n\n" +
			"bind resolves the named PolicyDefinition and the target product, then creates\n" +
			"a PolicyBinding linking them. Pass --release (a release id) or --tag (resolved\n" +
			"to a release under the definition) to pin a specific release. One of them is\n" +
			"required: the platform enforces a binding with no release nowhere, so creating\n" +
			"one only records something that reads as a control and gates nothing.\n\n" +
			"Auth: createPolicyBinding needs policy:write. If the platform rejects the call\n" +
			"for a missing scope, run `cilock login` again to pick up policy:write.",
		Example: "  # Bind a definition's v1.0.0 release to a product (by exact name)\n" +
			"  cilock policy bind --definition supply-chain --tag v1.0.0 --product my-service\n\n" +
			"  # See what that would bind, without binding it\n" +
			"  cilock policy bind --definition supply-chain --tag v1.0.0 --product my-service --dry-run\n\n" +
			"  # Pin an exact release by id\n" +
			"  cilock policy bind -d supply-chain --release 6a4e31bc-a182-4cdf-a909-c4419377c802 --product my-service",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyBind(cmd, policyBindOpts{
				definition:  definition,
				release:     release,
				tag:         tag,
				product:     product,
				platformURL: platformURL,
				dryRun:      dryRun,
			})
		},
	}

	f := cmd.Flags()
	f.StringVarP(&definition, "definition", "d", "", "PolicyDefinition name (required)")
	f.StringVar(&release, "release", "", "PolicyRelease id to bind (overrides --tag)")
	f.StringVarP(&tag, "tag", "t", "", "Release tag to resolve under the definition")
	f.StringVarP(&product, "product", "p", "", "Product id or exact name to bind to (required)")
	f.StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default: the logged-in platform)")
	f.BoolVar(&dryRun, "dry-run", false, "Resolve the definition, release and product and print the binding without creating it")

	_ = cmd.MarkFlagRequired("definition")
	_ = cmd.MarkFlagRequired("product")
	cmd.AddCommand(PolicyBindPushgateCmd())
	return cmd
}

// policyBindOpts groups the resolved flag values for `policy bind`.
type policyBindOpts struct {
	definition  string
	release     string
	tag         string
	product     string
	platformURL string
	dryRun      bool
}

// bindReleaseRe is the exact release id form: a canonical lowercase UUID.
var bindReleaseRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validateBindRelease refuses, before any platform call, a bind that pins no
// exact release. No component may select a policy by name, tag or latest (the
// Pushgate contract, "Policy artifact and catalog"), and the platform treats a
// release-less binding as not activated everywhere: Pushgate, the CI door, sync
// verify and control posture all skip it. Creating one would record a control
// that gates nothing.
func validateBindRelease(o policyBindOpts) error {
	if o.release != "" && !bindReleaseRe.MatchString(o.release) {
		return fmt.Errorf("--release %q is not an exact lowercase release UUID", o.release)
	}
	if o.release == "" && o.tag == "" {
		return fmt.Errorf("refusing to bind %q without an exact release: pass --release <uuid> (or --tag to resolve one); a binding with no release is enforced nowhere", o.definition)
	}
	return nil
}

// runPolicyBind executes the bind flow: resolve the platform session, the
// definition, an optional release, and the product, then create the binding.
func runPolicyBind(cmd *cobra.Command, o policyBindOpts) error {
	out := cmd.OutOrStdout()
	ctx := cmdContext(cmd)

	if err := validateBindRelease(o); err != nil {
		return err
	}
	sess, err := resolvePolicySession(o.platformURL)
	if err != nil {
		return err
	}
	pc := sess.policyClient()

	// Resolve the definition (must already exist — push it first).
	def, err := pc.ResolvePolicyDefinitionByName(ctx, o.definition)
	if err != nil {
		return err
	}
	if def == nil {
		return fmt.Errorf("no policy definition named %q — publish it first with `cilock policy push --definition %q`", o.definition, o.definition)
	}

	// Resolve the release: explicit id wins; else resolve --tag under the
	// definition; else bind the definition with no pinned release.
	releaseID, releaseTag, err := resolveBindRelease(ctx, pc, def, o.release, o.tag)
	if err != nil {
		return err
	}

	// Resolve the product (by id, then exact name).
	prod, err := pc.ResolveProduct(ctx, o.product)
	if err != nil {
		return err
	}

	if o.dryRun {
		_, _ = fmt.Fprintf(out, "would bind %q to product %q (dry run: nothing was changed)\n", def.Name, prod.Name)
		_, _ = fmt.Fprintf(out, "  definition: %s\n  product:    %s\n  release:    %s (%s)\n", def.ID, prod.ID, releaseID, releaseTag)
		return nil
	}

	binding, err := pc.CreatePolicyBinding(ctx, sess.cred.TenantID, def.ID, releaseID, prod.ID)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "✓ bound %q to product %q\n", def.Name, prod.Name)
	_, _ = fmt.Fprintf(out, "  binding:    %s\n  definition: %s\n  product:    %s\n", binding.ID, def.ID, prod.ID)
	if releaseID != "" {
		if releaseTag == "" && binding.PolicyRelease != nil {
			releaseTag = binding.PolicyRelease.Tag
		}
		_, _ = fmt.Fprintf(out, "  release:    %s (%s)\n", releaseID, releaseTag)
	} else {
		_, _ = fmt.Fprintln(out, "  release:    (none pinned: not enforced anywhere until an OWNER/ADMIN pins a release and activates it)")
	}
	return nil
}

// resolveBindRelease picks the release to pin: an explicit --release id wins;
// otherwise --tag is resolved to a release under the definition; otherwise the
// binding pins no release (the definition's latest applies). It returns the
// release id and its tag (empty when none was pinned).
func resolveBindRelease(ctx context.Context, pc *options.PolicyClient, def *options.PolicyDefinitionRef, releaseFlag, tagFlag string) (id, tag string, err error) {
	if releaseFlag != "" {
		return releaseFlag, "", nil
	}
	if tagFlag == "" {
		return "", "", nil
	}
	rel, rerr := pc.ResolveReleaseByTag(ctx, def.ID, tagFlag)
	if rerr != nil {
		return "", "", rerr
	}
	if rel == nil {
		return "", "", fmt.Errorf("no release tagged %q under definition %q — publish it with `cilock policy push --definition %q --tag %q`", tagFlag, def.Name, def.Name, tagFlag)
	}
	return rel.ID, rel.Tag, nil
}
