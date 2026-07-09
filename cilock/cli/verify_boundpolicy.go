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

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// resolveBoundPolicyRef resolves the policy a flagless `cilock verify` (no
// -p/--policy) verifies against: the platform policy BOUND to the session's
// working product. The chain is session -> bound product -> policy binding ->
// policy release -> the signed policy envelope's Archivista gitoid, which the
// caller feeds to policy.LoadPolicy exactly as if the operator had passed
// `-p <gitoid>`.
//
// Provenance is non-negotiable: before any verification output, this prints
// ONE clear line naming the policy it is about to trust — definition name,
// release tag, envelope digest, who bound it, and when — so a green flagless
// verify is never a verdict against an invisible policy.
//
// Fail-closed everywhere else: no platform, no session, no working product, or
// no binding each yield a crisp error that names the fix. An explicit -p never
// reaches this path (the caller gates on vo.PolicyFilePath == "").
func resolveBoundPolicyRef(ctx context.Context, vo *options.VerifyOptions) (string, error) {
	if vo.PlatformURL == "" {
		return "", fmt.Errorf("no policy given: pass -p/--policy, or drop --platform-url \"\" so the session's platform-bound policy can be resolved")
	}
	resolved, err := auth.Resolve(vo.PlatformURL, auth.ForBearer)
	if err != nil || resolved == nil || resolved.Credential == nil || resolved.Token == "" {
		return "", fmt.Errorf("no policy given and no platform session: pass -p/--policy, or run `cilock login --platform-url %s` so verify can resolve the product's bound policy", vo.PlatformURL)
	}
	cred := resolved.Credential
	if cred.ProductID == "" {
		return "", fmt.Errorf("no policy given and the session has no working product: run `cilock use` to select a product, or pass -p/--policy")
	}

	pc := &options.PolicyClient{GraphQLURL: resolveGraphQLURL(vo.PlatformURL), Token: cred.Token}
	bound, err := pc.ResolveBoundPolicy(ctx, cred.ProductID)
	if err != nil {
		return "", err
	}
	productLabel := cred.ProductName
	if productLabel == "" {
		productLabel = cred.ProductID
	}
	if bound == nil {
		return "", fmt.Errorf("no policy bound for product %q — bind one with `cilock policy bind --definition <name> --product %s`, or pass -p/--policy", productLabel, cred.ProductID)
	}

	// The loud provenance line: which policy this verify trusts, and on whose
	// authority. Printed BEFORE verification output, always.
	log.Infof("using platform-bound policy %q release %q (gitoid %s) for product %q — bound by %s at %s; pass -p to override",
		bound.DefinitionName, bound.ReleaseTag, bound.Gitoid, productLabel, bound.BoundBy, bound.BoundAt)
	return bound.Gitoid, nil
}
