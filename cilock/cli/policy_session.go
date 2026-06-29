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

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

// policySession is the resolved platform + credential a policy publish/bind
// command operates against. It is built by resolvePolicySession so both
// `cilock policy push` and `cilock policy bind` share one resolution path
// (platform default → token-bearing session → working tenant).
type policySession struct {
	platformURL string
	cred        *auth.Credential
}

// resolvePolicySession resolves the target platform (explicit flag, else the
// logged-in platform, else the compiled default), then requires a token-bearing
// session with a working tenant. The tenant is required because every policy
// create input (definition/release/binding) carries a mandatory tenantID.
func resolvePolicySession(platformURLFlag string) (*policySession, error) {
	platformURL := platformURLFlag
	if platformURL == "" {
		if active := auth.ActivePlatformURL(); active != "" {
			platformURL = active
		} else {
			platformURL = config.DefaultPlatformURL
		}
	}

	cred, err := auth.Lookup(platformURL)
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	if cred == nil || cred.Token == "" {
		return nil, fmt.Errorf("not logged in to %s — run `cilock login` first", auth.NormalizeURL(platformURL))
	}
	if cred.TenantID == "" {
		return nil, fmt.Errorf("no working tenant on this session — run `cilock login` (or `cilock use`) to select a tenant")
	}
	return &policySession{platformURL: platformURL, cred: cred}, nil
}

// policyClient builds the GraphQL policy client for this session, resolving the
// platform's advertised GraphQL endpoint (discovery → ${platform}/query).
func (s *policySession) policyClient() *options.PolicyClient {
	return &options.PolicyClient{GraphQLURL: resolveGraphQLURL(s.platformURL), Token: s.cred.Token}
}

// resolveArchivistaURL resolves the Archivista upload endpoint: the
// discovery-advertised URL when available, else derived from the platform URL.
// A discovery URL whose origin (scheme+host) differs from the platform is
// withheld (#5987): the session bearer / uploaded bundles are scoped to the
// platform origin and must never be sent to a host an untrusted discovery
// document points elsewhere.
func resolveArchivistaURL(platformURL string) string {
	if d, err := config.Discover(platformURL); err == nil && d.ArchivistaURL != "" {
		if config.SameOrigin(d.ArchivistaURL, platformURL) {
			return d.ArchivistaURL
		}
	}
	return config.Derive(platformURL).Archivista
}

// cmdContext returns the command's context, defaulting to context.Background
// when cobra was invoked without one (e.g. in unit tests).
func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}
