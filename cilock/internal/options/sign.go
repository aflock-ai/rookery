// Copyright 2025 The Aflock Authors
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

package options

import (
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

type SignOptions struct {
	SignerOptions            SignerOptions
	KMSSignerProviderOptions KMSSignerProviderOptions
	DataType                 string
	OutFilePath              string
	InFilePath               string
	TimestampServers         []string
	PlatformURL              string // TestifySec platform URL — derives fulcio + tsa URLs for keyless signing
}

var RequiredSignFlags = []string{
	"infile",
	"outfile",
}

func (so *SignOptions) AddFlags(cmd *cobra.Command) {
	so.SignerOptions.AddFlags(cmd)
	so.KMSSignerProviderOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&so.DataType, "datatype", "t", "https://witness.testifysec.com/policy/v0.1", "The URI reference to the type of data being signed. Defaults to the Witness policy type")
	cmd.Flags().StringVarP(&so.OutFilePath, "outfile", "o", "", "File to write signed data. Defaults to stdout")
	cmd.Flags().StringVarP(&so.InFilePath, "infile", "f", "", "Witness policy file to sign")
	cmd.Flags().StringSliceVar(&so.TimestampServers, "timestamp-servers", []string{}, "Timestamp Authority Servers to use when signing envelope")
	cmd.Flags().StringVar(&so.PlatformURL, "platform-url", platformconfig.DefaultPlatformURL,
		"TestifySec platform URL — derives the Fulcio and TSA URLs for keyless signing "+
			"(default "+platformconfig.DefaultPlatformURL+"). Run 'cilock login' first to sign a "+
			"policy keyless as yourself; the stored session is exchanged for a short-lived Fulcio "+
			"certificate. Pass --platform-url \"\" to opt out (sign with --signer-* only, no platform).")

	cmd.MarkFlagsRequiredTogether(RequiredSignFlags...)
}

// ResolvePlatformDefaults derives the Fulcio + TSA URLs from --platform-url and,
// when the user has logged in (`cilock login`), exchanges the stored session
// credential for a short-lived OIDC token the platform's Fulcio trusts — so a
// policy can be signed keyless with minimal flags. It mirrors the run command's
// resolution (see RunOptions.ResolvePlatformDefaults) for the signing subset:
// no archivista/attestor wiring, just the signer + timestamper.
//
// Pass --platform-url "" to opt out entirely (sign with the configured
// --signer-* only). Best-effort and fail-open: a missing/expired session, or an
// explicit --signer-fulcio-* choice, leaves signing exactly as it was.
func (so *SignOptions) ResolvePlatformDefaults(cmd *cobra.Command) {
	// Explicit-disable: the user passed --platform-url "" (changed + empty).
	if cmd.Flags().Changed("platform-url") && so.PlatformURL == "" {
		return
	}

	pc := platformconfig.Derive(so.PlatformURL)

	// Keyless signing: exchange the stored login credential for a Fulcio token,
	// feeding it to the fulcio signer. A non-keyless `cilock sign -k key.pem` (no
	// login, no signer-fulcio-* flag) never selects the fulcio signer. See
	// applyKeylessFulcioToken.
	cred, err := auth.Lookup(so.PlatformURL)
	loggedIn := err == nil && cred != nil
	if loggedIn {
		applyKeylessFulcioToken(cmd, so.PlatformURL, pc.Fulcio, cred.Token)
	}

	// Give a selected fulcio signer a URL if it lacks one — selected by the
	// keyless exchange above OR by an explicit --signer-fulcio-token. Runs outside
	// the login block so `cilock sign --platform-url X --signer-fulcio-token T`
	// works without login. No-op for local/KMS signing (fulcio unselected).
	ensureFulcioURL(cmd, pc.Fulcio)

	// Timestamp servers: add the platform TSA only when actually doing a keyless
	// platform signature (logged in). A purely local `cilock sign -k` should not
	// get a platform TSA appended. Explicit --timestamp-servers wins.
	if loggedIn && len(so.TimestampServers) == 0 {
		so.TimestampServers = []string{pc.TSA}
	}
}
