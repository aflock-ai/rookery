// Copyright 2026 The Aflock Authors
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/signer"
	fulciosigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// Flag names the fulcio provider's static-token options register under
// (internal/options addFlags prefixes every provider option with signer-<name>-).
const (
	fulcioTokenFlag     = "--signer-fulcio-token"      //nolint:gosec // G101 false positive: a flag name, not a credential.
	fulcioTokenPathFlag = "--signer-fulcio-token-path" //nolint:gosec // G101 false positive: a flag name, not a credential.
)

// refuseExpiredFulcioToken fails when the fulcio provider carries a STATIC
// identity token -- one the operator passed on --signer-fulcio-token or
// --signer-fulcio-token-path -- whose exp claim has already passed at now.
//
// It exists because the Fulcio certificate is minted at first signature, AFTER
// the wrapped command, and a static token is the one identity source nothing
// re-mints at that moment: the platform session and workflow-OIDC paths carry
// a refresher, and the ambient-CI and interactive-issuer paths mint inside the
// provider. Without this check a static token that expired during a long
// command reaches Fulcio and comes back as HTTP 400 "error processing the
// identity token", which names neither the flag nor the cause.
//
// It is deliberately lenient about everything except a legible, elapsed exp:
// a non-fulcio provider, no static token, an unreadable token file, a token
// that is not a JWT, or one with no exp all return nil and leave the verdict to
// Fulcio exactly as before. The point is to refuse the one case that would
// otherwise fail confusingly, not to add a second token validator.
func refuseExpiredFulcioToken(sp signer.SignerProvider, now time.Time) error {
	// A VALUE-type assertion, and the whole check rides on it. If the fulcio
	// provider ever moves to a pointer receiver, or gains a wrapper, this stops
	// matching and the check silently becomes a no-op -- every long run goes
	// back to minting a dead signature, and no test here would notice, because
	// they all build the provider the way production does and would degrade
	// along with it. TestRefuseExpiredFulcioTokenAssertsTheRealProviderType is
	// the pin: it asserts the concrete type the signer registry actually hands
	// back, so that refactor breaks loudly instead of disarming this check.
	//
	// Non-fulcio providers legitimately land here (loadSigners passes whatever
	// provider it built) and must pass through untouched -- erroring on an
	// unrecognised type would break third-party signer plugins.
	fsp, ok := sp.(fulciosigner.FulcioSignerProvider)
	if !ok {
		return nil
	}
	var raw, flag string
	switch {
	case fsp.Token != "":
		raw, flag = fsp.Token, fulcioTokenFlag
	case fsp.TokenPath != "":
		raw, flag = readStaticTokenFile(fsp.TokenPath), fulcioTokenPathFlag
	default:
		return nil
	}
	exp, ok := jwtExpiry(raw)
	if !ok || now.Before(exp) {
		return nil
	}
	return fmt.Errorf("the identity token from %s expired at %s (%s ago)",
		flag, exp.UTC().Format(time.RFC3339), now.Sub(exp).Round(time.Second))
}

// readStaticTokenFile returns the trimmed contents of a --signer-fulcio-token-path
// file, or "" when it cannot be read. The empty string is deliberate: the
// lifetime check has nothing to say about an unreadable file, and the fulcio
// provider reports the unreadable path itself when it reads the file to sign.
func readStaticTokenFile(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the operator chose this path via --signer-fulcio-token-path; reading it is the flag's purpose.
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// jwtExpiry reads the exp claim of a compact JWS without verifying it -- the
// same unverified read the fulcio provider itself performs on the token before
// forwarding it. ok is false when the input is not a JWT or carries no exp.
func jwtExpiry(raw string) (time.Time, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	sec, frac := int64(claims.Exp), claims.Exp-float64(int64(claims.Exp))
	return time.Unix(sec, int64(frac*float64(time.Second))), true
}
