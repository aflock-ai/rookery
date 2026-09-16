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

package options

import (
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// Attestation size limit.
//
// DefaultMaxAttestationBytes bounds the in-toto statement JSON that `cilock
// run` and `cilock sign` will sign: the bytes a consumer base64-decodes and
// parses. The number is set by what the platform's push evaluation can afford,
// not by what a signer can produce.
//
// Measured 2026-09-15 on the platform's evaluate-release path, which downloads
// and JSON-parses every envelope matching the commit three times and caches
// nothing above 512 KiB (judge-api/pkg/archivista/envelope_cache.go): about
// 0.4 s per MB. A commit with no large envelope evaluates in 0.95 s median;
// one 45 MB envelope takes 18.6 s; two take 32 s. The edge times a single
// evaluation out at 25 s (jade/factory/edge/git/evidence.js, under Envoy's
// 30 s route timeout). Keeping a commit with two or three envelopes near two
// seconds needs a ceiling in the low single-digit MB, and 4 MiB sits there with
// the parse cost of a full commit's worth of envelopes around two seconds.
//
// The edge has 4 MiB constants of its own (jade/factory/edge/git/bodylimit.go),
// but do NOT read this limit as matching them: that file's 4 MiB is
// maxPrefixBytes, the git push PREFIX (ref-update section, push certificate,
// push-options), and its whole-body cap is 16 MiB. Neither bounds an envelope.
// The agreement of the numbers is a coincidence, and an earlier draft of this
// comment claimed the alignment as a justification, which was wrong.
//
// Headroom, measured the same day so the number is not defended by assertion: a
// real push-tests mint of the Judge repo (-a git -a alps-evidence, product
// exclude glob, compact profile) is 17,023 bytes of statement — 0.4% of this
// limit. On a LEGACY-profile build, where the material attestor's per-file
// leaves stay inline, the same repository measured a 4.95 MiB envelope (~3.7 MiB
// of statement over 17,152 leaves) before compact inventories detached them:
// 88% of this limit. That thin margin is the intended signal, not a bug — a
// legacy build genuinely produces the envelopes push evaluation cannot afford —
// and the flag and env var are the deliberate escape hatch.
//
// Precedence: --max-attestation-bytes, then CILOCK_MAX_ATTESTATION_BYTES, then
// this default. 0 disables the limit and says so once on stderr.
//
// There is deliberately NO config-file layer. cilock reads exactly two files
// that could host one — ~/.jctl/config.yaml (another tool's auth session) and
// $XDG_CONFIG_HOME/cilock (a 0700 credential store with its own isolation
// contract, internal/auth/statepath.go) — and neither is a place to put a
// general flag default. Inventing a third file for one integer would add a
// config surface, a search order and a parser that nothing else in the CLI
// needs, inside a directory whose whole point is that its contents are
// credentials. The env var already covers the "set it once for this
// repository/CI lane" case, via direnv or the lane's own environment.
const (
	DefaultMaxAttestationBytes = 4 << 20
	MaxAttestationBytesFlag    = "max-attestation-bytes"
	MaxAttestationBytesEnv     = "CILOCK_MAX_ATTESTATION_BYTES"
)

// ByteSize is a pflag.Value holding a byte count parsed with ParseByteSize
// and printed with FormatByteSize, so the flag's default reads "4MiB" in help
// and an operator can write the limit the way they think of it.
type ByteSize int64

func (b *ByteSize) String() string { return FormatByteSize(int64(*b)) }

func (b *ByteSize) Set(s string) error {
	n, err := ParseByteSize(s)
	if err != nil {
		return err
	}
	*b = ByteSize(n)
	return nil
}

func (b *ByteSize) Type() string { return "bytes" }

// byteUnits is the size grammar: a non-negative decimal number followed by an
// optional unit. Binary units (KiB, MiB, GiB, and the bare K/M/G shorthand)
// are powers of 1024; decimal units (KB, MB, GB) are powers of 1000, because
// "4MB" written by a person who meant 4,000,000 must not silently become
// 4,194,304. TiB and above are rejected: no attestation limit that large is a
// limit, and 0 already spells "none".
var byteUnits = map[string]int64{
	"":    1,
	"b":   1,
	"k":   1 << 10,
	"kib": 1 << 10,
	"kb":  1000,
	"m":   1 << 20,
	"mib": 1 << 20,
	"mb":  1000 * 1000,
	"g":   1 << 30,
	"gib": 1 << 30,
	"gb":  1000 * 1000 * 1000,
}

// ParseByteSize parses "4194304", "4MiB", "4MB", "4M", "1.5MiB", "512KiB" or
// "0" into a byte count. Units are case-insensitive; a space before the unit
// is allowed. Negative values and unknown units are errors.
func ParseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty size; write bytes (4194304) or a size with a unit (4MiB, 4MB)")
	}
	number, mult, err := splitSizeUnit(s)
	if err != nil {
		return 0, err
	}
	whole, frac, err := splitSizeNumber(s, number)
	if err != nil {
		return 0, err
	}
	total, err := wholeBytes(s, whole, mult)
	if err != nil {
		return 0, err
	}
	if frac == "" {
		return total, nil
	}
	add, err := fractionBytes(s, frac, mult)
	if err != nil {
		return 0, err
	}
	if total > math.MaxInt64-add {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return total + add, nil
}

// splitSizeUnit separates the leading number from the unit and resolves the
// unit's multiplier. The number may still be empty or malformed here; that is
// splitSizeNumber's question.
func splitSizeUnit(s string) (number string, mult int64, err error) {
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	number, unit := s[:i], strings.ToLower(strings.TrimSpace(s[i:]))
	if number == "" {
		return "", 0, fmt.Errorf("invalid size %q: it must start with a number", s)
	}
	mult, ok := byteUnits[unit]
	if !ok {
		return "", 0, fmt.Errorf("invalid size %q: unknown unit %q (use B, KiB, MiB, GiB, KB, MB or GB)", s, s[i:])
	}
	return number, mult, nil
}

// splitSizeNumber splits the number at its decimal point and refuses the
// shapes that must never parse: more than one point, or no digit at all.
//
// AT LEAST ONE DIGIT. "." and ".MiB" arrive with both halves empty;
// defaulting the whole part to "0" and skipping an empty fraction once made
// them parse to 0, and 0 is the explicit opt-out. A malformed value must
// refuse, not disable the limit -- the same failure this parse exists to
// prevent, reached from the other end.
func splitSizeNumber(s, number string) (whole, frac string, err error) {
	whole, frac, _ = strings.Cut(number, ".")
	if strings.Contains(frac, ".") {
		return "", "", fmt.Errorf("invalid size %q: more than one decimal point", s)
	}
	if strings.Trim(whole+frac, "0123456789") != "" || whole+frac == "" {
		return "", "", fmt.Errorf("invalid size %q: it must contain at least one digit", s)
	}
	if whole == "" {
		whole = "0"
	}
	return whole, strings.TrimRight(frac, "0"), nil
}

// wholeBytes is the integer part times the unit, refused rather than wrapped
// when it does not fit.
func wholeBytes(s, whole string, mult int64) (int64, error) {
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return n * mult, nil
}

// fractionBytes is the fractional part times the unit, in arbitrary
// precision. The int64 version checked the numerator product for overflow
// BEFORE dividing by the decimal scale, so "0.9990234375GiB" -- exactly
// 1,072,693,248 bytes -- was refused as too large because 9990234375 * 2^30
// does not fit even though the quotient does. Overflow of an intermediate is
// not overflow of the answer; only the final byte count has to fit. A
// fraction that is not a whole number of bytes is refused, never rounded.
func fractionBytes(s, frac string, mult int64) (int64, error) {
	num, ok := new(big.Int).SetString(frac, 10)
	if !ok {
		return 0, fmt.Errorf("invalid size %q: bad fraction %q", s, frac)
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(frac))), nil)
	quo, rem := new(big.Int).QuoRem(new(big.Int).Mul(num, big.NewInt(mult)), scale, new(big.Int))
	if rem.Sign() != 0 {
		return 0, fmt.Errorf("invalid size %q: not a whole number of bytes", s)
	}
	if !quo.IsInt64() {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return quo.Int64(), nil
}

// FormatByteSize prints an exact multiple of a binary unit as that unit
// ("4MiB", "512KiB") and anything else as plain bytes, so the output always
// parses back to the same number.
func FormatByteSize(n int64) string {
	if n <= 0 {
		return strconv.FormatInt(n, 10)
	}
	for _, u := range []struct {
		name  string
		bytes int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n%u.bytes == 0 {
			return strconv.FormatInt(n/u.bytes, 10) + u.name
		}
	}
	return strconv.FormatInt(n, 10)
}

// AddMaxAttestationBytesFlag registers --max-attestation-bytes on cmd, bound
// to v, with the 4 MiB default.
func AddMaxAttestationBytesFlag(cmd *cobra.Command, v *ByteSize) {
	*v = DefaultMaxAttestationBytes
	cmd.Flags().Var(v, MaxAttestationBytesFlag,
		"Largest in-toto statement cilock will sign, as bytes or with a unit (4MiB, 4MB, 4194304). "+
			"A statement over this is refused before it is signed, written or uploaded, with a per-attestor "+
			"breakdown of what filled it. The platform parses every envelope matching a commit on each push "+
			"evaluation at ~0.4 s/MB against a 25 s budget, so the default keeps a commit with a few envelopes "+
			"under two seconds. Also settable via "+MaxAttestationBytesEnv+" (the flag wins). 0 disables the limit.")
}

// ResolveMaxAttestationBytes applies the precedence flag > env > default and
// returns the limit in bytes. env is a lookup (os.Getenv in production) so the
// precedence is testable without touching the process environment. A limit of
// 0 is honoured as "no limit" and announced with one line on warn, because a
// silent opt-out is how the next 45 MB envelope reaches the platform unnoticed.
func ResolveMaxAttestationBytes(cmd *cobra.Command, flagValue ByteSize, env func(string) string, warn io.Writer) (int, error) {
	limit := int64(flagValue)
	source := "--" + MaxAttestationBytesFlag
	if !cmd.Flags().Changed(MaxAttestationBytesFlag) {
		limit = DefaultMaxAttestationBytes
		source = ""
		if raw := env(MaxAttestationBytesEnv); raw != "" {
			n, err := ParseByteSize(raw)
			if err != nil {
				return 0, fmt.Errorf("%s: %w", MaxAttestationBytesEnv, err)
			}
			limit, source = n, MaxAttestationBytesEnv
		}
	}
	if limit > math.MaxInt {
		return 0, fmt.Errorf("%s: %d bytes is larger than this platform can address", source, limit)
	}
	if limit == 0 {
		// Best effort: a failed warning must not turn into a signing failure.
		_, _ = fmt.Fprintf(warn, "warning: %s=0: no attestation size limit; the %s default protects push evaluation and is off for this run\n",
			source, FormatByteSize(DefaultMaxAttestationBytes))
	}
	return int(limit), nil
}
