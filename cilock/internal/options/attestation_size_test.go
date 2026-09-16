// jade:ring local
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
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestParseByteSize(t *testing.T) {
	cases := map[string]int64{
		"4194304": 4194304,
		"4MiB":    4 << 20,
		"4mib":    4 << 20,
		"4 MiB":   4 << 20,
		"4MB":     4_000_000,
		"4M":      4 << 20,
		"512KiB":  512 << 10,
		"512kB":   512_000,
		"1GiB":    1 << 30,
		"1.5MiB":  3 << 19,
		"0":       0,
		"0B":      0,
		"100B":    100,
	}
	for in, want := range cases {
		got, err := ParseByteSize(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "-1", "-4MiB", "abc", "4XB", "4MiBs", "MiB", "1e6", "4TiB", "0x10"} {
		_, err := ParseByteSize(bad)
		require.Error(t, err, "%q must be rejected", bad)
	}
}

// TestParseByteSize_ExactDecimalNotFloat pins the two ways a float64 parse got
// this wrong. Both ended in the same place: a limit that does not limit.
//
//   - "1.001KB" is 1001 bytes exactly, but 1.001*1000 evaluates to
//     1000.9999999999999, so a whole-number check on the product REJECTED a
//     valid size. An operator who cannot set the limit they meant sets a
//     different one, or none.
//   - "9223372036854775808.0" is 2^63, one past max. Comparing it to
//     math.MaxInt64 promotes that constant to float64, where 2^63-1 is not
//     representable and rounds UP to 2^63, so the bound check passed. The
//     int64 conversion of an out-of-range float is then architecture-dependent:
//     amd64 yields a NEGATIVE limit, arm64 saturates to max. Negative disables
//     enforcement outright, and silently — without the one-line notice that
//     spelling it "0" prints. Saturating sets a ceiling nothing can reach.
//     A size limit that quietly turns itself off is the one failure this flag
//     must not have, so the parse refuses the input instead.
func TestParseByteSize_ExactDecimalNotFloat(t *testing.T) {
	for in, want := range map[string]int64{
		"1.001KB":             1001,
		"0.5KiB":              512,
		"1.25MiB":             5 << 18,
		"2.5MB":               2_500_000,
		"9223372036854775807": 9223372036854775807,
		// A long exact fraction whose NUMERATOR product overflows int64 while
		// the quotient does not: 9990234375 * 2^30 does not fit, 1,072,693,248
		// does. Refusing it as "too large" rejected an addressable limit.
		"0.9990234375GiB": 1072693248,
		"0.001953125MiB":  2048,
	} {
		got, err := ParseByteSize(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}

	for _, bad := range []string{
		"9223372036854775808.0", // 2^63: must not survive as a limit of any sign
		"9223372036854775808",
		"1.0009KB", // 1000.9 bytes is not a whole number of bytes
		"0.5B",     // half a byte
		"1.5.2MB",  // two decimal points
		// A VALUE WITH NO DIGITS MUST REFUSE, NOT PARSE TO ZERO. Zero is the
		// explicit opt-out, so "." and ".MiB" reading as 0 would disable
		// enforcement from a typo -- the same failure the exact-decimal parse
		// exists to prevent, reached from the other end.
		".",
		".MiB",
		".KB",
		". MiB",
	} {
		got, err := ParseByteSize(bad)
		require.Error(t, err, "%q must be rejected, got %d", bad, got)
	}

	// Whatever a caller writes, a successful parse never yields a value that
	// disables enforcement by accident. Only an explicit 0 opts out.
	for _, in := range []string{"1.001KB", "4MiB", "1B", "9223372036854775807"} {
		got, err := ParseByteSize(in)
		require.NoError(t, err, in)
		require.Positive(t, got, "%q parsed to %d; a non-positive limit disables the check", in, got)
	}
}

func TestFormatByteSizeRoundTrips(t *testing.T) {
	require.Equal(t, "4MiB", FormatByteSize(4<<20))
	require.Equal(t, "512KiB", FormatByteSize(512<<10))
	require.Equal(t, "0", FormatByteSize(0))
	require.Equal(t, "4194305", FormatByteSize(4<<20+1), "an inexact size prints as bytes")
	for _, n := range []int64{0, 1, 1023, 1024, 4 << 20, 4<<20 + 1, 3 << 30} {
		back, err := ParseByteSize(FormatByteSize(n))
		require.NoError(t, err)
		require.Equal(t, n, back)
	}
}

func TestDefaultMaxAttestationBytesIs4MiB(t *testing.T) {
	require.Equal(t, int64(4<<20), int64(DefaultMaxAttestationBytes))
	require.Equal(t, "4MiB", FormatByteSize(DefaultMaxAttestationBytes))
}

func newSizeCmd() (*cobra.Command, *ByteSize) {
	var v ByteSize
	cmd := &cobra.Command{Use: "x", Run: func(*cobra.Command, []string) {}}
	AddMaxAttestationBytesFlag(cmd, &v)
	return cmd, &v
}

func TestMaxAttestationBytesPrecedence(t *testing.T) {
	// default: 4 MiB, no warning.
	cmd, v := newSizeCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	var warn bytes.Buffer
	got, err := ResolveMaxAttestationBytes(cmd, *v, func(string) string { return "" }, &warn)
	require.NoError(t, err)
	require.Equal(t, 4<<20, got)
	require.Empty(t, warn.String())

	// env beats default.
	cmd, v = newSizeCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	env := func(k string) string {
		if k == MaxAttestationBytesEnv {
			return "8MiB"
		}
		return ""
	}
	got, err = ResolveMaxAttestationBytes(cmd, *v, env, &warn)
	require.NoError(t, err)
	require.Equal(t, 8<<20, got)

	// flag beats env, in every spelling the grammar accepts.
	for _, spelling := range []string{"2MiB", "2097152", "2M"} {
		cmd, v = newSizeCmd()
		require.NoError(t, cmd.ParseFlags([]string{"--" + MaxAttestationBytesFlag, spelling}))
		got, err = ResolveMaxAttestationBytes(cmd, *v, env, &warn)
		require.NoError(t, err)
		require.Equal(t, 2<<20, got, spelling)
	}
	require.Empty(t, warn.String())

	// a flag set to the default value still wins over env: "changed" is
	// what matters, not "differs from default".
	cmd, v = newSizeCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--" + MaxAttestationBytesFlag, "4MiB"}))
	got, err = ResolveMaxAttestationBytes(cmd, *v, env, &warn)
	require.NoError(t, err)
	require.Equal(t, 4<<20, got)

	// a malformed env value is an error, not a silent fall-through to the
	// default: an operator who typed it meant something.
	cmd, v = newSizeCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	_, err = ResolveMaxAttestationBytes(cmd, *v, func(string) string { return "lots" }, &warn)
	require.Error(t, err)
	require.Contains(t, err.Error(), MaxAttestationBytesEnv)

	// a malformed flag value is rejected at parse time.
	cmd, _ = newSizeCmd()
	require.Error(t, cmd.ParseFlags([]string{"--" + MaxAttestationBytesFlag, "lots"}))
	cmd, _ = newSizeCmd()
	require.Error(t, cmd.ParseFlags([]string{"--" + MaxAttestationBytesFlag, "-1"}))
}

func TestMaxAttestationBytesZeroOptsOutWithOneWarningLine(t *testing.T) {
	for _, via := range []string{"flag", "env"} {
		cmd, v := newSizeCmd()
		env := func(string) string { return "" }
		if via == "flag" {
			require.NoError(t, cmd.ParseFlags([]string{"--" + MaxAttestationBytesFlag, "0"}))
		} else {
			require.NoError(t, cmd.ParseFlags(nil))
			env = func(string) string { return "0" }
		}
		var warn bytes.Buffer
		got, err := ResolveMaxAttestationBytes(cmd, *v, env, &warn)
		require.NoError(t, err, via)
		require.Equal(t, 0, got, via)
		lines := strings.Split(strings.TrimRight(warn.String(), "\n"), "\n")
		require.Len(t, lines, 1, "exactly one warning line via %s: %q", via, warn.String())
		require.Contains(t, lines[0], "warning:")
		require.Contains(t, lines[0], "no attestation size limit", via)
		require.Contains(t, lines[0], "4MiB", "the warning names the default it is giving up")
	}
}

func TestMaxAttestationBytesFlagDefaultRendersAs4MiB(t *testing.T) {
	cmd, _ := newSizeCmd()
	f := cmd.Flags().Lookup(MaxAttestationBytesFlag)
	require.NotNil(t, f)
	require.Equal(t, "4MiB", f.DefValue)
	require.Contains(t, f.Usage, MaxAttestationBytesEnv, "the help text names the env var")
	require.Contains(t, f.Usage, "0", "the help text names the opt-out")
}
