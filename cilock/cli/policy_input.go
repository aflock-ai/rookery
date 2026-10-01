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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/spf13/cobra"
)

// PolicyInputCmd shows what a rego rule sees as `input` for each attestation in
// a step's envelope. Agents drafting rules decoded their own envelopes with
// `jq '.payload | @base64d | fromjson | .predicate.attestations[] | ...'` and jq
// was not installed (onbsim, 2026-09-25: 34 failures in 17 runs).
func PolicyInputCmd() *cobra.Command {
	var attestor string
	cmd := &cobra.Command{
		Use:   "input <envelope.json>",
		Short: "Show the input a policy rule sees for each attestation in a step's evidence",
		Long: `Decode a signed step envelope (the -o/--outfile of cilock run or cilock attest)
and show what a Rego rule for that step reads as ` + "`input`" + `.

Without --attestor it lists the step, its subjects, and each attestation with
its top-level fields. With --attestor it prints exactly that attestation's JSON:
the object a rule on that attestor evaluates.

` + regoInputNote,
		Example: `  cilock policy input tests.json
  cilock policy input tests.json --attestor command-run`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyInput(cmd.OutOrStdout(), args[0], attestor)
		},
	}
	cmd.Flags().StringVar(&attestor, "attestor", "", "print one attestation's input: a short name such as command-run, or its full type URI")
	return cmd
}

// regoInputNote is where a rule finds the attestation. The verifier passes it
// as bare input only when the step has no cross-step or timestamp context;
// with either (a platform-timestamped step always has one) it is
// input.attestation beside input.steps (attestation/policy buildRegoInput).
const regoInputNote = `A rule reads this JSON as input.attestation when the verifier adds
cross-step (attestationsFrom) or timestamp context, which a platform-signed
step always has, and as bare input otherwise. Read it the way the seeded rules
do: pred := object.get(input, "attestation", input)`

type inputStatement struct {
	Subject []struct {
		Name string `json:"name"`
	} `json:"subject"`
	Predicate struct {
		Name         string `json:"name"`
		Attestations []struct {
			Type        string          `json:"type"`
			Attestation json.RawMessage `json:"attestation"`
		} `json:"attestations"`
	} `json:"predicate"`
}

func runPolicyInput(out io.Writer, path, attestor string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // the caller names their own evidence file
	if err != nil {
		return err
	}
	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Payload) == 0 || env.PayloadType == "" {
		return fmt.Errorf("%s is not a DSSE envelope: pass the -o/--outfile a cilock run or cilock attest wrote", path)
	}
	var stmt inputStatement
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		return fmt.Errorf("%s: the envelope's payload is not an attestation statement: %w", path, err)
	}
	if attestor == "" {
		return writeInputSummary(out, stmt)
	}
	for _, a := range stmt.Predicate.Attestations {
		if a.Type == attestor || attestorShortName(a.Type) == attestor {
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, a.Attestation, "", "  "); err != nil {
				return fmt.Errorf("%s attestation is not JSON: %w", a.Type, err)
			}
			pretty.WriteByte('\n')
			_, err := out.Write(pretty.Bytes())
			return err
		}
	}
	carried := make([]string, 0, len(stmt.Predicate.Attestations))
	for _, a := range stmt.Predicate.Attestations {
		carried = append(carried, attestorShortName(a.Type))
	}
	return fmt.Errorf("this envelope carries no %s attestation; it carries: %s", attestor, strings.Join(carried, ", "))
}

func writeInputSummary(out io.Writer, stmt inputStatement) error {
	var b strings.Builder
	fmt.Fprintf(&b, "step: %s\n", stmt.Predicate.Name)
	fmt.Fprintf(&b, "subjects: %d\n", len(stmt.Subject))
	for _, a := range stmt.Predicate.Attestations {
		fmt.Fprintf(&b, "\n%s  (%s)\n", attestorShortName(a.Type), a.Type)
		var fields map[string]json.RawMessage
		if json.Unmarshal(a.Attestation, &fields) != nil {
			b.WriteString("  (not a JSON object)\n")
			continue
		}
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "  input fields: %s\n", strings.Join(keys, ", "))
	}
	b.WriteString("\n" + regoInputNote + "\n")
	b.WriteString("\nPrint one attestation's full input with --attestor <name>.\n")
	_, err := io.WriteString(out, b.String())
	return err
}

// attestorShortName is the attestor name inside a predicate type URI:
// https://aflock.ai/attestations/command-run/v0.2 is command-run.
func attestorShortName(predicateType string) string {
	parts := strings.Split(strings.TrimRight(predicateType, "/"), "/")
	if len(parts) >= 2 && strings.HasPrefix(parts[len(parts)-1], "v") {
		return parts[len(parts)-2]
	}
	return parts[len(parts)-1]
}
