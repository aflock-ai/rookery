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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// Stable diagnostic codes for step-name inference. Agents dispatch on
// these; renaming one is a breaking change.
const (
	codeStepInferOK       = "I_STEP_INFERENCE_OK"
	codeStepInferNoMatch  = "E_STEP_INFERENCE_NO_MATCH"
	codeStepInferAmbig    = "E_STEP_INFERENCE_AMBIGUOUS"
	stepDiagSchemaVersion = "cilock.stepdiag/v1"
)

// inferStepName fills in o.StepName when the operator didn't pass --step,
// by matching the wrapped command against the detector catalog. On a clean
// match it sets the step and logs a one-line audit note. When the command
// is unknown (no match) or maps to more than one step (ambiguous) it
// renders an actionable diagnostic and returns an error — a step name is
// the routing key the policy verifier uses to bind this attestation to a
// policy step, so cilock will not silently guess.
func inferStepName(o *options.RunOptions, args []string) error {
	cwd := o.WorkingDir
	if cwd == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}

	plan := detection.RunPrePlan(detection.PrePlan{
		Argv: args,
		Env:  envSliceToMap(os.Environ()),
		Cwd:  cwd,
	})
	inf := detection.InferStep(detection.Default(), plan)

	switch inf.Outcome {
	case detection.StepResolved:
		o.StepName = string(inf.Step)
		log.Warnf("[%s] inferred --step=%s from detector %q; pass --step to override",
			codeStepInferOK, inf.Step, inf.Source)
		return nil
	case detection.StepAmbiguous:
		renderStepDiag(os.Stderr, codeStepInferAmbig, args, inf)
		return fmt.Errorf("--step is required: command maps to more than one step (see %s above)", codeStepInferAmbig)
	default:
		renderStepDiag(os.Stderr, codeStepInferNoMatch, args, inf)
		return fmt.Errorf("--step is required: could not infer a step from the command (see %s above)", codeStepInferNoMatch)
	}
}

// stepDiag is the machine-readable half of the inference diagnostic.
type stepDiag struct {
	Schema       string                    `json:"schema"`
	Code         string                    `json:"code"`
	Why          string                    `json:"why"`
	ObservedArgv []string                  `json:"observed_argv"`
	Candidates   []detection.StepCandidate `json:"candidates,omitempty"`
	Lexicon      map[string][]string       `json:"lexicon"`
	Remediation  []map[string]string       `json:"remediation"`
}

const stepWhy = "--step names the supply-chain step this attestation records; the policy " +
	"verifier binds evidence to a policy step by this name, so it must be set before signing."

// renderStepDiag writes the dual-channel diagnostic: human-readable prose
// followed by a fenced JSON block carrying the same facts (stable code,
// observed argv, the full lexicon, and ordered remediation) so an agent
// parses the block instead of the prose. Everything is built into one
// string and written once to keep the write-path simple.
func renderStepDiag(w io.Writer, code string, args []string, inf detection.StepInference) {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "cilock: error[%s] — --step required, could not infer\n\n", code)
	b.WriteString("why:      ")
	b.WriteString(stepWhy)
	b.WriteString("\nobserved: ")
	b.WriteString(shellQuoteArgs(args))
	b.WriteString("\n")

	if code == codeStepInferAmbig {
		b.WriteString("matched:  ")
		parts := make([]string, 0, len(inf.Candidates))
		for _, c := range inf.Candidates {
			parts = append(parts, fmt.Sprintf("%s→%s", c.Detector, c.Category))
		}
		b.WriteString(strings.Join(parts, ", "))
		b.WriteString("\nfix:      pass --step <name> to pick one of the above, or any other name your policy expects.\n\n")
	} else {
		b.WriteString("          (no command detector matched)\n")
		b.WriteString("fix:      pass --step <name> — use a lexicon category below if one fits,\n")
		b.WriteString("          or any custom kebab-case name your policy expects.\n\n")
	}

	b.WriteString("lexicon (core): ")
	b.WriteString(joinCategories(detection.Tier1Categories()))
	b.WriteString("\n")

	// Structured block. The agent reads this; the prose above is for humans.
	diag := stepDiag{
		Schema:       stepDiagSchemaVersion,
		Code:         code,
		Why:          stepWhy,
		ObservedArgv: args,
		Candidates:   inf.Candidates,
		Lexicon: map[string][]string{
			"core":        categoriesToStrings(detection.Tier1Categories()),
			"specialized": categoriesToStrings(detection.Tier2Categories()),
		},
		Remediation: []map[string]string{
			{"kind": "set_flag", "hint": "pass --step <name>; a lexicon category, or any kebab-case custom name"},
		},
	}
	if jsonBytes, err := json.MarshalIndent(diag, "", "  "); err == nil {
		b.WriteString("\n---BEGIN cilock-stepdiag---\n")
		b.Write(jsonBytes)
		b.WriteString("\n---END cilock-stepdiag---\n")
	}

	_, _ = io.WriteString(w, b.String())
}

func categoriesToStrings(cats []detection.Category) []string {
	out := make([]string, len(cats))
	for i, c := range cats {
		out[i] = string(c)
	}
	return out
}

// shellQuoteArgs joins argv for display, quoting any element that contains
// whitespace so the observed command is unambiguous and a control char in
// user-controlled argv can't smuggle formatting into the diagnostic.
func shellQuoteArgs(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n\"'") {
			parts[i] = fmt.Sprintf("%q", a)
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}
