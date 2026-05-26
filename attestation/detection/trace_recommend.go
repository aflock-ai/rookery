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

package detection

// TraceRecommendation aggregates per-attestor trace recommendations
// into a single trace mode for the run.
//
// Threat model:
//
//   - off    — the attestor signs an output file (sarif, sbom, scan
//     result). The process that produced it is out of scope; tracing
//     it would burn CPU without strengthening the attestation.
//   - light  — the attestor needs argv of child execs to confirm the
//     right tool was invoked (e.g. capturing OCI image refs from a
//     docker save / skopeo copy chain). No I/O capture needed.
//   - full   — the attestor's claim covers materials, network calls,
//     or filesystem writes during the build (docker build, go build,
//     pip install, npm ci). Full eBPF tracing is the only way to
//     produce a defensible "what went into this artifact" claim.
//
// When multiple attestors fire and each declares a different
// recommendation, the highest tier wins: full > light > off. The
// caller may still override (e.g. user passed --tracing=off
// explicitly), but the recommendation makes the cost/benefit visible.
type TraceRecommendation struct {
	// Mode is the highest-priority recommendation across fired attestors.
	Mode TraceMode `json:"mode"`
	// Reasons maps attestor name → declared recommendation. Used in
	// audit + LLM output so the user understands which attestor drove
	// the trace decision.
	Reasons map[string]TraceMode `json:"reasons"`
}

// RecommendTrace inspects a PlanResult and the registry to determine
// what tracing tier the run should use to satisfy the union of fired
// attestors' threat models.
//
// Pass the same registry the plan was computed against; the function
// re-reads each fired attestor's detector.yaml to extract its
// RecommendedTrace field. Returns mode=off when nothing fires or
// nothing has a recommendation.
func RecommendTrace(reg *Registry, plan PlanResult) TraceRecommendation {
	rec := TraceRecommendation{
		Mode:    TraceOff,
		Reasons: make(map[string]TraceMode, len(plan.Fire)),
	}
	for _, f := range plan.Fire {
		d, _, err := reg.Lookup(f.Attestor)
		if err != nil || d == nil {
			continue
		}
		mode := d.RecommendedTrace
		if mode == "" {
			mode = TraceOff
		}
		rec.Reasons[f.Attestor] = mode
		if traceTier(mode) > traceTier(rec.Mode) {
			rec.Mode = mode
		}
	}
	return rec
}

func traceTier(m TraceMode) int {
	switch m {
	case TraceFull:
		return 3
	case TraceLight:
		return 2
	case TraceOff, TraceUnsupported:
		return 1
	default:
		return 0
	}
}
