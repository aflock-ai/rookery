package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

func projectJevState(ctx context.Context, att attestation.Attestor, projection *RegoPolicy) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrAIEvaluationRefused{Code: jevCancelled, cause: err}
	}
	raw, err := json.Marshal(att)
	if err != nil || len(raw) > 8<<20 {
		return nil, aiRefusal("input_size_or_encoding")
	}
	if err := validateJevJSON(raw); err != nil {
		return nil, aiRefusal("invalid_input")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var input interface{}
	if err := decoder.Decode(&input); err != nil {
		return nil, aiRefusal("invalid_input")
	}
	state := input
	if projection != nil {
		state, err = evaluateJevProjection(ctx, projection, input)
		if err != nil {
			return nil, err
		}
	}
	switch state.(type) {
	case string, map[string]interface{}, []interface{}:
	default:
		return nil, aiRefusal("invalid_state_shape")
	}
	raw, err = json.Marshal(state)
	if err != nil || len(raw) > jevRequestLimit {
		return nil, aiRefusal("state_size_limit")
	}
	return raw, nil
}

func evaluateJevProjection(ctx context.Context, projection *RegoPolicy, input interface{}) (interface{}, error) {
	module, err := ast.ParseModuleWithOpts("jev-state.rego", string(projection.Module), ast.ParserOptions{RegoVersion: ast.RegoV0})
	if err != nil {
		return nil, aiRefusal("invalid_projection")
	}
	query := fmt.Sprintf("%s.state", module.Package.Path)
	evaluator := rego.New(rego.ParsedModule(module), rego.Query(query), rego.Input(input), rego.Capabilities(restrictedCapabilities()), rego.StrictBuiltinErrors(true), rego.UnsafeBuiltins(map[string]struct{}{"time.now_ns": {}, "rand.intn": {}, "uuid.rfc4122": {}}))
	result, err := evaluator.Eval(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrAIEvaluationRefused{Code: jevCancelled, cause: ctx.Err()}
		}
		return nil, aiRefusal("projection_error")
	}
	if len(result) != 1 || len(result[0].Expressions) != 1 {
		return nil, aiRefusal("undefined_projection")
	}
	return result[0].Expressions[0].Value, nil
}
