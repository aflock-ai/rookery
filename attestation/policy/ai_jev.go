package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
)

const (
	jevCancelled         = "cancelled"
	jevChoiceType        = "choice"
	jevScoreType         = "score"
	jevRequestLimit      = 1 << 20
	jevResponseLimit     = 1 << 20
	jevQuestionLimit     = 128
	jevEvaluationTimeout = 2 * time.Second
)

var jevPinnedModel = regexp.MustCompile(`^jev-[0-9]+\.[0-9]+\.[0-9]+$`)

// ErrAIEvaluationRefused means no completed policy verdict was produced. Code
// is bounded local vocabulary; provider-controlled diagnostics are never copied.
type ErrAIEvaluationRefused struct {
	Code  string
	cause error
}

func (e ErrAIEvaluationRefused) Error() string { return "AI evaluation refused: " + e.Code }
func (e ErrAIEvaluationRefused) Unwrap() error { return e.cause }

func aiRefusal(code string) error { return ErrAIEvaluationRefused{Code: code} }

type jevProvider struct{ key string }

// NewJevProvider uses an operator-supplied key and an explicit endpoint supplied
// at evaluation time. It never reads ambient credentials, retries, or follows
// redirects. Callers remain responsible for authorizing the selected data egress.
func NewJevProvider(apiKey string) AiBatchProvider { return &jevProvider{key: apiKey} }

func (p *jevProvider) Evaluate(ctx context.Context, att attestation.Attestor, pol AiPolicy, baseURL string) (AiResponse, error) {
	responses, err := p.EvaluateBatch(ctx, att, []AiPolicy{pol}, baseURL)
	if len(responses) == 0 {
		return AiResponse{}, err
	}
	return responses[0], err
}

type jevQuestion struct {
	Type         string      `json:"type"`
	Instructions string      `json:"instructions"`
	Criteria     interface{} `json:"criteria"`
}

type jevGroup struct {
	State     json.RawMessage        `json:"state"`
	Model     string                 `json:"model"`
	Questions map[string]jevQuestion `json:"questions"`
	indexes   []int
}

func (p *jevProvider) EvaluateBatch(ctx context.Context, att attestation.Attestor, policies []AiPolicy, baseURL string) ([]AiResponse, error) {
	if len(policies) == 0 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrAIEvaluationRefused{Code: jevCancelled, cause: err}
	}
	endpoint, err := p.preflight(att, policies, baseURL)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, jevEvaluationTimeout)
	defer cancel()
	groups, err := prepareJevGroups(ctx, att, policies)
	if err != nil {
		return nil, err
	}
	// Finish projection and size validation for every group before any egress.
	bodies, err := encodeJevGroups(groups)
	if err != nil {
		return nil, err
	}
	responses := make([]AiResponse, len(policies))
	for i, group := range groups {
		answers, err := p.request(ctx, endpoint, bodies[i], group.Model)
		if err != nil {
			return nil, err
		}
		if err := applyJevGroupAnswers(group, answers, policies, responses); err != nil {
			return nil, err
		}
	}
	for _, response := range responses {
		if response.Status == AiStatusFail {
			return responses, ErrPolicyDenied{Reasons: []string{"AI decision assertion not satisfied"}}
		}
	}
	return responses, nil
}

func (p *jevProvider) preflight(att attestation.Attestor, policies []AiPolicy, baseURL string) (string, error) {
	if p == nil || strings.TrimSpace(p.key) == "" || strings.ContainsAny(p.key, "\r\n") {
		return "", aiRefusal("missing_or_invalid_credential")
	}
	endpoint, err := jevEndpoint(baseURL)
	if err != nil {
		return "", err
	}
	if att == nil {
		return "", aiRefusal("missing_attestor")
	}
	if len(policies) > jevQuestionLimit {
		return "", aiRefusal("question_limit")
	}
	if err := validateAiPolicySet(policies, "Jev questions"); err != nil {
		return "", aiRefusal("invalid_policy")
	}
	return endpoint, nil
}

func encodeJevGroups(groups []jevGroup) ([][]byte, error) {
	var err error
	bodies := make([][]byte, len(groups))
	for i, group := range groups {
		bodies[i], err = json.Marshal(group)
		if err != nil || len(bodies[i]) > jevRequestLimit {
			return nil, aiRefusal("request_size_limit")
		}
	}
	return bodies, nil
}

func applyJevGroupAnswers(group jevGroup, answers map[string]json.RawMessage, policies []AiPolicy, responses []AiResponse) error {
	if len(answers) != len(group.Questions) {
		return aiRefusal("answer_set_mismatch")
	}
	for _, index := range group.indexes {
		pol := policies[index]
		raw, ok := answers[pol.Name]
		if !ok {
			return aiRefusal("answer_set_mismatch")
		}
		answer, err := parseJevAnswer(raw, pol)
		if err != nil {
			return err
		}
		responses[index] = decideJevAnswer(pol, answer)
	}
	return nil
}

func prepareJevGroups(ctx context.Context, att attestation.Attestor, policies []AiPolicy) ([]jevGroup, error) {
	groups := []jevGroup{}
	byState := map[string]int{}
	projected := map[string]json.RawMessage{}
	for i, pol := range policies {
		if !jevPinnedModel.MatchString(pol.Model) {
			return nil, aiRefusal("unpinned_model")
		}
		question, err := makeJevQuestion(pol)
		if err != nil {
			return nil, err
		}
		projectionKey := "whole"
		if pol.Decision.State != nil {
			projectionKey = "rego:" + string(pol.Decision.State.Module)
		}
		state, ok := projected[projectionKey]
		if !ok {
			state, err = projectJevState(ctx, att, pol.Decision.State)
			if err != nil {
				return nil, err
			}
			projected[projectionKey] = state
		}
		key := pol.Model + "\x00" + string(state)
		index, ok := byState[key]
		if !ok {
			index = len(groups)
			byState[key] = index
			groups = append(groups, jevGroup{State: state, Model: pol.Model, Questions: map[string]jevQuestion{}})
		}
		groups[index].Questions[pol.Name] = question
		groups[index].indexes = append(groups[index].indexes, i)
	}
	return groups, nil
}

func makeJevQuestion(pol AiPolicy) (jevQuestion, error) {
	if pol.Decision == nil {
		return jevQuestion{}, aiRefusal("unsupported_generative_policy")
	}
	d := pol.Decision
	var q jevQuestion
	switch {
	case d.YesNo != nil:
		// The provider's noul rubric uses true/false, not arbitrary option names.
		if len(d.YesNo.Criteria) != 2 || strings.TrimSpace(d.YesNo.Criteria["true"]) == "" || strings.TrimSpace(d.YesNo.Criteria["false"]) == "" {
			return q, aiRefusal("invalid_noul_criteria")
		}
		q = jevQuestion{"noul", d.YesNo.Instructions, d.YesNo.Criteria}
	case d.Choice != nil:
		for name, description := range d.Choice.Options {
			if strings.TrimSpace(name) == "" || strings.TrimSpace(description) == "" {
				return q, aiRefusal("invalid_choice_criteria")
			}
		}
		q = jevQuestion{jevChoiceType, d.Choice.Instructions, d.Choice.Options}
	case d.Score != nil:
		if len(d.Score.Levels) < 2 {
			return q, aiRefusal("invalid_score_levels")
		}
		for _, level := range d.Score.Levels {
			if strings.TrimSpace(level) == "" {
				return q, aiRefusal("invalid_score_levels")
			}
		}
		q = jevQuestion{jevScoreType, d.Score.Instructions, d.Score.Levels}
	default:
		return q, aiRefusal("invalid_policy")
	}
	if strings.TrimSpace(q.Instructions) == "" {
		return q, aiRefusal("missing_instructions")
	}
	return q, nil
}

func jevEndpoint(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", aiRefusal("invalid_endpoint")
	}
	// Plain HTTP is only for loopback test/local providers, never remote egress.
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return "", aiRefusal("insecure_endpoint")
		}
	}
	u.Path = "/v1/systemone"
	return u.String(), nil
}

func (p *jevProvider) request(ctx context.Context, endpoint string, body []byte, model string) (map[string]json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrAIEvaluationRefused{Code: jevCancelled, cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, aiRefusal("invalid_request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.key)
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrAIEvaluationRefused{Code: jevCancelled, cause: ctx.Err()}
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return nil, aiRefusal("provider_timeout")
		}
		return nil, aiRefusal("provider_unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, jevResponseLimit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrAIEvaluationRefused{Code: jevCancelled, cause: ctx.Err()}
		}
		return nil, aiRefusal("response_read_failed")
	}
	if len(data) > jevResponseLimit {
		return nil, aiRefusal("response_size_limit")
	}
	return decodeJevResponse(resp.StatusCode, data, model)
}

func decodeJevResponse(status int, data []byte, model string) (map[string]json.RawMessage, error) {
	if status != http.StatusOK {
		var detail struct {
			Detail struct {
				ErrorType string `json:"error_type"`
			} `json:"detail"`
		}
		if status == http.StatusBadRequest && json.Unmarshal(data, &detail) == nil && detail.Detail.ErrorType == "max_tokens_exceeded" {
			return nil, aiRefusal("max_tokens_exceeded")
		}
		return nil, aiRefusal("http_" + strconv.Itoa(status))
	}
	if err := validateJevJSON(data); err != nil {
		return nil, aiRefusal("malformed_response")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(data, &envelope) != nil {
		return nil, aiRefusal("malformed_response")
	}
	var resolved string
	if json.Unmarshal(envelope["model"], &resolved) != nil || resolved != model {
		return nil, aiRefusal("model_mismatch")
	}
	var answers map[string]json.RawMessage
	if json.Unmarshal(envelope["answers"], &answers) != nil || answers == nil {
		return nil, aiRefusal("missing_answers")
	}
	return answers, nil
}

// JSON duplicates are ambiguous even when the last occurrence is well typed.
func validateJevJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := walkJevJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func walkJevJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON too deep")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate JSON member")
			}
			seen[name] = true
		}
		if err := walkJevJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

type jevAnswer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul"`
	Choice        string             `json:"choice"`
	Score         *float64           `json:"score"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    *float64           `json:"confidence"`
	Legend        map[string]string  `json:"legend"`
}

func finiteUnit(v *float64) bool {
	return v != nil && !math.IsNaN(*v) && !math.IsInf(*v, 0) && *v >= 0 && *v <= 1
}

func parseJevAnswer(raw json.RawMessage, pol AiPolicy) (*AiAnswer, error) {
	var wire jevAnswer
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil || json.Unmarshal(raw, &wire) != nil {
		return nil, aiRefusal("malformed_answer")
	}
	if err := validateJevProbabilityFields(fields); err != nil {
		return nil, err
	}

	allowed := map[string]bool{"type": true}
	d := pol.Decision
	answer := &AiAnswer{}
	switch {
	case d.YesNo != nil:
		allowed["noul"] = true
		if wire.Type != "noul" || !finiteUnit(wire.Noul) {
			return nil, aiRefusal("invalid_noul_answer")
		}
		answer.Type, answer.YesNo = "yesNo", wire.Noul
	case d.Choice != nil:
		for _, field := range []string{jevChoiceType, "probabilities", "confidence"} {
			allowed[field] = true
		}
		if err := validateJevChoice(wire, d.Choice); err != nil {
			return nil, err
		}
		answer.Type, answer.Choice, answer.Confidence, answer.Probabilities = jevChoiceType, wire.Choice, wire.Confidence, wire.Probabilities
	case d.Score != nil:
		for _, field := range []string{jevScoreType, "probabilities", "confidence", "legend"} {
			allowed[field] = true
		}
		if err := validateJevScore(wire, d.Score); err != nil {
			return nil, err
		}
		answer.Type, answer.Score, answer.Confidence, answer.Probabilities = jevScoreType, wire.Score, wire.Confidence, wire.Probabilities
	}
	if err := validateJevAnswerFields(fields, allowed); err != nil {
		return nil, err
	}
	return answer, nil
}

func validateJevAnswerFields(fields map[string]json.RawMessage, allowed map[string]bool) error {
	for field := range fields {
		if !allowed[field] {
			return aiRefusal("unexpected_answer_field")
		}
	}
	return nil
}

func validateJevProbabilityFields(fields map[string]json.RawMessage) error {
	if data, ok := fields["probabilities"]; ok {
		var probabilities map[string]*float64
		if json.Unmarshal(data, &probabilities) != nil || probabilities == nil {
			return aiRefusal("invalid_distribution")
		}
		for _, value := range probabilities {
			if !finiteUnit(value) {
				return aiRefusal("invalid_distribution")
			}
		}
	}
	return nil
}

func validateJevChoice(wire jevAnswer, question *AiChoice) error {
	if wire.Type != jevChoiceType || !finiteUnit(wire.Confidence) {
		return aiRefusal("invalid_choice_answer")
	}
	if _, ok := question.Options[wire.Choice]; !ok {
		return aiRefusal("unknown_choice")
	}
	if err := validateJevDistribution(wire.Probabilities, question.Options); err != nil {
		return err
	}
	for _, probability := range wire.Probabilities {
		if probability > wire.Probabilities[wire.Choice] {
			return aiRefusal("inconsistent_choice")
		}
	}
	return nil
}

func validateJevScore(wire jevAnswer, question *AiScore) error {
	if wire.Type != jevScoreType || !finiteUnit(wire.Confidence) || wire.Score == nil || math.IsNaN(*wire.Score) || math.IsInf(*wire.Score, 0) || *wire.Score < 0 || *wire.Score > float64(len(question.Levels)-1) {
		return aiRefusal("invalid_score_answer")
	}
	levels := map[string]string{}
	for i, level := range question.Levels {
		levels[strconv.Itoa(i)] = level
	}
	if err := validateJevDistribution(wire.Probabilities, levels); err != nil {
		return err
	}
	if len(wire.Legend) != len(levels) {
		return aiRefusal("score_legend_mismatch")
	}
	weighted := 0.0
	for i, level := range question.Levels {
		key := strconv.Itoa(i)
		if wire.Legend[key] != level {
			return aiRefusal("score_legend_mismatch")
		}
		weighted += float64(i) * wire.Probabilities[key]
	}
	if math.Abs(weighted-*wire.Score) > 0.0001 {
		return aiRefusal("inconsistent_score")
	}
	return nil
}

func validateJevDistribution(probabilities map[string]float64, options map[string]string) error {
	if len(probabilities) != len(options) {
		return aiRefusal("invalid_distribution")
	}
	sum := 0.0
	for key := range options {
		v, ok := probabilities[key]
		if !ok || !finiteUnit(&v) {
			return aiRefusal("invalid_distribution")
		}
		sum += v
	}
	if math.Abs(sum-1) > 0.0001 {
		return aiRefusal("invalid_distribution")
	}
	return nil
}

func decideJevAnswer(pol AiPolicy, answer *AiAnswer) AiResponse {
	pass := true
	switch {
	case pol.Decision.YesNo != nil:
		q := pol.Decision.YesNo
		pass = (q.MinProbability == nil || *answer.YesNo >= *q.MinProbability) && (q.MaxProbability == nil || *answer.YesNo <= *q.MaxProbability)
	case pol.Decision.Choice != nil:
		q := pol.Decision.Choice
		pass = (len(q.Allow) == 0 || slices.Contains(q.Allow, answer.Choice)) && !slices.Contains(q.Deny, answer.Choice) && (q.MinConfidence == nil || *answer.Confidence >= *q.MinConfidence)
	case pol.Decision.Score != nil:
		q := pol.Decision.Score
		pass = (q.MinScore == nil || *answer.Score >= *q.MinScore) && (q.MaxScore == nil || *answer.Score <= *q.MaxScore)
	}
	response := AiResponse{Status: AiStatusPass, Reason: "typed decision assertions satisfied", Model: pol.Model, Answer: answer}
	if !pass {
		response.Status, response.Reason = AiStatusFail, "typed decision assertions not satisfied"
	}
	return response
}
