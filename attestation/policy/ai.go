package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/invopop/jsonschema"
)

const (
	defaultAIServerURL = "http://judge-ollama.judge.svc.cluster.local:11434"
	defaultAIModel     = "llama3.2"
	defaultAITimeout   = 120 * time.Second
)

// AiResponse represents the result of an AI policy evaluation.
type AiResponse struct {
	Status string `json:"status"` // Pass/Fail status of the policy evaluation
	Reason string `json:"reason"` // Explanation of the evaluation result
}

// EvaluateAIPolicy evaluates if the given attestor passes the provided AI policies.
// Returns an array of AI responses and an error if any policy evaluation fails.
func EvaluateAIPolicy(attestor attestation.Attestor, policies []AiPolicy, serverURL string) ([]AiResponse, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	responses := make([]AiResponse, 0, len(policies))

	for _, policy := range policies {
		result, err := ExecuteAiPolicy(attestor, policy, serverURL)
		responses = append(responses, result)

		if err != nil {
			return responses, err
		}
	}

	return responses, nil
}

func generateSchema[T any]() interface{} {
	reflector := jsonschema.Reflector{
		AllowAdditionalProperties: false,
		DoNotReference:            true,
	}
	var v T
	schema := reflector.Reflect(v)
	return schema
}

// ExecuteAiPolicy evaluates a single AI policy against an attestor using an Ollama-compatible API.
func ExecuteAiPolicy(attestor attestation.Attestor, pol AiPolicy, serverURL string) (AiResponse, error) {
	data, err := json.Marshal(attestor)
	if err != nil {
		return AiResponse{}, fmt.Errorf("failed to marshal attestor: %w", err)
	}

	if serverURL == "" {
		serverURL = defaultAIServerURL
	}

	prompt := fmt.Sprintf("Given the following attestation data:\n%s\n\nEvaluate the following policy:\n%s\n\nIn the response, the Status field MUST be exactly 'PASS' or 'FAIL', and include a detailed Reason for the evaluation result.", string(data), pol.Prompt)

	model := pol.Model
	if model == "" {
		model = defaultAIModel
	}

	reqBody := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}

	schema := generateSchema[AiResponse]()
	reqBody["format"] = schema

	reqBodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return AiResponse{}, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/api/generate", bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return AiResponse{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: defaultAITimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return AiResponse{}, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return AiResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var res struct {
		Response string `json:"response"`
	}

	err = json.Unmarshal(bodyBytes, &res)
	if err != nil {
		return AiResponse{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	var aiResponse AiResponse
	if err := json.Unmarshal([]byte(res.Response), &aiResponse); err != nil {
		return AiResponse{}, fmt.Errorf("failed to parse AI response: %w", err)
	}

	if aiResponse.Status != "PASS" && aiResponse.Status != "FAIL" {
		return AiResponse{}, fmt.Errorf("invalid status in AI response: %s", aiResponse.Status)
	}

	if aiResponse.Status == "FAIL" {
		return aiResponse, fmt.Errorf("AI policy evaluation failed: %s", aiResponse.Reason)
	}

	return aiResponse, nil
}
