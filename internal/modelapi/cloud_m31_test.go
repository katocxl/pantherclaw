// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelapi

import (
	"slices"
	"strings"
	"testing"
)

// TestHR727_BedrockAndVertexCallsAreReadLikeModelCalls: a Converse call's
// model comes from the path and its max tokens from inferenceConfig (the
// gateway's default inserted when absent), so a token budget reserves it;
// a Vertex call is the Messages format with the model in the path; the
// answers' usage is counted.
//
// Covers: HR-727
func TestHR727_BedrockAndVertexCallsAreReadLikeModelCalls(t *testing.T) {
	r, err := ParsePath(BedrockConverse, "anthropic.claude-sonnet-4-5-v1:0",
		[]byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"lookup"}}]}}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if r.Model != "anthropic.claude-sonnet-4-5-v1:0" || r.MaxTokens != 1024 || !r.Inserted || len(r.ServerTools) != 0 ||
		!strings.Contains(string(r.Body), `"inferenceConfig":{"maxTokens":1024}`) || r.ReservedTokens() <= 1024 {
		t.Fatalf("converse %+v %s", r, r.Body)
	}
	r, err = ParsePath(BedrockConverse, "anthropic.claude-sonnet-4-5-v1:0",
		[]byte(`{"messages":[],"inferenceConfig":{"maxTokens":64}}`), 1024)
	if err != nil || r.MaxTokens != 64 || r.Inserted {
		t.Fatalf("set max tokens %+v %v", r, err)
	}
	v, err := ParsePath(VertexRawPredict, "claude-sonnet-4-5@20250929",
		[]byte(`{"anthropic_version":"vertex-2023-10-16","max_tokens":32,"messages":[{"role":"user","content":"hi"}]}`), 1024)
	if err != nil || v.Model != "claude-sonnet-4-5@20250929" || v.MaxTokens != 32 {
		t.Fatalf("vertex %+v %v", v, err)
	}
	u := AnswerUsage(BedrockConverse, []byte(`{"output":{},"usage":{"inputTokens":12,"outputTokens":5,"cacheReadInputTokens":3,"totalTokens":20}}`))
	if u.Input != 12 || u.Output != 5 || u.CacheRead != 3 || u.Total() != 20 {
		t.Fatalf("bedrock usage %+v", u)
	}
	if u := AnswerUsage(VertexRawPredict, []byte(`{"usage":{"input_tokens":7,"output_tokens":2}}`)); u.Total() != 9 {
		t.Fatalf("vertex usage %+v", u)
	}
}

// TestHR727_ProviderSideToolsOnTheCloudsAreNamed: a Bedrock system tool or
// an unknown tool entry, and an Anthropic server tool passed to Bedrock or
// Vertex, are named as provider-side tools for the M29 rule to refuse
// unless allowed (fail closed); a malformed max tokens is refused before
// any decision.
//
// Covers: HR-727, T-334
func TestHR727_ProviderSideToolsOnTheCloudsAreNamed(t *testing.T) {
	r, err := ParsePath(BedrockConverse, "anthropic.claude-sonnet-4-5-v1:0", []byte(`{"messages":[],"toolConfig":{"tools":[`+
		`{"toolSpec":{"name":"a"}},{"systemTool":{"name":"web_grounding"}}]},`+
		`"additionalModelRequestFields":{"tools":[{"type":"web_search_20250305","name":"web_search"}]}}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.ServerTools, "systemTool") || !slices.Contains(r.ServerTools, "web_search_20250305") {
		t.Fatalf("server tools %v", r.ServerTools)
	}
	v, err := ParsePath(VertexRawPredict, "claude-sonnet-4-5@20250929",
		[]byte(`{"anthropic_version":"vertex-2023-10-16","max_tokens":32,"messages":[],"tools":[{"type":"code_execution_20250522","name":"code"}]}`), 1024)
	if err != nil || !slices.Contains(v.ServerTools, "code_execution_20250522") {
		t.Fatalf("vertex server tools %v %v", v, err)
	}
	for name, body := range map[string]string{
		"max tokens text": `{"messages":[],"inferenceConfig":{"maxTokens":"64"}}`,
		"max tokens zero": `{"messages":[],"inferenceConfig":{"maxTokens":0}}`,
		"two tool kinds":  `{"messages":[],"toolConfig":{"tools":[{"toolSpec":{},"systemTool":{}}]}}`,
	} {
		if _, err := ParsePath(BedrockConverse, "anthropic.claude-sonnet-4-5-v1:0", []byte(body), 1024); Code(err) != CodeInvalidRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParsePath(BedrockConverse, "a model", []byte(`{"messages":[]}`), 1024); err == nil {
		t.Error("a model id with a space")
	}
}
