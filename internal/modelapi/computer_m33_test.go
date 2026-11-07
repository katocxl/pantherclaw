// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelapi_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/modelapi"
)

func serverTools(t *testing.T, api modelapi.API, body string) []string {
	t.Helper()
	var (
		r   *modelapi.Request
		err error
	)
	if api.ModelInPath() {
		r, err = modelapi.ParsePath(api, "anthropic.claude-test-v1:0", []byte(body), 1024)
	} else {
		r, err = modelapi.Parse(api, []byte(body), 1024)
	}
	if err != nil {
		t.Fatalf("%s %s: %v", api, body, err)
	}
	return r.ServerTools
}

// TestHR756_DeclaringAComputerToolNamesComputerUse: an Anthropic computer_*
// tool (Messages, Vertex, Bedrock's additional fields) and the Responses
// API's computer_use_preview add the pseudo-name computer_use, so the gate
// asks for it; the tool stays client-run (it is not itself a server tool).
func TestHR756_DeclaringAComputerToolNamesComputerUse(t *testing.T) {
	for name, tc := range map[string]struct {
		api  modelapi.API
		body string
	}{
		"anthropic": {modelapi.AnthropicMessages, `{"model":"claude-test","max_tokens":100,"messages":[{"role":"user","content":"hi"}],` +
			`"tools":[{"type":"computer_20250124","name":"computer","display_width_px":1024,"display_height_px":768}]}`},
		"anthropic newer": {modelapi.AnthropicMessages, `{"model":"claude-test","max_tokens":100,"messages":[],` +
			`"tools":[{"type":"computer_20251124","name":"computer"},{"name":"lookup","input_schema":{"type":"object"}}]}`},
		"vertex": {modelapi.VertexRawPredict, `{"anthropic_version":"vertex-2023-10-16","max_tokens":100,"messages":[],` +
			`"tools":[{"type":"computer_20250124","name":"computer"}]}`},
		"responses": {modelapi.OpenAIResponses, `{"model":"computer-use-preview","input":"hi",` +
			`"tools":[{"type":"computer_use_preview","display_width":1024,"display_height":768,"environment":"browser"}]}`},
		"bedrock": {modelapi.BedrockConverse, `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"inferenceConfig":{"maxTokens":100},` +
			`"additionalModelRequestFields":{"tools":[{"type":"computer_20250124","name":"computer"}]}}`},
	} {
		got := serverTools(t, tc.api, tc.body)
		if !slices.Equal(got, []string{modelapi.ComputerUse}) {
			t.Errorf("%s: server tools %v, want [computer_use] only", name, got)
		}
	}
}

// TestHR756_OtherToolsDoNotNameComputerUse: custom tools, the bash and text
// editor client tools, Chat functions and a Responses function never add
// computer_use.
func TestHR756_OtherToolsDoNotNameComputerUse(t *testing.T) {
	for name, tc := range map[string]struct {
		api  modelapi.API
		body string
	}{
		"anthropic custom": {modelapi.AnthropicMessages, `{"model":"claude-test","max_tokens":100,"messages":[],` +
			`"tools":[{"name":"computer","input_schema":{"type":"object"}},{"type":"bash_20250124","name":"bash"},{"type":"text_editor_20250124","name":"str_replace_editor"}]}`},
		"chat function": {modelapi.OpenAIChat, `{"model":"gpt-test","messages":[],` +
			`"tools":[{"type":"function","function":{"name":"computer_use_preview"}}]}`},
		"responses function": {modelapi.OpenAIResponses, `{"model":"gpt-test","input":"hi",` +
			`"tools":[{"type":"function","name":"computer"}]}`},
	} {
		if got := serverTools(t, tc.api, tc.body); slices.Contains(got, modelapi.ComputerUse) {
			t.Errorf("%s: server tools %v", name, got)
		}
	}
}
