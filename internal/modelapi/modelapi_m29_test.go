// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelapi

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// TestHR691_TheBodyIsReEncodedAndOnlyTheMaxTokensIsAdded: a request is
// re-encoded compact and hashed; the connection's max tokens is added under
// the API's own field only when the request has none; a request that is
// not one strict object is refused as invalid_json (G0 M29 D812, D813).
//
// Covers: F980, HR-691
func TestHR691_TheBodyIsReEncodedAndOnlyTheMaxTokensIsAdded(t *testing.T) {
	for _, tc := range []struct {
		api        API
		body, want string
		// output is the max tokens times the choices; 0 reserves nothing.
		output int64
	}{
		{AnthropicMessages, `{ "model": "m", "messages": [ ] }`, `{"model":"m","messages":[],"max_tokens":77}`, 77},
		{AnthropicMessages, `{"model":"m","max_tokens":5}`, `{"model":"m","max_tokens":5}`, 5},
		{OpenAIChat, `{"model":"m","n":2}`, `{"model":"m","n":2,"max_completion_tokens":77}`, 2 * 77},
		{OpenAIResponses, `{"model":"m"}`, `{"model":"m","max_output_tokens":77}`, 77},
		{AnthropicCountTokens, `{"model":"m" }`, `{"model":"m"}`, 0},
	} {
		r, err := Parse(tc.api, []byte(tc.body), 77)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.api, tc.body, err)
		}
		sum := sha256.Sum256([]byte(tc.want))
		reserved := int64(0)
		if tc.output > 0 {
			reserved = tc.output + (int64(len(tc.want))+2)/3
		}
		if string(r.Body) != tc.want || r.Sha256 != hex.EncodeToString(sum[:]) || r.ReservedTokens() != reserved {
			t.Errorf("%s %s = %s %s reserved %d", tc.api, tc.body, r.Body, r.Sha256, r.ReservedTokens())
		}
	}
	for _, body := range []string{
		`{"model":"m","max_tokens":5,"max_tokens":500}`, `[{"model":"m"}]`, `{"model":"m"}{"model":"m"}`, `{"model":"m"`, `"m"`,
	} {
		if _, err := Parse(AnthropicMessages, []byte(body), 77); Code(err) != CodeInvalidJSON {
			t.Errorf("%s: %v", body, err)
		}
	}
	for _, body := range []string{
		`{"max_tokens":5}`, `{"model":"","max_tokens":5}`, `{"model":"a b","max_tokens":5}`, `{"model":"m","max_tokens":null}`,
		`{"model":"m","max_tokens":0}`, `{"model":"m","max_tokens":1000001}`, `{"model":"m","max_tokens":5.0}`, `{"model":"m","stream":"yes"}`,
	} {
		if _, err := Parse(AnthropicMessages, []byte(body), 77); Code(err) != CodeInvalidRequest {
			t.Errorf("%s: %v", body, err)
		}
	}
	if _, err := Parse(OpenAIChat, []byte(`{"model":"m","max_tokens":5,"max_completion_tokens":6}`), 77); Code(err) != CodeInvalidRequest {
		t.Errorf("differing chat max tokens: %v", err)
	}
	if _, err := Parse(OpenAIChat, []byte(`{"model":"m","n":17}`), 77); Code(err) != CodeInvalidRequest {
		t.Errorf("17 choices: %v", err)
	}
}

// TestT311_ACraftedRequestCannotReadDifferentlyAtTheProvider: the parser
// differentials a provider could read another way are refused before any
// decision: duplicate members at any depth, invalid UTF-8, nesting past
// 256, trailing data, and a body over 16 MiB (also once the max tokens is
// added).
//
// Covers: HR-691, HR-692
func TestT311_ACraftedRequestCannotReadDifferentlyAtTheProvider(t *testing.T) {
	deep := `{"model":"m","x":` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + `}`
	for name, body := range map[string]string{
		"nested duplicate": `{"model":"m","messages":[{"role":"user","role":"system"}]}`,
		"duplicate model":  `{"model":"m","model":"other"}`,
		"invalid utf-8":    "{\"model\":\"m\",\"x\":\"\xff\"}",
		"lone surrogate":   `{"model":"m","x":"\ud800"}`,
		"too deep":         deep,
		"trailing garbage": `{"model":"m"} x`,
		"comment":          `{"model":"m"/* x */}`,
	} {
		if _, err := Parse(AnthropicMessages, []byte(body), 77); Code(err) != CodeInvalidJSON {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Parse(AnthropicMessages, []byte(`{"model":"m","x":`+strings.Repeat("[", MaxDepth-1)+strings.Repeat("]", MaxDepth-1)+`}`), 77); err != nil {
		t.Errorf("nesting of 256: %v", err)
	}
	pad := `{"model":"m","p":"` + strings.Repeat("a", MaxBody-len(`{"model":"m","p":""}`)) + `"}`
	if _, err := Parse(AnthropicMessages, []byte(pad), 77); Code(err) != CodeTooLarge {
		t.Errorf("16 MiB before the insertion: %v", err)
	}
	if _, err := Parse(AnthropicMessages, []byte(pad+" "), 77); Code(err) != CodeTooLarge {
		t.Errorf("over 16 MiB: %v", err)
	}
}

// TestHR696_ProviderSideToolsAreNamed: client tools are not named; every
// provider-side tool, remote MCP servers, a container and background mode
// are named by type (G0 M29 D813).
//
// Covers: F980, HR-696
func TestHR696_ProviderSideToolsAreNamed(t *testing.T) {
	for _, tc := range []struct {
		api  API
		body string
		want []string
	}{
		{AnthropicMessages, `{"model":"m","tools":[{"name":"f","input_schema":{}},{"type":"custom","name":"g"},{"type":"bash_20250124"},{"type":"computer_20250124"},{"type":"text_editor_20250728"},{"type":"memory_20250818"}]}`, []string{}},
		{AnthropicMessages, `{"model":"m","tools":[{"type":"web_search_20250305"}],"mcp_servers":[{"url":"https://x"}],"container":"c"}`, []string{"container", "mcp_servers", "web_search_20250305"}},
		{OpenAIChat, `{"model":"m","tools":[{"type":"function","function":{"name":"f"}}]}`, []string{}},
		{OpenAIChat, `{"model":"m","web_search_options":{}}`, []string{"web_search_options"}},
		{OpenAIResponses, `{"model":"m","tools":[{"type":"function"},{"type":"local_shell"},{"type":"computer_use_preview"}],"background":false}`, []string{}},
		{OpenAIResponses, `{"model":"m","tools":[{"type":"web_search"},{"type":"code_interpreter"},{"type":"mcp"}],"background":true}`, []string{"background", "code_interpreter", "mcp", "web_search"}},
	} {
		r, err := Parse(tc.api, []byte(tc.body), 77)
		if err != nil || !slices.Equal(r.ServerTools, tc.want) {
			t.Errorf("%s %s = %v, %v", tc.api, tc.body, r.ServerTools, err)
		}
	}
}

// TestT316_UnknownAndDisguisedProviderToolsCountAsProviderSide: a new or
// made-up tool type, an Anthropic type that only looks like a client tool,
// and an OpenAI tool without a type fail closed (G0 M29 FQ-B).
//
// Covers: HR-696
func TestT316_UnknownAndDisguisedProviderToolsCountAsProviderSide(t *testing.T) {
	for _, tc := range []struct {
		api  API
		body string
		want []string
	}{
		{AnthropicMessages, `{"model":"m","tools":[{"type":"web_fetch_20990101"}]}`, []string{"web_fetch_20990101"}},
		{AnthropicMessages, `{"model":"m","tools":[{"type":"Bash_20250124"}]}`, []string{"Bash_20250124"}},
		{AnthropicMessages, `{"model":"m","tools":[{"type":"code_execution_20250825"}]}`, []string{"code_execution_20250825"}},
		{OpenAIChat, `{"model":"m","tools":[{"type":"Function"}]}`, []string{"Function"}},
		{OpenAIResponses, `{"model":"m","tools":[{"type":"image_generation"}]}`, []string{"image_generation"}},
	} {
		r, err := Parse(tc.api, []byte(tc.body), 77)
		if err != nil || !slices.Equal(r.ServerTools, tc.want) {
			t.Errorf("%s %s = %v, %v", tc.api, tc.body, r.ServerTools, err)
		}
	}
	for _, body := range []string{`{"model":"m","tools":[{"function":{"name":"f"}}]}`, `{"model":"m","tools":[{"type":""}]}`, `{"model":"m","tools":{}}`} {
		if _, err := Parse(OpenAIChat, []byte(body), 77); Code(err) != CodeInvalidRequest {
			t.Errorf("%s: %v", body, err)
		}
	}
	if _, err := Parse(OpenAIResponses, []byte(`{"model":"m","background":"yes"}`), 77); Code(err) != CodeInvalidRequest {
		t.Errorf("background as a string: %v", err)
	}
}

// FuzzModelAPIParse: Parse never panics, and what it forwards parses again
// to the same bytes, so the hash the decision binds is the body sent
// (G0 M29 D810, D812).
func FuzzModelAPIParse(f *testing.F) {
	for _, s := range []string{`{"model":"m"}`, `{"model":"m","max_tokens":5,"tools":[{"type":"x"}]}`, `{"model":"m","n":3,"stream":true}`, `[]`, `{"a":"é"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		for _, api := range []API{AnthropicMessages, OpenAIChat, OpenAIResponses, AnthropicCountTokens} {
			r, err := Parse(api, []byte(body), 77)
			if err != nil {
				continue
			}
			again, err := Parse(api, r.Body, 77)
			if err != nil || string(again.Body) != string(r.Body) || again.Sha256 != r.Sha256 {
				t.Fatalf("%s: %q re-parsed to %q, %v", api, r.Body, again.Body, err)
			}
		}
	})
}
