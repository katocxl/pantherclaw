// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package modelapi reads model provider requests and answers for the
// gateway's model connections (G0 M29 D810, D812, D813, D818; HR-691,
// HR-696). It is a pure leaf: the standard library only, no I/O, clock or
// randomness.
//
// Parse strictly parses a request body (exactly one JSON object, no
// duplicate member names, valid UTF-8, nesting at most 256 deep, at most 16
// MiB) and re-encodes it compactly. The re-encoded body is what the gateway
// forwards and hashes: the decision, any approval and the receipt bind its
// sha256 (the written exception to HR-075 for model connections, HR-691).
// The only edit is inserting the connection's max-tokens value when the
// request has none. Parse also extracts the metadata the decision is made on
// (model, max tokens, choices, stream, input size, provider-side tools) and
// every string of the body, which the gateway's secret scan reads (D817).
//
// Usage and Stream read the token usage a provider reports in a JSON answer
// or an event stream (D818).
package modelapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// API is a model provider API. The values are the definitions' model
// dispatch APIs (internal/definitions/domain ModelAPI*).
type API string

// APIs (D813).
const (
	AnthropicMessages    API = "anthropic.messages"
	AnthropicCountTokens API = "anthropic.count_tokens" //nolint:gosec // G101: an API name, not a credential
	AnthropicModels      API = "anthropic.models"
	OpenAIChat           API = "openai.chat"
	OpenAIResponses      API = "openai.responses"
	OpenAIModels         API = "openai.models"
)

// APIs lists every API.
var APIs = []API{AnthropicMessages, AnthropicCountTokens, AnthropicModels, OpenAIChat, OpenAIResponses, OpenAIModels}

// Read reports whether a lists or reads models: a GET with no body.
func (a API) Read() bool { return a == AnthropicModels || a == OpenAIModels }

// Anthropic reports whether a is one of Anthropic's APIs.
func (a API) Anthropic() bool { return strings.HasPrefix(string(a), "anthropic.") }

// MaxTokensField is the request member that holds a's max output tokens
// (the one the gateway inserts when it is absent); empty for an API without
// one.
func (a API) MaxTokensField() string {
	switch a {
	case AnthropicMessages:
		return "max_tokens"
	case OpenAIChat:
		return "max_completion_tokens"
	case OpenAIResponses:
		return "max_output_tokens"
	case AnthropicCountTokens, AnthropicModels, OpenAIModels:
	}
	return ""
}

// Limits (D812, D813).
const (
	// MaxBody is the largest request (and forwarded) body.
	MaxBody = 16 << 20
	// MaxDepth is the deepest nesting of objects and arrays.
	MaxDepth = 256
	// MaxTokens is the largest max-tokens value.
	MaxTokens = 1_000_000
	// MaxChoices is the largest number of chat choices (n).
	MaxChoices = 16
	// MaxModelID is the longest model id.
	MaxModelID = 256
	// MaxServerTools is the most provider-side tool types one request names.
	MaxServerTools = 32
)

// Error codes. Each maps to the provider-shaped refusal of D819.
const (
	// CodeTooLarge: the body is over MaxBody (413).
	CodeTooLarge = "body_too_large"
	// CodeInvalidJSON: not exactly one strict JSON object (400).
	CodeInvalidJSON = "invalid_json"
	// CodeInvalidRequest: a field the gateway reads is missing or out of
	// range (400).
	CodeInvalidRequest = "invalid_request"
)

// Error is a request the gateway refuses before any decision. Message never
// carries the body's content.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return "modelapi: " + e.Code + ": " + e.Message }

func fail(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Code returns err's code, or "" when err is not an *Error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Request is a parsed model request (D812, D813).
type Request struct {
	API API
	// Body is the re-encoded body the gateway forwards, the max-tokens
	// value inserted when it was absent; Sha256 is its sha256 in lowercase
	// hex (the ActionIR param body_sha256).
	Body   []byte
	Sha256 string
	// Model is the requested model id.
	Model string
	// MaxTokens is the max output tokens (0 for token counting), and
	// Inserted whether the gateway added it.
	MaxTokens int64
	Inserted  bool
	// Choices is the number of chat choices (n, default 1); 1 elsewhere.
	Choices int64
	// Stream is whether the answer is an event stream.
	Stream bool
	// ServerTools are the provider-side tool types the request names,
	// sorted and unique (D813, HR-696).
	ServerTools []string
	// Strings are every string of the body, member names included, as
	// decoded: the parts the secret scan reads (D817). StringBytes is their
	// total length.
	Strings     []string
	StringBytes int64
}

// InputBytes is the length of the forwarded body.
func (r *Request) InputBytes() int64 { return int64(len(r.Body)) }

// ReservedTokens is what a token rule reserves for the call before it is
// sent (D813, HR-693): the max tokens times the choices plus a third of the
// body's bytes, rounded up; 0 for token counting and reads.
func (r *Request) ReservedTokens() int64 {
	switch r.API {
	case AnthropicMessages, OpenAIResponses:
		return r.MaxTokens + (r.InputBytes()+2)/3
	case OpenAIChat:
		return r.MaxTokens*r.Choices + (r.InputBytes()+2)/3
	case AnthropicCountTokens, AnthropicModels, OpenAIModels:
	}
	return 0
}

// CheckModelID checks a model id: 1..256 bytes of printable ASCII without
// spaces (the ActionIR identifier rules, HR-102).
func CheckModelID(id string) error {
	if id == "" || len(id) > MaxModelID {
		return fail(CodeInvalidRequest, "model must be 1..%d bytes", MaxModelID)
	}
	for i := range len(id) {
		if c := id[i]; c < 0x21 || c > 0x7e {
			return fail(CodeInvalidRequest, "model must be printable ASCII without spaces")
		}
	}
	return nil
}

// Parse strictly parses a request body for api and re-encodes it, inserting
// defaultMaxTokens (1..MaxTokens) under api's max-tokens field when the
// request has none. A read API has no body: Parse refuses it.
func Parse(api API, body []byte, defaultMaxTokens int64) (*Request, error) {
	if !slices.Contains(APIs, api) || api.Read() {
		return nil, fmt.Errorf("modelapi: %q has no request body", api)
	}
	if field := api.MaxTokensField(); field != "" && (defaultMaxTokens < 1 || defaultMaxTokens > MaxTokens) {
		return nil, fmt.Errorf("modelapi: default max tokens %d out of range", defaultMaxTokens)
	}
	if len(body) > MaxBody {
		return nil, fail(CodeTooLarge, "the body is over %d bytes", MaxBody)
	}
	r := &Request{API: api, Choices: 1}
	out, top, err := r.walk(body)
	if err != nil {
		return nil, err
	}
	if err := r.extract(top); err != nil {
		return nil, err
	}
	if field := api.MaxTokensField(); field != "" && r.MaxTokens == 0 {
		// The only edit (D812): the connection's max tokens, under this
		// API's field, as the last member of the object.
		member := strconv.Quote(field) + ":" + strconv.FormatInt(defaultMaxTokens, 10)
		if len(out) > 2 {
			member = "," + member
		}
		out = slices.Concat(out[:len(out)-1], []byte(member), []byte("}"))
		r.MaxTokens, r.Inserted = defaultMaxTokens, true
	}
	if len(out) > MaxBody {
		return nil, fail(CodeTooLarge, "the forwarded body is over %d bytes", MaxBody)
	}
	sum := sha256.Sum256(out)
	r.Body, r.Sha256 = out, hex.EncodeToString(sum[:])
	return r, nil
}

// walk reads body token by token under the strict defaults of jsontext (no
// duplicate names, valid UTF-8), bounds the depth, collects every string and
// writes the compact re-encoding. It returns the re-encoding and its
// top-level members.
func (r *Request) walk(body []byte) ([]byte, map[string]jsontext.Value, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	var buf bytes.Buffer
	buf.Grow(len(body) + 64)
	enc := jsontext.NewEncoder(&buf)
	depth := 0
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, nil, fail(CodeInvalidJSON, "the body is not one strict JSON object")
		}
		switch k := tok.Kind(); {
		case depth == 0 && k != '{':
			return nil, nil, fail(CodeInvalidJSON, "the body must be a JSON object")
		case k == '{' || k == '[':
			if depth++; depth > MaxDepth {
				return nil, nil, fail(CodeInvalidJSON, "the body nests deeper than %d", MaxDepth)
			}
		case k == '}' || k == ']':
			depth--
		case k == '"':
			s := tok.String()
			r.Strings = append(r.Strings, s)
			r.StringBytes += int64(len(s))
		}
		if err := enc.WriteToken(tok); err != nil {
			return nil, nil, fail(CodeInvalidJSON, "the body could not be re-encoded")
		}
		if depth == 0 {
			break
		}
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, nil, fail(CodeInvalidJSON, "the body must be exactly one JSON object")
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	var top map[string]jsontext.Value
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, nil, fail(CodeInvalidJSON, "the body is not one strict JSON object")
	}
	return out, top, nil
}

// extract reads the metadata the decision is made on (D813).
func (r *Request) extract(top map[string]jsontext.Value) error {
	model, ok := top["model"]
	if !ok {
		return fail(CodeInvalidRequest, "model is required")
	}
	if model.Kind() != '"' || json.Unmarshal(model, &r.Model) != nil {
		return fail(CodeInvalidRequest, "model must be a string")
	}
	if err := CheckModelID(r.Model); err != nil {
		return err
	}
	if v, ok := top["stream"]; ok {
		if k := v.Kind(); k != 't' && k != 'f' {
			return fail(CodeInvalidRequest, "stream must be a boolean")
		}
		r.Stream = v.Kind() == 't'
	}
	if err := r.maxTokens(top); err != nil {
		return err
	}
	if r.API == OpenAIChat {
		if v, ok := top["n"]; ok {
			n, err := integer("n", v, 1, MaxChoices)
			if err != nil {
				return err
			}
			r.Choices = n
		}
	}
	return r.serverTools(top)
}

// maxTokens reads the API's max-tokens field; 0 when absent. Chat
// Completions also takes the legacy max_tokens: both present and different
// is refused (D813).
func (r *Request) maxTokens(top map[string]jsontext.Value) error {
	field := r.API.MaxTokensField()
	if field == "" {
		return nil
	}
	var got []int64
	names := []string{field}
	if r.API == OpenAIChat {
		names = append(names, "max_tokens")
	}
	for _, name := range names {
		if v, ok := top[name]; ok {
			n, err := integer(name, v, 1, MaxTokens)
			if err != nil {
				return err
			}
			got = append(got, n)
		}
	}
	switch {
	case len(got) == 2 && got[0] != got[1]:
		return fail(CodeInvalidRequest, "max_completion_tokens and max_tokens differ")
	case len(got) > 0:
		r.MaxTokens = got[0]
	}
	return nil
}

// integer reads a JSON integer written as digits only, within lo..hi.
func integer(name string, v jsontext.Value, lo, hi int64) (int64, error) {
	if v.Kind() != '0' {
		return 0, fail(CodeInvalidRequest, "%s must be an integer", name)
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil || n < lo || n > hi {
		return 0, fail(CodeInvalidRequest, "%s must be an integer in %d..%d", name, lo, hi)
	}
	return n, nil
}

// Client-run tools (D813): a tool of one of these types (or prefixes) runs
// in the agent, so it is not a provider-side tool.
var (
	anthropicClientPrefixes = []string{"computer_", "text_editor_", "bash_", "memory_"}
	chatClientTypes         = []string{"function", "custom"}
	responsesClientTypes    = []string{"function", "custom", "local_shell", "computer_use_preview"}
)

// serverTools classifies the provider-side tools a request names (D813,
// FQ-B, HR-696). An unknown tool type counts as provider-side.
func (r *Request) serverTools(top map[string]jsontext.Value) error {
	names := map[string]bool{}
	if v, ok := top["tools"]; ok && v.Kind() != 'n' {
		var tools []map[string]jsontext.Value
		if err := json.Unmarshal(v, &tools); err != nil {
			return fail(CodeInvalidRequest, "tools must be an array of objects")
		}
		for _, t := range tools {
			typ, set := t["type"]
			var name string
			if set && typ.Kind() != 'n' {
				if typ.Kind() != '"' || json.Unmarshal(typ, &name) != nil || name == "" {
					return fail(CodeInvalidRequest, "a tool's type must be a non-empty string")
				}
			} else if !r.API.Anthropic() {
				return fail(CodeInvalidRequest, "a tool needs a type")
			}
			if r.providerSide(name, set && typ.Kind() != 'n') {
				names[name] = true
			}
		}
	}
	present := func(name string) bool { v, ok := top[name]; return ok && v.Kind() != 'n' }
	switch {
	case r.API.Anthropic():
		if v, ok := top["mcp_servers"]; ok && v.Kind() != 'n' {
			var servers []jsontext.Value
			if err := json.Unmarshal(v, &servers); err != nil {
				return fail(CodeInvalidRequest, "mcp_servers must be an array")
			}
			if len(servers) > 0 {
				names["mcp_servers"] = true
			}
		}
		if present("container") {
			names["container"] = true
		}
	case r.API == OpenAIChat:
		if present("web_search_options") {
			names["web_search_options"] = true
		}
	case r.API == OpenAIResponses:
		if v, ok := top["background"]; ok {
			if k := v.Kind(); k != 't' && k != 'f' && k != 'n' {
				return fail(CodeInvalidRequest, "background must be a boolean")
			}
			if v.Kind() == 't' {
				names["background"] = true
			}
		}
	}
	r.ServerTools = make([]string, 0, len(names))
	for n := range names {
		r.ServerTools = append(r.ServerTools, n)
	}
	slices.Sort(r.ServerTools)
	return nil
}

// providerSide reports whether a tool of type name (set: the tool has a
// type) runs on the provider's servers. An Anthropic tool without a type is
// a custom (client) tool; an OpenAI tool always has one.
func (r *Request) providerSide(name string, set bool) bool {
	switch {
	case r.API.Anthropic():
		if !set || name == "custom" {
			return false
		}
		return !slices.ContainsFunc(anthropicClientPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
	case r.API == OpenAIChat:
		return !set || !slices.Contains(chatClientTypes, name)
	default:
		return !set || !slices.Contains(responsesClientTypes, name)
	}
}
