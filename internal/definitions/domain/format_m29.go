// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"slices"
)

// ModelDispatch is a call of a model provider's API over a model connection
// (G0 M29 D813, HR-691). It has no body template: the gateway strictly
// parses the agent's request, decides on its metadata and the hash of the
// re-encoded body, and forwards exactly that body to the connection's base
// URL plus Path. Its mappings name the channel http, a method and the path
// below the connection's base URL path, and extract nothing: the action's
// params come from internal/modelapi.
type ModelDispatch struct {
	// API is which provider API the body is, one of ModelAPIs.
	API string `json:"api"`
	// Path is the operation's fixed suffix after the connection's base URL
	// (ModelAPIPaths[API]); a read of one model appends /{id}.
	Path string `json:"path"`
}

// Model APIs (D813).
const (
	ModelAPIAnthropicMessages    = "anthropic.messages"
	ModelAPIAnthropicCountTokens = "anthropic.count_tokens" //nolint:gosec // G101: an API name, not a credential
	ModelAPIAnthropicModels      = "anthropic.models"
	ModelAPIOpenAIChat           = "openai.chat"
	ModelAPIOpenAIResponses      = "openai.responses"
	ModelAPIOpenAIModels         = "openai.models"
)

// ModelAPIPaths are each model API's fixed suffix (D813).
var ModelAPIPaths = map[string]string{
	ModelAPIAnthropicMessages:    "/messages",
	ModelAPIAnthropicCountTokens: "/messages/count_tokens",
	ModelAPIAnthropicModels:      "/models",
	ModelAPIOpenAIChat:           "/chat/completions",
	ModelAPIOpenAIResponses:      "/responses",
	ModelAPIOpenAIModels:         "/models",
}

// ModelReadAPI reports whether api lists or reads models: a read, with no
// body, that reserves no tokens.
func ModelReadAPI(api string) bool {
	return api == ModelAPIAnthropicModels || api == ModelAPIOpenAIModels
}

// IsModel reports whether d is a model operation: its dispatch is a model
// call (D813).
func (d *Definition) IsModel() bool { return d.Dispatch != nil && d.Dispatch.Model != nil }

// validateModelDispatch checks a model dispatch: a known API, its fixed
// path, and the access its API has (models are read; the rest write).
func (d *Definition) validateModelDispatch(at string, m *ModelDispatch) error {
	want, ok := ModelAPIPaths[m.API]
	if !ok {
		return invalid("%s.model: api one of %v", at, slices.Sorted(maps.Keys(ModelAPIPaths)))
	}
	if m.Path != want {
		return invalid("%s.model: the %s path is %s", at, m.API, want)
	}
	if ModelReadAPI(m.API) != (d.Access == AccessRead) {
		return invalid("%s.model: %s is a %s", at, m.API, map[bool]string{true: "read", false: "write"}[ModelReadAPI(m.API)])
	}
	if d.Test {
		return invalid("%s.model: a model operation is never a connection test", at)
	}
	return nil
}

// validateModelMapping checks a model operation's mapping (D813): channel
// http with a method and path, no encoding or headers, and nothing to
// extract.
func (d *Definition) validateModelMapping(at string, m Mapping) error {
	x := m.Extract
	if m.Channel != ChannelHTTP {
		return invalid("%s: a model operation maps only the http channel", at)
	}
	if x.TargetID != "" || x.TargetAccount != "" || len(x.Params) > 0 || len(x.Destinations) > 0 {
		return invalid("%s: a model operation extracts nothing; its params come from the model API parser", at)
	}
	return nil
}
