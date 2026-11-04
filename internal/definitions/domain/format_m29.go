// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"regexp"
	"slices"
	"strings"
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
	// (ModelAPIPaths[API]); a read of one model appends /{id}. An API that
	// names its model in the path (ModelInPath) has {id} in its suffix,
	// where the gateway puts the escaped model id (G0 M31 D961).
	Path string `json:"path"`
	// AWSAction and AWSResource narrow the session a Bedrock call is signed
	// with to one action on one model (G0 M31 D961, HR-525, HR-727): the
	// action, such as InvokeModel, and an ARN template whose references are
	// the target (the model id) and the connection's account, region and
	// partition. A Bedrock API needs both; every other API has neither.
	AWSAction   string `json:"aws_action,omitzero"`
	AWSResource string `json:"aws_resource,omitzero"`
}

// Model APIs (D813; G0 M31 D961 adds Anthropic models on Vertex AI and
// Bedrock Converse).
const (
	ModelAPIAnthropicMessages    = "anthropic.messages"
	ModelAPIAnthropicCountTokens = "anthropic.count_tokens" //nolint:gosec // G101: an API name, not a credential
	ModelAPIAnthropicModels      = "anthropic.models"
	ModelAPIOpenAIChat           = "openai.chat"
	ModelAPIOpenAIResponses      = "openai.responses"
	ModelAPIOpenAIModels         = "openai.models"
	ModelAPIVertexRawPredict     = "vertex.anthropic.raw_predict"
	ModelAPIVertexStream         = "vertex.anthropic.stream_raw_predict"
	ModelAPIBedrockConverse      = "bedrock.converse"
	ModelAPIBedrockStream        = "bedrock.converse_stream"
)

// ModelAPIPaths are each model API's fixed suffix (D813).
var ModelAPIPaths = map[string]string{
	ModelAPIAnthropicMessages:    "/messages",
	ModelAPIAnthropicCountTokens: "/messages/count_tokens",
	ModelAPIAnthropicModels:      "/models",
	ModelAPIOpenAIChat:           "/chat/completions",
	ModelAPIOpenAIResponses:      "/responses",
	ModelAPIOpenAIModels:         "/models",
	ModelAPIVertexRawPredict:     "/{id}:rawPredict",
	ModelAPIVertexStream:         "/{id}:streamRawPredict",
	ModelAPIBedrockConverse:      "/model/{id}/converse",
	ModelAPIBedrockStream:        "/model/{id}/converse-stream",
}

// ModelIDRef is where a model-in-path API's suffix takes the model id.
const ModelIDRef = "{id}"

// ModelInPath reports whether api names its model in the request path, not
// the body (G0 M31 D961).
func ModelInPath(api string) bool { return strings.Contains(ModelAPIPaths[api], ModelIDRef) }

// bedrockAPI reports whether api is a Bedrock API, signed with an AWS
// session (G0 M31 D961).
func bedrockAPI(api string) bool {
	return api == ModelAPIBedrockConverse || api == ModelAPIBedrockStream
}

// modelPathRe is a model mapping path whose last segment names the model
// and an action, such as /{id}:rawPredict (G0 M31 D961): the general path
// grammar takes a variable only as a whole segment.
var modelPathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/\{id\}:[A-Za-z]{1,32}$`)

// modelMappingPath reports whether path is the mapping path of a
// model-in-path API whose suffix ends in {id}:<action>.
func (d *Definition) modelMappingPath(path string) bool {
	return d.IsModel() && ModelInPath(d.Dispatch.Model.API) && modelPathRe.MatchString(path)
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
	if bedrock := bedrockAPI(m.API); (bedrock && (m.AWSAction == "" || m.AWSResource == "")) || (!bedrock && (m.AWSAction != "" || m.AWSResource != "")) {
		return invalid("%s.model: a Bedrock API names aws_action and aws_resource; no other API names either", at)
	}
	if m.AWSAction != "" {
		if !awsModelActionRe.MatchString(m.AWSAction) {
			return invalid("%s.model.aws_action %q", at, m.AWSAction)
		}
		if err := d.validateAWSResource(at+".model", m.AWSResource); err != nil {
			return err
		}
	}
	return nil
}

// awsModelActionRe is an AWS action name, as the broker's session policy
// takes it.
var awsModelActionRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)

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
