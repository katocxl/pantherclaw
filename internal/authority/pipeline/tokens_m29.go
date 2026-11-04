// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// ModelTokens are the tokens a model call reserves against token rules (G0
// M29 D813, D821, HR-693), computed by the authority from the action's own
// params, never taken from a separate number: max_tokens times choices (1
// unless the API takes several) plus a third of input_bytes, rounded up.
// Only the create operations reserve; counting tokens and reading models
// reserve none, and every other action is 0.
func ModelTokens(def *defs.Definition, vals defs.Values) int64 {
	if def == nil || !def.IsModel() {
		return 0
	}
	switch def.Dispatch.Model.API {
	case defs.ModelAPIAnthropicMessages, defs.ModelAPIOpenAIChat, defs.ModelAPIOpenAIResponses:
	default:
		return 0
	}
	choices := int64(1)
	if v, ok := vals["choices"]; ok && v.Type == defs.TypeInteger {
		choices = v.Int
	}
	return gdomain.ReservedTokens(vals["max_tokens"].Int, choices, vals["input_bytes"].Int)
}
