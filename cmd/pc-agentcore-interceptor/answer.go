// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"time"
)

// The interceptor's limits (D994, D995).
const (
	// maxEvent is the largest interceptor event the gateway's face takes.
	maxEvent = 1 << 20
	// maxDecision bounds one decision; the Lambda's own deadline less
	// deadlineMargin bounds it further.
	maxDecision    = 8 * time.Second
	deadlineMargin = 500 * time.Millisecond
	// cannotDecide is what a tool call PantherClaw cannot decide answers
	// (D995).
	cannotDecide = "PantherClaw cannot decide this tool call, so it does not run"
	// outputVersion is the interceptor output's version.
	outputVersion = "1.0"
)

// eventID is the JSON-RPC id of the event's MCP request, or null when the
// event carries none the interceptor can read.
func eventID(event []byte) jsontext.Value {
	var ev struct {
		MCP struct {
			GatewayRequest struct {
				Body jsontext.Value `json:"body"`
			} `json:"gatewayRequest"`
		} `json:"mcp"`
	}
	if json.Unmarshal(event, &ev) != nil || len(ev.MCP.GatewayRequest.Body) == 0 {
		return jsontext.Value("null")
	}
	var body struct {
		ID jsontext.Value `json:"id"`
	}
	if json.Unmarshal(ev.MCP.GatewayRequest.Body, &body) != nil || len(body.ID) == 0 {
		return jsontext.Value("null")
	}
	if k := body.ID.Kind(); k == jsontext.KindString || k == jsontext.KindNumber {
		return body.ID
	}
	return jsontext.Value("null")
}

// denyOutput is the interceptor output that answers the MCP request with a
// tool error and never reaches the target (D994's deny shape, D995).
func denyOutput(id jsontext.Value, text string) []byte {
	type content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type result struct {
		IsError bool      `json:"isError"`
		Content []content `json:"content"`
	}
	type rpc struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      jsontext.Value `json:"id"`
		Result  result         `json:"result"`
	}
	type response struct {
		StatusCode int `json:"statusCode"`
		Body       rpc `json:"body"`
	}
	type mcp struct {
		TransformedGatewayResponse response `json:"transformedGatewayResponse"`
	}
	out := struct {
		Version string `json:"interceptorOutputVersion"`
		MCP     mcp    `json:"mcp"`
	}{
		Version: outputVersion,
		MCP: mcp{TransformedGatewayResponse: response{StatusCode: 200, Body: rpc{
			JSONRPC: "2.0", ID: id, Result: result{IsError: true, Content: []content{{Type: "text", Text: text}}},
		}}},
	}
	b, err := json.Marshal(out)
	if err != nil {
		// Unreachable: every value above marshals. A fixed deny keeps it closed.
		return []byte(`{"interceptorOutputVersion":"1.0","mcp":{"transformedGatewayResponse":{"statusCode":200,"body":{"jsonrpc":"2.0","id":null,"result":{"isError":true,"content":[{"type":"text","text":"` + cannotDecide + `"}]}}}}}`)
	}
	return b
}

// answer is the interceptor output for one event: the gateway's, or a deny
// on any error (fail closed, HR-766). It never logs the event.
func (ic *interceptor) answer(ctx context.Context, gatewayARN string, event []byte, deadline time.Time) []byte {
	if len(event) > maxEvent {
		ic.log.Warn("interceptor.denied", "reason", "event_too_large")
		return denyOutput(jsontext.Value("null"), cannotDecide)
	}
	limit := time.Now().Add(maxDecision)
	if d := deadline.Add(-deadlineMargin); !deadline.IsZero() && d.Before(limit) {
		limit = d
	}
	dctx, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	out, err := ic.decide(dctx, gatewayARN, event)
	if err != nil {
		ic.log.Warn("interceptor.denied", "reason", err.Error())
		return denyOutput(eventID(event), cannotDecide)
	}
	return out
}
