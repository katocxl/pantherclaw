// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/modelapi"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// A Bedrock Converse call carrying a Bedrock system tool is refused by
// M29's provider-side tool gate, before anything is decided or sent, unless
// the connection allows that tool type (HR-727, HR-696, T-334).
//
// Covers: HR-727
func TestHR727_ABedrockSystemToolIsRefusedLikeAModelCallsServerTool(t *testing.T) {
	req, err := modelapi.ParsePath(modelapi.BedrockConverse, "anthropic.claude-sonnet-4-5-v1:0",
		[]byte(`{"messages":[],"toolConfig":{"tools":[{"systemTool":{"name":"web_grounding"}}]}}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{log: pclog.Discard()}
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c", Model: &pb.ModelConfig{AllowedServerTools: []string{"web_search_20250305"}}}}
	call := ModelCall{
		Connection: conn, Request: req,
		Action: actionir.Parsed{Action: actionir.ActionIR{Operation: "bedrock.converse.create", Target: actionir.Target{Type: "model", ID: req.Model}}},
	}
	if r := e.DispatchModel(t.Context(), call); r.Class != CannotAuthorize || r.Code != CodeServerToolNotAllowed ||
		r.Decision != pb.Decision_DECISION_CANNOT_AUTHORIZE {
		t.Fatalf("a Bedrock system tool: %+v", r)
	}
	if got := notAllowed(req.ServerTools, []string{"systemTool"}); len(got) != 0 {
		t.Fatalf("an allowed system tool is still refused: %v", got)
	}
}
