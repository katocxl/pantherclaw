// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/modelapi"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func modelConn(allowed ...string) *control.Connection {
	return &control.Connection{GatewayConnection: &pb.GatewayConnection{
		Id: "01920000-0000-7000-8000-0000000000c1", Kind: KindModel, Model: &pb.ModelConfig{AllowedServerTools: allowed},
	}}
}

// TestHR756_ComputerUseNeedsItsAllowance: a request declaring a client-run
// computer tool (ServerTools computer_use) on a connection whose
// allowed_server_tools lacks computer_use is refused before anything is
// asked or sent (MODEL_COMPUTER_USE_NOT_ALLOWED) and reported as a local
// refusal; with another server tool refused too, the computer-use code
// still names the reason.
func TestHR756_ComputerUseNeedsItsAllowance(t *testing.T) {
	for name, tc := range map[string]struct {
		tools, allowed []string
		code           string
	}{
		"computer use":                {[]string{modelapi.ComputerUse}, nil, CodeComputerUseNotAllowed},
		"computer use and web":        {[]string{modelapi.ComputerUse, "web_search_20250305"}, []string{"web_search_20250305"}, CodeComputerUseNotAllowed},
		"both refused":                {[]string{modelapi.ComputerUse, "web_search_20250305"}, nil, CodeComputerUseNotAllowed},
		"another server tool":         {[]string{"web_search_20250305"}, []string{modelapi.ComputerUse}, CodeServerToolNotAllowed},
		"allowed a different spell":   {[]string{modelapi.ComputerUse}, []string{"computer"}, CodeComputerUseNotAllowed},
		"allowed the provider's tool": {[]string{modelapi.ComputerUse}, []string{"computer_20250124"}, CodeComputerUseNotAllowed},
	} {
		var refused []string
		e := &Engine{log: pclog.Discard(), localRefusals: func(_ context.Context, _, code, _, _ string, _ RefusalDetail) error {
			refused = append(refused, code)
			return nil
		}}
		r := e.dispatchModel(context.Background(), ModelCall{
			Connection: modelConn(tc.allowed...),
			Action:     actionir.Parsed{Action: actionir.ActionIR{Operation: "model.messages.create"}},
			Request:    &modelapi.Request{API: modelapi.AnthropicMessages, ServerTools: tc.tools},
		}, &timer{})
		if r.Class != CannotAuthorize || r.Code != tc.code || r.Decision != pb.Decision_DECISION_CANNOT_AUTHORIZE ||
			len(refused) != 1 || refused[0] != localModelServerTool {
			t.Errorf("%s: %+v, refusals %v", name, r, refused)
		}
	}
}

// TestHR756_AllowedComputerUsePassesTheGate: with computer_use in
// allowed_server_tools nothing is left for the gate to refuse.
func TestHR756_AllowedComputerUsePassesTheGate(t *testing.T) {
	for _, tc := range [][2][]string{
		{{modelapi.ComputerUse}, {modelapi.ComputerUse}},
		{{modelapi.ComputerUse, "web_search_20250305"}, {"web_search_20250305", modelapi.ComputerUse}},
		{nil, nil},
	} {
		if got := notAllowed(tc[0], tc[1]); len(got) != 0 {
			t.Errorf("notAllowed(%v, %v) = %v", tc[0], tc[1], got)
		}
	}
}
