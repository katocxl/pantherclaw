// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sdk

import (
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
)

// FuzzSDKCall: whatever the body, a call names an MCP tool only as
// mcp__{server}__{tool} with that server, and is observed instead of
// decided only when it is a plain built-in name without a server (HR-200,
// HR-201): an MCP call never slips into OBSERVE_ONLY.
func FuzzSDKCall(f *testing.F) {
	for _, s := range []string{
		`{"tool":"mcp__payments__create_refund","server":"payments","input":{},"tool_use_id":"t1"}`,
		`{"tool":"mcp__git__hub__merge","server":"git__hub","input":{},"tool_use_id":"t1"}`,
		`{"tool":"mcp__payments__","server":"payments","input":{},"tool_use_id":"t1"}`,
		`{"tool":"Read","input":{},"tool_use_id":"t1"}`,
		`{"tool":"Read","server":"payments","input":{},"tool_use_id":"t1"}`,
		`{"tool":"mcp__x","input":{},"tool_use_id":"t1"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var req Request
		if json.Unmarshal(body, &req, json.RejectUnknownMembers(true)) != nil {
			return
		}
		tool, err := mcpTool(req)
		switch {
		case err == nil:
			if tool == "" || req.Server == "" || req.Tool != "mcp__"+req.Server+"__"+tool || !serverRe.MatchString(req.Server) {
				t.Fatalf("%q mapped as MCP tool %q", body, tool)
			}
		case errors.Is(err, errBuiltIn):
			if req.Server != "" || strings.HasPrefix(req.Tool, "mcp__") || !builtinRe.MatchString(req.Tool) {
				t.Fatalf("%q observed as a built-in", body)
			}
		case !errors.Is(err, errShape):
			t.Fatalf("%q: %v", body, err)
		}
	})
}
