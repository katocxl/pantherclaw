// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// agentSDKSnippets prints, for each Claude Agent SDK project init found,
// how to add PantherClaw's integration (integrations/claude-agent-sdk) to
// its code. init prints it and never writes code (G0 M8 design decision 9).
// The integration takes the /sdk connection for the agent's other tools,
// which init does not know, so that one is left for the developer to fill.
func (f initFlags) agentSDKSnippets(a *app, findings []scan.Finding) {
	key, err := filepath.Abs(f.keyFile)
	if err != nil {
		key = f.keyFile
	}
	gateway := strings.TrimSuffix(f.gateway, "/")
	for _, fd := range findings {
		at := fd.Attributes
		if fd.Kind != scan.KindAgentProject || !slices.Contains(strings.Split(at["frameworks"], ","), "claude-agent-sdk") {
			continue
		}
		_, _ = fmt.Fprintf(a.stdout, "\nClaude Agent SDK project %s: init does not change code. To decide its tool calls, add:\n\n", at["path"])
		q := strconv.Quote
		if at["manifest"] == "package.json" {
			_, _ = fmt.Fprintf(a.stdout, `  import { pantherclaw } from "@pantherclaw/claude-agent-sdk";

  const pc = await pantherclaw({
    gateway: %s,
    keyFile: %s,
    shellConnection: %s,
    connection: "<the /sdk connection for its other tools>",
  });
  // query({ prompt, options: { ...options, hooks: pc.hooks, canUseTool: pc.canUseTool } })

`, q(gateway), q(key), q(f.connection))
			continue
		}
		_, _ = fmt.Fprintf(a.stdout, `  from pantherclaw_claude_agent_sdk import pantherclaw

  pc = await pantherclaw(
      gateway=%s,
      key_file=%s,
      shell_connection=%s,
      connection="<the /sdk connection for its other tools>",
  )
  # ClaudeAgentOptions(..., hooks=pc.hooks, can_use_tool=pc.can_use_tool)

`, q(gateway), q(key), q(f.connection))
	}
}
