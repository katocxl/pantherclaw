// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package builtin names the tools the Claude Agent SDK has built in: exactly
// the "builtins" of sdk/conformance/sdk_face.json, which track S takes from
// the SDK the integration supports, so the face and every SDK classify a name
// alike. It imports nothing, so the supply-chain checks and pclaw can read the
// list without the gateway (G0 M24 D210).
package builtin

import (
	"maps"
	"slices"
)

var names = map[string]bool{
	"Agent": true, "AskUserQuestion": true, "Bash": true, "CronCreate": true, "CronDelete": true, "CronList": true,
	"Edit": true, "EnterPlanMode": true, "EnterWorktree": true, "ExitPlanMode": true, "ExitWorktree": true, "Glob": true,
	"Grep": true, "ListMcpResourcesTool": true, "LSP": true, "Monitor": true, "NotebookEdit": true, "PowerShell": true,
	"Read": true, "ReadMcpResourceTool": true, "Skill": true, "Task": true, "TaskCreate": true, "TaskGet": true,
	"TaskList": true, "TaskOutput": true, "TaskStop": true, "TaskUpdate": true, "TodoWrite": true, "ToolSearch": true,
	"WaitForMcpServers": true, "WebFetch": true, "WebSearch": true, "Write": true,
}

// Set returns the names as a set the caller owns.
func Set() map[string]bool { return maps.Clone(names) }

// Names lists the built-in tools, sorted. An MCP tool with one of these names
// shadows it (D210).
func Names() []string { return slices.Sorted(maps.Keys(names)) }
