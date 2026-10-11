// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubscan

import (
	"maps"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gateway/githubfacts"
)

// agentActions are the actions known to run a coding agent in a workflow.
// A workflow that uses one is an agent route M9 should cover.
var agentActions = []string{
	"anthropics/claude-code-action", "anthropics/claude-code-base-action",
	"openai/codex-action",
	"google-github-actions/run-gemini-cli",
	"github/copilot-swe-agent",
}

// Workflow is what a scan keeps of a workflow file: the agent actions its
// steps use and the permissions it grants. Never inputs, env, run
// commands or secrets (HR-209).
type Workflow struct {
	// Actions are the agent actions, as owner/repo without a ref.
	Actions []string
	// Permissions are the scopes it grants, as scope:level, or
	// write-all / read-all.
	Permissions []string
}

// ParseWorkflow reads a workflow file with the bounded parser of the
// deploy-trigger facts (the M4 YAML restrictions, HR-100).
func ParseWorkflow(raw []byte) (Workflow, error) {
	doc, err := githubfacts.ParseWorkflowYAML(raw)
	if err != nil {
		return Workflow{}, err
	}
	root, _ := doc.(map[string]any)
	actions, perms := map[string]bool{}, map[string]bool{}
	permissions(root["permissions"], perms)
	jobs, _ := root["jobs"].(map[string]any)
	for _, j := range jobs {
		job, _ := j.(map[string]any)
		permissions(job["permissions"], perms)
		steps, _ := job["steps"].([]any)
		for _, s := range steps {
			step, _ := s.(map[string]any)
			uses, _ := step["uses"].(string)
			ref, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(uses)), "@")
			if slices.Contains(agentActions, ref) {
				actions[ref] = true
			}
		}
	}
	return Workflow{Actions: slices.Sorted(maps.Keys(actions)), Permissions: slices.Sorted(maps.Keys(perms))}, nil
}

func permissions(v any, into map[string]bool) {
	switch p := v.(type) {
	case string:
		if p == "write-all" || p == "read-all" {
			into[p] = true
		}
	case map[string]any:
		for scope, level := range p {
			if l, ok := level.(string); ok && (l == "read" || l == "write" || l == "none") {
				into[clip(scope)+":"+l] = true
			}
		}
	}
}
