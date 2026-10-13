// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubscan

import (
	"errors"
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
// steps use, the permissions it grants and the environments it deploys to.
// Never inputs, env, run commands or secrets (HR-209).
type Workflow struct {
	// Actions are the agent actions, as owner/repo without a ref.
	Actions []string
	// Permissions are the scopes it grants, as scope:level, or write-all /
	// read-all, the ones that may write first.
	Permissions []string
	// DefaultPermissions is set when the workflow or one of its jobs sets
	// no permissions: it runs with the repository's default token
	// permissions, which may write.
	DefaultPermissions bool
	// Environments are the environments its jobs deploy to, "(expression)"
	// for one an expression chooses.
	Environments []string
}

// Writes reports whether the workflow's token may write: a write
// permission, write-all, or the repository's defaults.
func (w Workflow) Writes() bool {
	return w.DefaultPermissions || slices.ContainsFunc(w.Permissions, func(p string) bool {
		return p == "write-all" || strings.HasSuffix(p, ":write")
	})
}

// ParseWorkflow reads a workflow file with the bounded parser of the
// deploy-trigger facts (the M4 YAML restrictions, HR-100).
func ParseWorkflow(raw []byte) (Workflow, error) {
	if len(raw) > githubfacts.MaxWorkflowBytes {
		return Workflow{}, errors.New("githubscan: workflow file too large")
	}
	doc, err := githubfacts.ParseWorkflowYAML(raw)
	if err != nil {
		return Workflow{}, err
	}
	root, _ := doc.(map[string]any)
	actions, perms, envs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	_, workflowPerms := root["permissions"]
	permissions(root["permissions"], perms)
	var w Workflow
	jobs, _ := root["jobs"].(map[string]any)
	for _, j := range jobs {
		job, _ := j.(map[string]any)
		if _, set := job["permissions"]; !set && !workflowPerms {
			w.DefaultPermissions = true
		}
		permissions(job["permissions"], perms)
		switch env := job["environment"].(type) {
		case string:
			envs[environmentName(env)] = true
		case map[string]any:
			if name, ok := env["name"].(string); ok {
				envs[environmentName(name)] = true
			}
		}
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
	w.Actions = slices.Sorted(maps.Keys(actions))
	w.Permissions = slices.SortedFunc(maps.Keys(perms), func(a, b string) int {
		if c := permissionRank(a) - permissionRank(b); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	w.Environments = slices.Sorted(maps.Keys(envs))
	return w, nil
}

// permissionRank orders permissions most dangerous first, so a list cut
// to fit an attribute keeps the ones that may write.
func permissionRank(p string) int {
	switch {
	case p == "write-all":
		return 0
	case strings.HasSuffix(p, ":write"):
		return 1
	case p == "read-all":
		return 2
	case strings.HasSuffix(p, ":read"):
		return 3
	}
	return 4
}

// environmentName is an environment as a finding names it: "(expression)"
// when an expression chooses it.
func environmentName(s string) string {
	if strings.Contains(s, "${{") {
		return "(expression)"
	}
	return clip(s)
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
