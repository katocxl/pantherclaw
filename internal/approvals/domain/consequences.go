// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/actionir"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
)

// maxShown bounds the environments, workflows and reasons shown for one
// consequence.
const maxShown = 16

// ConsequenceInput is a predicted or unknown consequence of the action, as
// the decision found it (G0 M8, F158, HR-206).
type ConsequenceInput struct {
	Rule, Operation, State string
	Target                 actionir.Target
	Environments, Unknown  []string
	// Facts are the facts the rule read; the workflows behind it come from
	// their workflows member.
	Facts []fdomain.Fact
}

// ConsequenceLine is a predicted or unknown consequence on the approval
// page: a prediction, never an authorized or confirmed effect, with the
// environments and workflows behind it and, when unknown, why.
type ConsequenceLine struct {
	Rule         string          `json:"rule"`
	Operation    string          `json:"operation"`
	Target       actionir.Target `json:"target"`
	State        string          `json:"state"`
	Environments []string        `json:"environments,omitzero"`
	Workflows    []string        `json:"workflows,omitzero"`
	Unknown      []string        `json:"unknown,omitzero"`
}

func consequenceLines(in []ConsequenceInput) []ConsequenceLine {
	var out []ConsequenceLine
	for _, c := range in {
		l := ConsequenceLine{Rule: c.Rule, Operation: c.Operation, Target: c.Target, State: c.State}
		for _, e := range c.Environments[:min(len(c.Environments), maxShown)] {
			l.Environments = append(l.Environments, Clean("", e, 100).Text)
		}
		for _, u := range c.Unknown[:min(len(c.Unknown), maxShown)] {
			l.Unknown = append(l.Unknown, Clean("", u, 256).Text)
		}
		for _, f := range c.Facts {
			for _, w := range workflows(f) {
				if len(l.Workflows) < maxShown && !slices.Contains(l.Workflows, w) {
					l.Workflows = append(l.Workflows, w)
				}
			}
		}
		out = append(out, l)
	}
	return out
}

// workflows are the paths an object fact's workflows member lists
// ([{path, environments}], as github.repo.deploy_triggers has).
func workflows(f fdomain.Fact) []string {
	if f.Value.Type != fdomain.TypeObject {
		return nil
	}
	list, _ := f.Value.Object["workflows"].([]any)
	var out []string
	for _, w := range list {
		if m, ok := w.(map[string]any); ok {
			if p, ok := m["path"].(string); ok && p != "" {
				out = append(out, Clean("", p, 256).Text)
			}
		}
	}
	return out
}
