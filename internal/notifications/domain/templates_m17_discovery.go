// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// discoveryTemplates are continuous discovery's notification types (G0 M17,
// PN-001.3, D114, D116). They go to a claimed agent's owners, or to the org
// admins for an unclaimed discovery. A vanished discovery is only announced:
// the agent keeps its state and authority (HR-458). They render ids, kinds
// and counts only, never an observed (untrusted) value (HR-158).
var discoveryTemplates = []Template{
	{
		Type: "agent.discovery_vanished", Severity: Warning, Params: []string{"agent", "kind", "discovery", "scans"},
		Title: "A discovered agent was not seen in recent scans",
		Body: "The {kind} discovery {discovery} of agent {agent} was missed by the last {scans} complete scans. PantherClaw " +
			"changed nothing: the agent keeps its state and authority. Check whether it was removed or moved, and retire " +
			"the agent if it is gone.",
		Link: "/agents",
	},
	// A material change of an open or claimed discovery (HR-460): only the
	// names of the changed keys; their values are in the agent's history.
	{
		Type: "agent.discovery_changed", Severity: Warning, Params: []string{"agent", "kind", "discovery", "keys"},
		Title: "A discovered agent changed what it may do",
		Body: "A scan saw the {kind} discovery {discovery} of agent {agent} change: {keys}. PantherClaw changed nothing; " +
			"the before and after values are in the agent's history. Review whether the agent still needs what it now " +
			"declares.",
		Link: "/agents",
	},
}

func init() { templates = append(templates, discoveryTemplates...) }
