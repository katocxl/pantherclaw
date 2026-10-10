// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m5Templates are the approval and waitlist notification types (G0 M5
// part 2, HR-173). Like every template they render only ids, fixed codes
// and times (HR-158): never parameter values, amounts, notes or agent text.
// An approval notice links to the authenticated approval page of its
// request, where the decision is made; a message never decides anything.
var m5Templates = []Template{
	{
		Type: "approval.requested", Severity: Warning, Params: []string{"operation", "agent", "deadline", "request"},
		Title: "A decision is waiting for you in PantherClaw",
		Body: "An approval request for {operation} by the agent {agent} is waiting for a decision before {deadline}. " +
			"Open the approval page to see exactly what would happen, and decide there.",
		Link: "/approvals/{request}",
	},
	{
		Type: "approval.reminder", Severity: Warning, Params: []string{"operation", "agent", "deadline", "request"},
		Title: "Reminder: a decision is still waiting in PantherClaw",
		Body: "The approval request for {operation} by the agent {agent} is still waiting. If no one decides before " +
			"{deadline}, the action is denied.",
		Link: "/approvals/{request}",
	},
	{
		Type: "approval.escalated", Severity: Warning, Params: []string{"operation", "agent", "deadline", "request"},
		Title: "A waiting decision was escalated to you",
		Body: "The approval request for {operation} by the agent {agent} has no decision yet and now reaches more people. " +
			"If no one decides before {deadline}, the action is denied.",
		Link: "/approvals/{request}",
	},
	{
		Type: "approval.decided", Severity: Info, Params: []string{"operation", "agent", "outcome", "request"},
		Title: "An approval request was decided",
		Body:  "The approval request for {operation} by the agent {agent} was decided: {outcome}.",
		Link:  "/approvals/{request}",
	},
	{
		Type: "approval.expired", Severity: Info, Params: []string{"operation", "agent", "request"},
		Title: "An approval request expired",
		Body:  "No one decided the approval request for {operation} by the agent {agent} in time, so the action was denied.",
		Link:  "/approvals/{request}",
	},
	{
		Type: "approval.invalidated", Severity: Info, Params: []string{"operation", "agent", "reason", "request"},
		Title: "An approval request no longer applies",
		Body: "The approval request for {operation} by the agent {agent} no longer applies ({reason}). " +
			"The action has to be decided again.",
		Link: "/approvals/{request}",
	},
	{
		Type: "approval.unroutable", Severity: Critical, Params: []string{"operation", "agent", "deadline", "request"},
		Title: "No one can decide a waiting approval request",
		Body: "No eligible person can decide the approval request for {operation} by the agent {agent}. Bind a role that " +
			"decides it where the agent lives, or the action is denied at {deadline}.",
		Link: "/approvals/{request}",
	},
	{
		Type: "approval.multi_person_completed", Severity: Warning, Params: []string{"operation", "agent", "request"},
		Title: "A multi-person approval was completed",
		Body: "Every required person signed the approval request for {operation} by the agent {agent}. " +
			"Review it if you did not expect it.",
		Link: "/approvals/{request}",
	},
	{
		Type: "security.variant_suspected", Severity: Warning, Params: []string{"operation", "agent", "count", "request"},
		Title: "An agent keeps changing a held action",
		Body: "The agent {agent} asked {count} times within 24 hours for {operation} on the same target with different " +
			"details. Look for an agent trying variants until one gets through.",
		Link: "/approvals/{request}",
	},
	{
		Type: "waitlist.entry_created", Severity: Info, Params: []string{"kind", "deadline"},
		Title: "A decision is waiting in the PantherClaw Agent Waitlist",
		Body:  "A {kind} entry is waiting for a decision before {deadline}.",
	},
	{
		Type: "waitlist.entry_escalated", Severity: Warning, Params: []string{"kind", "deadline"},
		Title: "A waiting decision in the Agent Waitlist was escalated",
		Body:  "A {kind} entry still has no decision and now reaches more people. It ends at {deadline} if no one decides.",
	},
}

func init() { templates = append(templates, m5Templates...) }
