// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m11EngineTemplates are the governed-automation execution notices (G0 M11
// part 2 D25): gates, which are approval requests an automation asks for,
// and an automation's notify step. Like every template they render only
// ids, fixed codes and times (HR-158): a notify step's title and body, which
// may carry trigger parameters, are shown only on the authenticated
// execution page the notice links to. A message never decides anything.
var m11EngineTemplates = []Template{
	{
		Type: "automation.gate_requested", Severity: Warning, Params: []string{"automation", "step", "deadline", "request"},
		Title: "An automation waits for your approval in PantherClaw",
		Body: "The automation {automation} waits at its gate {step} for an approval before {deadline}. " +
			"Open the approval page to see the parameters it would continue with, and decide there.",
		Link: "/approvals/{request}",
	},
	{
		Type: "automation.gate_reminder", Severity: Warning, Params: []string{"automation", "step", "deadline", "request"},
		Title: "Reminder: an automation still waits for an approval",
		Body: "The automation {automation} still waits at its gate {step}. If no one decides before {deadline}, " +
			"the gate fails and the execution stops.",
		Link: "/approvals/{request}",
	},
	{
		Type: "automation.gate_escalated", Severity: Warning, Params: []string{"automation", "step", "deadline", "request"},
		Title: "A waiting automation gate was escalated to you",
		Body: "The automation {automation} waits at its gate {step} with no decision yet, and the request now reaches " +
			"more people. If no one decides before {deadline}, the gate fails.",
		Link: "/approvals/{request}",
	},
	{
		Type: "automation.gate_decided", Severity: Info, Params: []string{"automation", "step", "outcome", "request"},
		Title: "An automation gate was decided",
		Body:  "The gate {step} of the automation {automation} was decided: {outcome}.",
		Link:  "/approvals/{request}",
	},
	{
		Type: "automation.gate_expired", Severity: Info, Params: []string{"automation", "step", "request"},
		Title: "An automation gate expired",
		Body:  "No one decided the gate {step} of the automation {automation} in time, so its execution stopped.",
		Link:  "/approvals/{request}",
	},
	{
		Type: "automation.gate_invalidated", Severity: Info, Params: []string{"automation", "step", "reason", "request"},
		Title: "An automation gate no longer applies",
		Body:  "The gate {step} of the automation {automation} no longer applies ({reason}).",
		Link:  "/approvals/{request}",
	},
	{
		Type: "automation.gate_unroutable", Severity: Critical, Params: []string{"automation", "step", "deadline", "request"},
		Title: "No one can decide a waiting automation gate",
		Body: "No eligible person can decide the gate {step} of the automation {automation}. Bind a role that decides " +
			"automation gates at the organization, or the gate fails at {deadline}.",
		Link: "/approvals/{request}",
	},
	{
		Type: "automation.gate_multi_person_completed", Severity: Warning, Params: []string{"automation", "step", "request"},
		Title: "A two-person automation gate was signed",
		Body:  "Every required person signed the gate {step} of the automation {automation}. Review it if you did not expect it.",
		Link:  "/approvals/{request}",
	},
	{
		Type: "automation.notice", Severity: Info, Params: []string{"automation", "step", "execution"},
		Title: "A message from an automation in PantherClaw",
		Body:  "The automation {automation} sent a notice from its step {step}. Open the execution to read it.",
		Link:  "/automations/executions/{execution}",
	},
	{
		Type: "automation.notice_shadow", Severity: Info, Params: []string{"automation", "step", "execution"},
		Title: "[SHADOW] An automation would send a message",
		Body: "The automation {automation} runs in shadow: its step {step} would send a notice. Nothing was sent to " +
			"anyone else. Open the execution to read it.",
		Link: "/automations/executions/{execution}",
	},
}

func init() { templates = append(templates, m11EngineTemplates...) }
