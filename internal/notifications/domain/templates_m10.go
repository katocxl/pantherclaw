// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m10CoreTemplates are Reflex's alert, incident, page and digest types (G0
// M10 D7, D17; F620). Each says what happened (the rule), why it matters
// (the built-in rule's fixed title, or the rule id for a custom rule),
// what containment applies, what exposure remains and what to do next.
// They render rule ids, severities, counts and ids, never agent text
// (HR-158).
var m10CoreTemplates = []Template{
	{
		Type: "reflex.alert", Severity: Warning,
		Params: []string{"rule", "why", "severity", "containment", "exposure", "alert"},
		Title:  "PantherClaw detection {rule} raised an alert",
		Body: "{why} Severity: {severity}. Current containment: {containment}. Remaining exposure: {exposure}. " +
			"Next: open alert {alert}, check its evidence and contain what it names if it is real.",
	},
	{
		Type: "reflex.page", Severity: Critical,
		Params: []string{"rule", "why", "severity", "containment", "exposure", "alert"},
		Title:  "PantherClaw page: {rule}",
		Body: "{why} Severity: {severity}. Current containment: {containment}. Remaining exposure: {exposure}. " +
			"Next: someone looks now; open alert {alert} and its incident.",
	},
	{
		Type: "reflex.incident", Severity: Critical,
		Params: []string{"incident", "why", "severity", "containment", "exposure"},
		Title:  "PantherClaw opened an incident",
		Body: "Incident {incident} was opened: {why} Severity: {severity}. Current containment: {containment}. " +
			"Remaining exposure: {exposure}. Next: assign an owner and decide on containment.",
	},
	{
		Type: "reflex.digest", Severity: Info,
		Params: []string{"day", "decisions", "authority_changes", "alerts"},
		Title:  "PantherClaw daily digest for {day}",
		Body: "On {day}: {decisions} decisions, {authority_changes} authority changes (grants, guardrails, policies) and " +
			"{alerts} new alerts. Open the operations view for details.",
	},
}

func init() { templates = append(templates, m10CoreTemplates...) }
