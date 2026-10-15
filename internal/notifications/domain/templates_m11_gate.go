// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m11GateTemplates are the policy change notification types (G0 M11.1
// design decision 11, HR-231). Like every template they render only ids
// and fixed text (HR-158) and link to the authenticated change page;
// nothing in a message confirms, declines or changes anything.
var m11GateTemplates = []Template{
	{
		Type: "policy.change_requested", Severity: Warning, Params: []string{"request", "kind", "user"},
		Title: "A PantherClaw policy change waits for your confirmation",
		Body: "{user} asked for a policy change ({kind}) that loosens what the organization enforces. It takes effect only " +
			"after people who publish policies confirm it with a security key on its page within 24 hours.",
		Link: "/policy-changes/{request}",
	},
}

func init() { templates = append(templates, m11GateTemplates...) }
