// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// modelTemplates tell an org's admins that model drafting's data boundary
// changed (G0 M21 D309). The message carries the change and who made it,
// never the key.
var modelTemplates = []Template{
	{
		Type: "security.model_drafting_changed", Severity: Warning, Params: []string{"change", "user"},
		Title: "Model drafting changed in PantherClaw",
		Body: "User {user} made this change to model drafting: {change}. People's drafting text now goes to, or may go to, " +
			"your organization's model provider under your own key. Records are never sent. Any org admin can turn it off " +
			"at any time, without a security key. Every call is in the audit log.",
	},
}

func init() { templates = append(templates, modelTemplates...) }
