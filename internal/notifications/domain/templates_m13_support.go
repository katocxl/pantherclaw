// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// supportTemplates tell an org's admins about support access (G0 M13 D32,
// D33): a staff member's request, its decision, a revoked grant, and a
// break-glass activation. The task and reasons people write stay in the
// request and the audit ledger; messages carry codes, numbers, ids and
// times.
var supportTemplates = []Template{
	{
		Type: "support.access_requested", Severity: Warning, Params: []string{"request", "staff", "scope", "hours", "expires"},
		Title: "PantherClaw support asks to access your organization",
		Body: "{staff} of PantherClaw support asks for {scope} access to your organization for {hours} hours. Nothing is " +
			"accessible until an org admin grants it with a security key on the request's page; the request expires " +
			"unanswered at {expires}. The task is on that page.",
		Link: "/support-access/{request}",
	},
	{
		Type: "support.access_approved", Severity: Warning, Params: []string{"request", "grant", "until"},
		Title: "PantherClaw support access was granted",
		Body: "Support access request {request} was granted: grant {grant} lets the requester read your organization " +
			"until {until}. Every call made under it is in your audit log. Any org admin can revoke it at any time.",
		Link: "/support-access/{request}",
	},
	{
		Type: "support.access_denied", Severity: Info, Params: []string{"request"},
		Title: "PantherClaw support access was denied",
		Body:  "Support access request {request} was denied. Who denied it is in the audit log.",
	},
	{
		Type: "support.grant_revoked", Severity: Info, Params: []string{"grant"},
		Title: "PantherClaw support access was revoked",
		Body:  "Support grant {grant} was revoked, and its support sessions ended. Who revoked it is in the audit log.",
	},
	{
		Type: "breakglass.activated", Severity: Critical, Params: []string{"activation", "user", "role", "until"},
		Title: "Break-glass access was activated in PantherClaw",
		Body: "User {user} activated break-glass access {activation}: they hold the {role} role at the organization until " +
			"{until}. Every call they make meanwhile is in the audit log with the activation. Their reason is in the audit " +
			"log; an org admin can end it early.",
	},
}

func init() { templates = append(templates, supportTemplates...) }
