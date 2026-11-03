// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// idaccessTemplates tell every org admin about a change to how the org's
// identity provider and standard MCP clients reach its agents (G0 M26
// D400-D402, D408; HR-623): when an addition is filed, when a second person
// applies it, and when something is turned off. Like every template they
// carry ids, codes and fixed text only (HR-158).
var idaccessTemplates = []Template{
	{
		Type: "idaccess.change_requested", Severity: Warning, Params: []string{"request", "change", "user"},
		Title: "A change to how your identity provider reaches agents waits for a second person",
		Body: "{user} asked to add or turn on IdP-native agent access ({change}). It applies only after a different " +
			"admin confirms it with a security key on its page. It creates no access: it can only use or narrow " +
			"grants people already hold. If you did not expect this change, decline it.",
		Link: "/changes/{request}",
	},
	{
		Type: "idaccess.change_applied", Severity: Warning, Params: []string{"change", "user", "publisher"},
		Title: "IdP-native agent access changed",
		Body: "The change ({change}) asked by {user} was confirmed by {publisher} and now applies. " +
			"Every change is in the audit log.",
	},
	{
		Type: "idaccess.removed", Severity: Warning, Params: []string{"change", "user"},
		Title: "IdP-native agent access was turned off",
		Body:  "{user} turned something off ({change}). It applied at once: tokens it covered stop on their next use.",
	},
	{
		Type: "idaccess.refresh_reuse", Severity: Critical, Params: []string{"client", "run"},
		Title: "A reused MCP refresh token was refused",
		Body: "A refresh token of MCP client {client} was used after it had been rotated. Every token of that sign-in " +
			"was revoked and run {run} was ended. A reused token can mean it was stolen.",
	},
	{
		Type: "idaccess.client_document_changed", Severity: Warning, Params: []string{"client"},
		Title: "An allowed MCP client's metadata document changed",
		Body: "MCP client {client} asked to return to an address its metadata document lists now but did not list " +
			"when your organization allowed it. The request was refused. The client keeps only the addresses that were " +
			"confirmed; taking its new document is a new change a second admin must confirm.",
	},
}

func init() { templates = append(templates, idaccessTemplates...) }
