// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m8Templates are the consequence notification types (G0 M8). Monitor mode
// stays observe-only (HR-184), so an action whose consequence is unknown is
// still dispatched on a monitor-mode route; enforce mode would have held it
// (HR-206, founder decision 2026-10-13), and people hear about it once per
// transaction.
var m8Templates = []Template{
	{
		Type: "security.consequence_unknown_dispatched", Severity: Warning,
		Params: []string{"operation", "consequence", "would", "transaction"},
		Title:  "A monitor-mode route ran an action whose consequence is unknown",
		Body: "{operation} ran on a monitor-mode route although PantherClaw could not rule out its consequence {consequence}. " +
			"On an enforce-mode route the decision would have been {would}. Review transaction {transaction}, and move the " +
			"route to enforce mode before you rely on PantherClaw to stop such actions.",
	},
	// A GitHub link decides whose pull requests a person may review (HR-207,
	// P2f), so every change is announced like other security changes.
	{
		Type: "security.github_identity_linked", Severity: Warning, Params: []string{"user", "github_login", "github_user_id", "by"},
		Title: "A person linked a GitHub account",
		Body: "User {user} signed in to GitHub as {github_login} (GitHub user {github_user_id}) and linked that account to " +
			"themselves. They can no longer review pull requests that account authored, committed or pushed to. If you did not " +
			"expect this, check the account with them.",
	},
	{
		Type: "security.github_identity_unlinked", Severity: Warning, Params: []string{"user", "github_login", "github_user_id", "by"},
		Title: "A GitHub account was unlinked",
		Body: "{by} removed the link between user {user} and the GitHub account {github_login} (GitHub user {github_user_id}). " +
			"Until they link an account again by signing in to GitHub, they cannot review GitHub merges, and requests created " +
			"while they were linked still exclude them.",
	},
	// An exempted account no longer holds up the reviews of pull requests it
	// worked on (founder decision 2026-10-13), so exemptions are announced
	// too.
	{
		Type: "security.github_account_exempted", Severity: Warning, Params: []string{"github_login", "github_user_id", "reason", "by"},
		Title: "A GitHub account was exempted as not a person",
		Body: "{by} registered the GitHub account {github_login} (GitHub user {github_user_id}) as a bot or a machine user: " +
			"{reason}. Reviews of pull requests it worked on no longer wait for it to be linked to someone. If it is a " +
			"person's account, remove the exemption.",
	},
	{
		Type: "security.github_exemption_removed", Severity: Warning, Params: []string{"github_login", "github_user_id", "reason", "by"},
		Title: "A GitHub account's exemption was removed",
		Body: "{by} removed the exemption of the GitHub account {github_login} (GitHub user {github_user_id}), given as " +
			"\"{reason}\". Reviews of pull requests it worked on wait again until it is linked to someone.",
	},
}

func init() { templates = append(templates, m8Templates...) }
