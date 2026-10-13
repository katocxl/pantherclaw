// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// retentionTemplates are the retention and capture notification types (G0 M7
// design decisions 9 and 10, HR-198, HR-199), sent to the org's admins and
// auditors. Reasons and purposes people write stay in the audit ledger, the
// hold and the profile; the messages carry only codes, numbers, ids and
// times.
var retentionTemplates = []Template{
	{
		Type: "evidence.retention_shortened", Severity: Warning, Params: []string{"category", "days", "previous_days", "effective"},
		Title: "A PantherClaw retention period was shortened",
		Body: "The retention of {category} evidence was shortened from {previous_days} to {days} days. It takes effect " +
			"at {effective}; bodies older than the new period are then removed. If evidence must be kept, place a " +
			"legal hold before then.",
	},
	{
		Type: "evidence.legal_hold_released", Severity: Warning, Params: []string{"hold", "scope"},
		Title: "A PantherClaw legal hold was released",
		Body: "The legal hold {hold} ({scope}) was released. Retention applies again to the evidence it held: bodies " +
			"past their retention are removed at the next daily run. Who released it and why is in the audit log.",
	},
	// Capture profiles (design decision 10, HR-199): the purpose stays in
	// the profile, never in a message.
	{
		Type: "evidence.capture_profile_created", Severity: Warning, Params: []string{"profile", "connections", "expires"},
		Title: "PantherClaw payload capture was switched on",
		Body: "The capture profile {profile} now captures request or response bodies on {connections} connections until " +
			"{expires}. Captures are sealed and only people with restricted evidence access can read them, and every read " +
			"is audited. Who created it and why is in the capture profile and the audit log.",
	},
	{
		Type: "evidence.capture_profile_disabled", Severity: Info, Params: []string{"profile"},
		Title: "A PantherClaw payload capture profile was disabled",
		Body: "The capture profile {profile} was disabled: nothing more is captured under it. Captures already taken are " +
			"kept until their retention ends.",
	},
}

func init() { templates = append(templates, retentionTemplates...) }
