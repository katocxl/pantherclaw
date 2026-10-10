// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// retentionTemplates are the retention notification types (G0 M7 design
// decision 9, HR-198), sent to the org's admins and auditors. Reasons
// people write stay in the audit ledger and the hold; the messages carry
// only codes, numbers, ids and times.
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
}

func init() { templates = append(templates, retentionTemplates...) }
