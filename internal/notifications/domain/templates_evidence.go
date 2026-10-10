// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// evidenceTemplates are the evidence-integrity notification types (G0 M7
// design decision 8, HR-194). Like every template they render only codes
// and fixed text (HR-158).
var evidenceTemplates = []Template{
	{
		Type: "security.evidence_integrity_failed", Severity: Critical, Params: []string{"check", "reason"},
		Title: "The PantherClaw evidence ledger failed an integrity check",
		Body: "The {check} of this organization's evidence ledger failed ({reason}): a ledger entry, its chain link, " +
			"a tile or a checkpoint does not match. Checkpoints are stopped until an operator investigates; receipts " +
			"are still written and chained.",
	},
	// The operator's reason is free text: it stays in the audit ledger.
	{
		Type: "security.evidence_integrity_reset", Severity: Warning, Params: []string{"reason"},
		Title: "Checkpoints of the PantherClaw evidence ledger were resumed",
		Body: "An operator cleared the failed integrity status of this organization's evidence ledger (it had failed " +
			"with {reason}), so checkpoints resume. The next checkpoint and the daily verification check the ledger " +
			"again; if it is still broken, it fails again and you are notified again. The operator's reason is in " +
			"the audit log.",
	},
}

func init() { templates = append(templates, evidenceTemplates...) }
