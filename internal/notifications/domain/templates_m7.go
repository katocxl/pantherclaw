// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m7Templates are the effect notification types (G0 M7). An effect without a
// receipt is a finding, not proof of an attack: a person may have used the
// target's own console, so the message only asks for a review (HR-112). An
// unknown outcome's notices link to its reconciliation page, the only
// place where a person releases it (design decision 3); a message never
// resolves anything.
var m7Templates = []Template{
	{
		Type: "security.effect_without_receipt", Severity: Warning, Params: []string{"connection", "count"},
		Title: "A target lists effects PantherClaw has no receipt for",
		Body: "The target log of the connection {connection} lists {count} new effects that no PantherClaw receipt " +
			"accounts for. Someone may have used the target's own console, or a credential may have leaked. " +
			"Review them before you rely on the connection's records.",
	},
	{
		Type: "reconciliation.waiting", Severity: Warning, Params: []string{"operation", "agent", "reconciliation"},
		Title: "An unknown outcome is waiting for reconciliation",
		Body: "Nobody knows whether {operation} by the agent {agent} happened. Its budget stays held until the effect is " +
			"found, or until a person independent of the run confirms on the reconciliation page that it did not happen. " +
			"Open the page to see the evidence.",
		Link: "/reconciliations/{reconciliation}",
	},
	{
		Type: "reconciliation.escalated", Severity: Warning, Params: []string{"operation", "agent", "reconciliation"},
		Title: "An unknown outcome is still waiting for reconciliation",
		Body: "It is still not known whether {operation} by the agent {agent} happened, and the reconciliation now reaches " +
			"more people. Its budget stays held until it is reconciled.",
		Link: "/reconciliations/{reconciliation}",
	},
	{
		Type: "transaction.reconciliation_released", Severity: Warning, Params: []string{"operation", "agent", "reconciliation"},
		Title: "A person released an unknown outcome",
		Body: "A person confirmed with a security key that {operation} by the agent {agent} did not happen, and its held " +
			"budget was released. Review the basis they wrote on the reconciliation page if you did not expect this.",
		Link: "/reconciliations/{reconciliation}",
	},
}

func init() { templates = append(templates, m7Templates...) }
