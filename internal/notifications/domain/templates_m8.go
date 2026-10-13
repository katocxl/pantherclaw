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
}

func init() { templates = append(templates, m8Templates...) }
