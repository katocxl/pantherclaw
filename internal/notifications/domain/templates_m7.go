// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m7Templates are the effect notification types (G0 M7). An effect without a
// receipt is a finding, not proof of an attack: a person may have used the
// target's own console, so the message only asks for a review (HR-112).
var m7Templates = []Template{
	{
		Type: "security.effect_without_receipt", Severity: Warning, Params: []string{"connection", "count"},
		Title: "A target lists effects PantherClaw has no receipt for",
		Body: "The target log of the connection {connection} lists {count} new effects that no PantherClaw receipt " +
			"accounts for. Someone may have used the target's own console, or a credential may have leaked. " +
			"Review them before you rely on the connection's records.",
	},
}

func init() { templates = append(templates, m7Templates...) }
