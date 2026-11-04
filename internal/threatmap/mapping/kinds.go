// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

// KindMapping maps one behavior or content signal kind to techniques
// (G0 M28 D714): ids XOR None.
type KindMapping struct {
	ATLAS  []string `json:"atlas,omitzero"`
	ATTACK []string `json:"attack,omitzero"`
	// Why gives each id one line that cites it.
	Why map[string]string `json:"why,omitzero"`
	// None says in one line why the kind maps to no technique.
	None string `json:"none,omitzero"`
}

// Kinds maps "behavior.<KIND>" (the behavior deviation kinds) and
// "content.<kind>" (the content signal kinds, all but scan_incomplete,
// which is an owned failure) to techniques (D714).
var Kinds = map[string]KindMapping{
	"behavior.NEW_TOOL": {ATLAS: []string{"AML.T0053"}, Why: map[string]string{
		"AML.T0053": "AI agent tool invocation (AML.T0053): the agent calls a tool it has not used before.",
	}},
	"behavior.NEW_DESTINATION": {ATLAS: []string{"AML.T0086"}, ATTACK: []string{"T1567"}, Why: map[string]string{
		"AML.T0086": "Exfiltration via AI agent tool invocation (AML.T0086): a tool writes toward a destination not seen before.",
		"T1567":     "Exfiltration over web service (T1567): data heads to a service destination new to the agent.",
	}},
	"behavior.UNUSUAL_HOUR": {None: "A timing signal about the agent's own pattern; it names no technique."},
	"behavior.NEW_SEQUENCE": {None: "An order-of-operations signal about the agent's own pattern; it names no technique."},
	"behavior.VOLUME_SPIKE": {ATLAS: []string{"AML.T0034.002"}, Why: map[string]string{
		"AML.T0034.002": "Agentic resource consumption (AML.T0034.002): the agent makes far more calls than its usual volume.",
	}},
	"behavior.SPEND_SPIKE": {ATLAS: []string{"AML.T0048.000"}, ATTACK: []string{"T1657"}, Why: map[string]string{
		"AML.T0048.000": "Financial harm (AML.T0048.000): the agent moves far more money than its usual spend.",
		"T1657":         "Financial theft (T1657): spend well above the agent's pattern is how theft through payments shows.",
	}},
	"content.injection_phrase": {ATLAS: []string{"AML.T0051.001"}, ATTACK: []string{"T1698"}, Why: map[string]string{
		"AML.T0051.001": "Indirect prompt injection (AML.T0051.001): content the agent reads or writes carries an instruction phrase.",
		"T1698":         "Indirect prompt injection (T1698): the flagged phrase arrives in data, not from the person running the agent.",
	}},
	"content.secret_format": {ATLAS: []string{"AML.T0055", "AML.T0098"}, ATTACK: []string{"T1552"}, Why: map[string]string{
		"AML.T0055": "Unsecured credentials (AML.T0055): content carries something shaped like a token or private key.",
		"AML.T0098": "AI agent tool credential harvesting (AML.T0098): a tool result the agent retrieved carries a credential.",
		"T1552":     "Unsecured credentials (T1552): a credential-shaped value sits in data the agent handles.",
	}},
	"content.high_entropy":    {None: "A shape signal on content; on its own it names no technique."},
	"content.pii_email":       {None: "A data class signal for personal data; it names no technique."},
	"content.pii_card":        {None: "A data class signal for card numbers; it names no technique."},
	"content.pii_national_id": {None: "A data class signal for national ids; it names no technique."},
	"content.classifier_flag": {None: "Whatever an outside classifier flags; it names no technique."},
}
