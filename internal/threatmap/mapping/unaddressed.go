// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

// UnaddressedEntry is a technique inside an agent platform's reach for which
// PantherClaw ships no control (G0 M28 D714, founder FQ2 A): shown red in
// the "No PantherClaw control yet" list with its reason, every lane
// NONE_SHIPPED, fix NONE.
type UnaddressedEntry struct {
	ID string `json:"id"`
	// Why is one line citing the id.
	Why string `json:"why"`
}

// Unaddressed is every technique PantherClaw ships no control for yet.
var Unaddressed = []UnaddressedEntry{
	// ATLAS
	{ID: "AML.T0054", Why: "LLM jailbreak (AML.T0054): it happens inside the model's conversation; PantherClaw decides on the actions that follow, not on the prompt."},
	{ID: "AML.T0061", Why: "LLM prompt self-replication (AML.T0061): PantherClaw does not inspect model output for prompts that copy themselves."},
	{ID: "AML.T0067", Why: "LLM trusted output components manipulation (AML.T0067): citations and labels in a model's answer have no PantherClaw control."},
	{ID: "AML.T0069", Why: "Discover LLM system information (AML.T0069): asking the model about its system prompt never reaches a PantherClaw decision."},
	{ID: "AML.T0077", Why: "LLM response rendering (AML.T0077): rendering of model output in a client has no PantherClaw control."},
	{ID: "AML.T0080", Why: "AI agent context poisoning (AML.T0080): an agent's memory and context are not read by PantherClaw."},
	{ID: "AML.T0082", Why: "RAG credential harvesting (AML.T0082): credentials retrieved from an index never pass a PantherClaw decision."},
	{ID: "AML.T0085", Why: "Data from AI services (AML.T0085): collection through an organization's AI services has no PantherClaw control yet."},
	{ID: "AML.T0092", Why: "Manipulate user LLM chat history (AML.T0092): chat history lives in the assistant, not in PantherClaw's evidence."},
	{ID: "AML.T0094", Why: "Delay execution of LLM instructions (AML.T0094): a delayed instruction is only seen when it turns into an action."},
	{ID: "AML.T0096", Why: "AI service API (AML.T0096): command and control over an AI provider's API has no PantherClaw control."},
	{ID: "AML.T0100", Why: "AI agent clickbait (AML.T0100): clicks by computer-using agents in a browser have no PantherClaw control."},
	{ID: "AML.T0103", Why: "Deploy AI agent (AML.T0103): an agent launched apart from PantherClaw is only found by discovery; it has no PantherClaw control."},
	{ID: "AML.T0108", Why: "AI agent (AML.T0108): an agent used as a command channel beyond its grants has no PantherClaw control yet."},
	{ID: "AML.T0119", Why: "Exploit automated artifact processing pipeline (AML.T0119): pipelines that process artifacts have no PantherClaw control."},
	{ID: "AML.T0121", Why: "AI agent environment reconstruction (AML.T0121): an agent rebuilding its own environment has no PantherClaw control yet."},
	{ID: "AML.T0129", Why: "Triggers in multimodal inputs (AML.T0129): content signals read text; images and audio have no control yet."},
	{ID: "AML.T0130", Why: "AI agent response biasing (AML.T0130): bias in what an assistant recommends never reaches a PantherClaw decision."},
	{ID: "AML.T0131", Why: "Crafted AI assistant links (AML.T0131): a link that opens an assistant with input supplied has no PantherClaw control."},
	{ID: "AML.T0134", Why: "AI targeted cloaking (AML.T0134): PantherClaw does not compare what a site shows agents and people."},
	{ID: "AML.T0136", Why: "Exfiltration via AI user interface (AML.T0136): disclosure in an assistant's own answers has no PantherClaw control."},
	{ID: "AML.T0143", Why: "LLM prompt propagation (AML.T0143): instructions carried onward between stores and agents have no control of their own yet."},
	// ATT&CK
	{ID: "T1080", Why: "Taint shared content (T1080): granted writes to a shared repository are allowed; PantherClaw does not judge their content."},
	{ID: "T1528", Why: "Steal application access token (T1528): theft of a token happens where it is stored; PantherClaw acts only on its later use."},
	{ID: "T1651", Why: "Cloud administration command (T1651): commands run through a cloud's own management service have no PantherClaw control yet."},
	{ID: "T1696", Why: "Anti-automation evasion (T1696): an agent solving automation checks in its own browser makes no PantherClaw call."},
	{ID: "T1699", Why: "Direct prompt injection (T1699): it happens in the model's conversation; PantherClaw decides on the actions that follow."},
}
