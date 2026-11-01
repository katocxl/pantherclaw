// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "regexp"

// safeTool is a tool name as ReportDrift takes it: the only listed name that
// is shown as a name, because nothing else about it is free text.
var safeTool = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// ToolName returns name when it is a pattern-checked tool name, and "" when
// it is listed text that may say anything (HR-583).
func ToolName(name string) string {
	if safeTool.MatchString(name) {
		return name
	}
	return ""
}

// titles are the queue's titles, one per check (D204). They say what was
// seen, never that anything is or is not safe (D213).
var titles = map[CheckKind]string{
	KindHiddenInstruction: "Text that does not show in a listing",
	KindInjectionPattern:  "Instruction-like text in a listing",
	KindToolShadowing:     "A tool with the name of another tool",
	KindOverbroadSchema:   "A tool that takes free-form input",
	KindRugPull:           "A tool that changed after approval",
	KindProvenanceUnknown: "A listed entry no reviewed package names",
	KindSchemaUnavailable: "A tool whose input schema was not reported",
}

// Title is a flag's title, always one of these fixed words: an observed name
// goes in a finding's detail, never here (D260).
func Title(k CheckKind) string {
	if t := titles[k]; t != "" {
		return t
	}
	return "A supply-chain flag"
}
