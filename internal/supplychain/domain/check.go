// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the supply-chain checks on what an MCP server lists
// (G0 M24 D210; HR-582, HR-583; F867). Each check reads one listed entry and
// returns flags: a kind, a severity and where in the text it looked. The
// listed text is the upstream server's UNTRUSTED text, and it stays that way:
// a flag's Note is written here, from counts and fixed words, and carries none
// of it, and a check never acts on what it reads. A flag only informs a
// person. Flags approve nothing and refuse nothing, and an entry with no flags
// has "no known flags", which never means safe (HR-582, F801). The checks are
// heuristics over text a server chose. Everything here is pure.
package domain

import (
	"slices"
	"strings"
)

// CheckKind names a check.
type CheckKind string

// The checks (D210), a closed list.
const (
	KindHiddenInstruction CheckKind = "hidden_instruction"
	KindInjectionPattern  CheckKind = "injection_pattern"
	KindToolShadowing     CheckKind = "tool_shadowing"
	KindOverbroadSchema   CheckKind = "overbroad_schema"
	KindRugPull           CheckKind = "rug_pull"
	KindProvenanceUnknown CheckKind = "provenance_unknown"
	// KindSchemaUnavailable: the gateway left a schema or another listed field
	// out at a size limit (D240, D270), so a server cannot hide behind size.
	KindSchemaUnavailable CheckKind = "schema_unavailable"
)

// Kinds lists every check.
func Kinds() []CheckKind {
	return []CheckKind{
		KindHiddenInstruction, KindInjectionPattern, KindToolShadowing, KindOverbroadSchema, KindRugPull, KindProvenanceUnknown,
		KindSchemaUnavailable,
	}
}

// Severity is a flag's severity, in the API's upper case.
type Severity string

// Severities, least to most.
const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Field names the text a Span points into.
type Field string

// ReasonDigestUnknown says a tool had no upstream digest to compare (D272).
const ReasonDigestUnknown = "digest_unknown"

// Fields.
const (
	FieldDescription Field = "description"
	// FieldInputSchema: offsets are into the input schema as listed, and cover
	// the JSON token or member that held the hit.
	FieldInputSchema Field = "input_schema"
	// FieldListed: offsets are into the listed title, annotations and output
	// schema, as the gateway reported them.
	FieldListed Field = "listed_extra"
)

// Limits (D211).
const (
	// MaxInputSchema is the most of an input schema that is reported: a
	// longer schema is reported by digest alone.
	MaxInputSchema = 64 << 10
	// MaxListedExtra is the most of a tool's other listed fields reported.
	MaxListedExtra = 16 << 10
	// MaxSpans is how many spans one flag keeps.
	MaxSpans = 32
)

// Span is a byte range of one field: Start up to, not including, End. It says
// where to look, and holds none of the text.
type Span struct {
	Field Field `json:"field"`
	Start int   `json:"start"`
	End   int   `json:"end"`
}

// Flag is one check's finding on one entry, at most one per kind. Note is
// PantherClaw's own plain text and never holds listed text (HR-583).
type Flag struct {
	Kind     CheckKind
	Severity Severity
	Note     string
	Spans    []Span
	// Reason is a fixed word for a flag that has more than one, or empty.
	Reason string
}

// Tool is one listed entry. All of its text is UNTRUSTED.
type Tool struct {
	// Name is the tool name, resource URI or template.
	Name string
	// IsTool: a tool, not a resource or template. Shadowing, the schema and a
	// rug pull are about tools.
	IsTool bool
	// Digest is "sha256:<hex>" of the listing entry.
	Digest string
	// DigestUnknown: Digest is not the upstream tool's, because a package pins
	// none, so it says nothing against another definition's (D272).
	DigestUnknown bool
	Description   string
	// DescriptionCut: the description reached here cut short.
	DescriptionCut bool
	// InputSchema is the schema's JSON as listed. Empty when none was
	// reported; with InputSchemaCut set, the schema was too long to report.
	InputSchema       []byte
	InputSchemaDigest string
	InputSchemaCut    bool
	// SchemaOmitted: the schema fit its own limit and not the report's.
	SchemaOmitted bool
	// Extra is a JSON object of the tool's other listed fields an agent reads:
	// title, annotations and output schema. ExtraCut: one or more of them did
	// not fit and is missing from Extra.
	Extra    []byte
	ExtraCut bool
	// Version is the version the entry is judged at: the connection's pinned
	// package version.
	Version string
}

// Approved is a tool a person already approved somewhere else.
type Approved struct{ Name, Digest string }

// Baseline is what was approved for this tool.
type Baseline struct {
	Digest  string
	Version string
	// TextKnown: Description and SchemaDigest hold the approved text. Without
	// it only the digest is known, so any other digest counts as a change.
	TextKnown    bool
	Description  string
	SchemaDigest string
}

// Known is what the caller knows about the entry; the checks read nothing
// else.
type Known struct {
	// BuiltIns are the names agents have built in.
	BuiltIns []string
	// Approved are approved tools of other connections or packages.
	Approved []Approved
	// Baseline is what the pinned version reviewed for this tool, nil when it
	// names no such tool.
	Baseline *Baseline
	// Provenance: a reviewed package names this entry, or its signer says
	// where it came from.
	Provenance bool
}

// Result is what the checks found on one entry.
type Result struct {
	Flags []Flag
	// Partial: part of the text was not checked, so even "no known flags"
	// covers only the rest.
	Partial bool
}

// Check runs every check on one entry, in the order of Kinds. It never fails:
// a schema it cannot read is itself a flag.
func Check(t Tool, k Known) Result {
	out := Result{Partial: t.DescriptionCut || t.InputSchemaCut || t.SchemaOmitted || t.ExtraCut || t.IsTool && len(t.InputSchema) == 0}
	schema, schemaErr := parseSchema(t.InputSchema)
	extra, extraErr := parseSchema(t.Extra)
	docs := []document{documentOf(FieldInputSchema, t.InputSchema, schema, schemaErr), documentOf(FieldListed, t.Extra, extra, extraErr)}
	add := func(f *Flag) {
		if f != nil {
			out.Flags = append(out.Flags, *f)
		}
	}
	add(hidden(t, docs))
	add(injected(t, docs))
	if t.IsTool {
		add(shadowing(t, k))
		add(overbroad(t, schema, schemaErr))
		add(rugPull(t, k.Baseline))
	}
	if !k.Provenance {
		add(&Flag{Kind: KindProvenanceUnknown, Severity: SeverityLow, Note: "No reviewed package names this entry."})
	}
	if t.IsTool {
		add(unavailable(t))
	}
	return out
}

// unavailable is the schema_unavailable check: a field left out at a size limit
// was not checked, so it never passes by silence (D240, D270).
func unavailable(t Tool) *Flag {
	note := ""
	switch {
	case t.SchemaOmitted && t.ExtraCut:
		note = "The input schema and another listed field did not fit and were not checked."
	case t.SchemaOmitted:
		note = "The input schema did not fit the report and was not checked."
	case t.ExtraCut:
		note = "A listed title, annotations or output schema did not fit and was not checked."
	default:
		return nil
	}
	return &Flag{Kind: KindSchemaUnavailable, Severity: SeverityMedium, Note: note}
}

// Summary is the result in words, for a review entry. An empty result reads
// "no known flags" and nothing stronger (D213, F801).
func Summary(r Result) string {
	if len(r.Flags) == 0 {
		if r.Partial {
			return "no known flags in the part checked"
		}
		return "no known flags"
	}
	kinds := make([]string, 0, len(r.Flags))
	for _, f := range r.Flags {
		if !slices.Contains(kinds, string(f.Kind)) {
			kinds = append(kinds, string(f.Kind))
		}
	}
	return strings.Join(kinds, ",")
}

// capSpans keeps the first MaxSpans spans.
func capSpans(s []Span) []Span {
	if len(s) > MaxSpans {
		return s[:MaxSpans]
	}
	return s
}
