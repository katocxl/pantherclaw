// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain is the compliance control table (G0 M25 D300, D302; HR-600,
// HR-601): for each framework its controls and the evidence each one reads,
// and the pure rule that turns what the records hold into a control state.
// A report shows evidence and gaps. It carries no score, and it never says a
// customer meets a framework (F527, F801, PN-009.4, HR-224).
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
)

// Framework names a control table.
type Framework string

// The frameworks (D300), in the order they ship (H4). No other is listed.
const (
	OWASPASI        Framework = "OWASP_ASI"
	NISTAIRMF       Framework = "NIST_AI_RMF"
	EUAIActDeployer Framework = "EU_AI_ACT_DEPLOYER"
	ISO42001        Framework = "ISO_42001"
	SOC2            Framework = "SOC2"
)

// Source is a kind of evidence. Each comes from PantherClaw's own records
// (D312); nothing a customer or a runner says becomes one.
type Source string

// The sources.
const (
	SourceReceipts  Source = "receipts"
	SourceApprovals Source = "approvals"
	SourceGrants    Source = "grants"
	SourceCoverage  Source = "coverage"
	// SourceRange and SourceCampaign are tests, never production records.
	// Both are simulated by construction (HR-220, F630).
	SourceRange    Source = "range"
	SourceCampaign Source = "campaign"
	// SourceStated is what a person said about an agent. It is never evidence.
	SourceStated Source = "stated"
)

// RecordSources are the sources of production records.
func RecordSources() []Source {
	return []Source{SourceReceipts, SourceApprovals, SourceGrants, SourceCoverage}
}

// TestSources are the sources of test results.
func TestSources() []Source { return []Source{SourceRange, SourceCampaign} }

// StatedField is an agent field a person states (migration 00273).
type StatedField string

// The stated fields.
const (
	FieldAIActRole StatedField = "ai_act_role"
	FieldAIActRisk StatedField = "ai_act_risk"
)

// StatedFields lists them.
func StatedFields() []StatedField { return []StatedField{FieldAIActRole, FieldAIActRisk} }

// Control is one row of a framework's table.
type Control struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Records are the production records the control reads: all must hold.
	Records []Source `json:"records,omitzero"`
	// Tests are the OWASP agentic risks whose tagged range and campaign
	// results the control reads. Those results are simulated, so tests alone
	// never make a control EVIDENCED.
	Tests []string `json:"tests,omitzero"`
	// Stated, when set, is the only thing the control reads: a person's
	// statement, which yields STATED and never EVIDENCED (D302).
	Stated StatedField `json:"stated,omitzero"`
	// Outside says why no PantherClaw record reaches this control. It reads
	// as a gap: a report never leaves a framework's obligation off the list.
	Outside string `json:"outside,omitzero"`
}

const outsideRecords = "PantherClaw holds no record of this: it is the organization's own process"

// Frameworks lists every framework, in order.
func Frameworks() []Framework {
	return []Framework{OWASPASI, NISTAIRMF, EUAIActDeployer, ISO42001, SOC2}
}

// Known reports whether f is a listed framework.
func (f Framework) Known() bool { return slices.Contains(Frameworks(), f) }

// Title is a framework's display name.
func (f Framework) Title() string {
	switch f {
	case OWASPASI:
		return "OWASP Top 10 for Agentic Applications (2026)"
	case NISTAIRMF:
		return "NIST AI Risk Management Framework 1.0"
	case EUAIActDeployer:
		return "EU AI Act (Regulation 2024/1689), deployer obligations"
	case ISO42001:
		return "ISO/IEC 42001:2023 Annex A"
	case SOC2:
		return "SOC 2 Trust Services Criteria, common criteria"
	}
	return ""
}

// Controls returns a copy of a framework's table, nil for an unknown one.
func Controls(f Framework) []Control {
	return slices.Clone(tables[f])
}

// CatalogDigest identifies a framework's table: `pclaw verify` re-derives a
// report only under the table it was written with.
func CatalogDigest(f Framework) string {
	raw, err := json.Marshal(tables[f], json.Deterministic(true))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var tables = map[Framework][]Control{
	OWASPASI:        owaspASI,
	NISTAIRMF:       nistAIRMF,
	EUAIActDeployer: euAIActDeployer,
	ISO42001:        iso42001,
	SOC2:            soc2,
}

// owaspASI holds every risk of the closed list. ASI05 and ASI06 name no
// production record: they read as gaps unless a tagged test exercised them
// (D304), and even then only as PARTIAL.
var owaspASI = []Control{
	{ID: "ASI01", Title: "Agent goal hijack", Records: []Source{SourceReceipts}, Tests: []string{"ASI01"}},
	{ID: "ASI02", Title: "Tool misuse and exploitation", Records: []Source{SourceReceipts, SourceApprovals}, Tests: []string{"ASI02"}},
	{ID: "ASI03", Title: "Identity and privilege abuse", Records: []Source{SourceGrants, SourceReceipts}, Tests: []string{"ASI03"}},
	{ID: "ASI04", Title: "Agentic supply chain vulnerabilities", Records: []Source{SourceCoverage}, Tests: []string{"ASI04"}},
	{ID: "ASI05", Title: "Unexpected code execution", Tests: []string{"ASI05"}},
	{ID: "ASI06", Title: "Memory and context poisoning", Tests: []string{"ASI06"}},
	{ID: "ASI07", Title: "Insecure inter-agent communication", Records: []Source{SourceGrants}, Tests: []string{"ASI07"}},
	{ID: "ASI08", Title: "Cascading failures", Records: []Source{SourceReceipts}, Tests: []string{"ASI08"}},
	{ID: "ASI09", Title: "Human-agent trust exploitation", Records: []Source{SourceApprovals}, Tests: []string{"ASI09"}},
	{ID: "ASI10", Title: "Rogue agents", Records: []Source{SourceCoverage, SourceGrants}, Tests: []string{"ASI10"}},
}

// nistAIRMF lists the subcategories PantherClaw's records can speak to, and
// names the ones next to them that it cannot.
var nistAIRMF = []Control{
	{ID: "GOVERN-1.6", Title: "Mechanisms exist to inventory AI systems", Records: []Source{SourceCoverage}},
	{ID: "GOVERN-2.1", Title: "Roles and responsibilities are documented", Records: []Source{SourceGrants}},
	{ID: "GOVERN-3.2", Title: "Roles for human-AI oversight are defined", Records: []Source{SourceApprovals}},
	{ID: "GOVERN-6.1", Title: "Policies address third-party AI risk", Outside: outsideRecords},
	{ID: "MAP-1.1", Title: "Intended purposes and context are understood", Outside: outsideRecords},
	{ID: "MAP-3.5", Title: "Processes for human oversight are defined", Records: []Source{SourceApprovals}},
	{ID: "MAP-4.2", Title: "Internal risk controls for components are identified", Records: []Source{SourceCoverage}, Tests: []string{"ASI04"}},
	{ID: "MEASURE-2.4", Title: "Behavior is monitored in production", Records: []Source{SourceReceipts, SourceCoverage}},
	{ID: "MEASURE-2.7", Title: "Security and resilience are evaluated", Records: []Source{SourceReceipts}, Tests: []string{"ASI01", "ASI02", "ASI03"}},
	{ID: "MEASURE-2.8", Title: "Transparency and accountability risks are examined", Records: []Source{SourceReceipts, SourceApprovals}},
	{ID: "MEASURE-2.11", Title: "Fairness and bias are evaluated", Outside: outsideRecords},
	{ID: "MANAGE-2.4", Title: "Systems can be superseded, disengaged or deactivated", Records: []Source{SourceGrants}, Tests: []string{"ASI08", "ASI10"}},
	{ID: "MANAGE-3.1", Title: "Third-party resources are monitored", Records: []Source{SourceCoverage}},
	{ID: "MANAGE-4.1", Title: "Post-deployment monitoring is in place", Records: []Source{SourceReceipts}},
	{ID: "MANAGE-4.3", Title: "Incidents are communicated to those affected", Outside: outsideRecords},
}

// euAIActDeployer is the deployer's side only (D300). A risk class or a role
// is a person's statement, never a finding of PantherClaw's (D302).
var euAIActDeployer = []Control{
	{ID: "ART-3-ROLE", Title: "Who the organization is for this system", Stated: FieldAIActRole},
	{ID: "ART-6-CLASS", Title: "The system's risk class", Stated: FieldAIActRisk},
	{ID: "ART-4", Title: "AI literacy of staff", Outside: outsideRecords},
	{ID: "ART-26-1", Title: "Use in line with the provider's instructions", Records: []Source{SourceGrants, SourceReceipts}},
	{ID: "ART-26-2", Title: "Human oversight is assigned", Records: []Source{SourceApprovals}},
	{ID: "ART-26-4", Title: "Input data is relevant", Outside: outsideRecords},
	{ID: "ART-26-5", Title: "Operation is monitored", Records: []Source{SourceReceipts, SourceCoverage}},
	{ID: "ART-26-6", Title: "Automatically generated logs are kept", Records: []Source{SourceReceipts}},
	{ID: "ART-26-7", Title: "Workers are informed", Outside: outsideRecords},
	{ID: "ART-27", Title: "Fundamental rights impact assessment", Outside: outsideRecords},
	{ID: "ART-50", Title: "Transparency to people who interact with the system", Outside: outsideRecords},
}

// iso42001 reads Annex A.
var iso42001 = []Control{
	{ID: "A.2.2", Title: "AI policy", Outside: outsideRecords},
	{ID: "A.3.2", Title: "AI roles and responsibilities", Records: []Source{SourceGrants, SourceApprovals}},
	{ID: "A.4.2", Title: "Resource documentation", Records: []Source{SourceCoverage}},
	{ID: "A.5.2", Title: "AI system impact assessment process", Outside: outsideRecords},
	{ID: "A.6.2.6", Title: "AI system operation and monitoring", Records: []Source{SourceReceipts, SourceCoverage}},
	{ID: "A.6.2.8", Title: "Recording of event logs", Records: []Source{SourceReceipts}},
	{ID: "A.8.4", Title: "Communication of incidents", Outside: outsideRecords},
	{ID: "A.9.2", Title: "Processes for responsible use", Records: []Source{SourceApprovals, SourceGrants}},
	{ID: "A.9.4", Title: "Intended use of the AI system", Records: []Source{SourceGrants, SourceReceipts}},
	{ID: "A.10.3", Title: "Suppliers", Outside: outsideRecords},
}

// soc2 reads the common criteria PantherClaw's records can speak to.
var soc2 = []Control{
	{ID: "CC6.1", Title: "Logical access security", Records: []Source{SourceGrants, SourceReceipts}, Tests: []string{"ASI03"}},
	{ID: "CC6.2", Title: "Access is registered and authorized", Records: []Source{SourceGrants}},
	{ID: "CC6.3", Title: "Access is role-based and least privilege", Records: []Source{SourceGrants, SourceApprovals}},
	{ID: "CC6.6", Title: "Logical access from outside the boundary", Records: []Source{SourceCoverage}, Tests: []string{"ASI02"}},
	{ID: "CC7.1", Title: "Detection of configuration changes", Records: []Source{SourceCoverage}},
	{ID: "CC7.2", Title: "Monitoring for anomalies", Records: []Source{SourceReceipts}},
	{ID: "CC7.3", Title: "Security events are evaluated", Records: []Source{SourceApprovals, SourceReceipts}},
	{ID: "CC7.4", Title: "Incident response", Records: []Source{SourceGrants}, Tests: []string{"ASI08", "ASI10"}},
	{ID: "CC8.1", Title: "Changes are authorized", Records: []Source{SourceApprovals}},
	{ID: "CC9.2", Title: "Vendors and business partners", Outside: outsideRecords},
}
