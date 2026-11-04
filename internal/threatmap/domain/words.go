// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"regexp"
	"strings"
)

// Statement says what the map is and is not (G0 M28 D717). Every RPC
// response, CLI output, pack, Navigator layer and MCP tool result carries it
// verbatim.
const Statement = "This map shows the PantherClaw controls mapped to each technique and the evidence for them. " +
	"A mapped control covers the technique, not every way of carrying it out. " +
	"Techniques outside PantherClaw need other tools. It is not a score or a guarantee."

// Banned are the words no threat-map string may use, case-insensitive and
// word-bounded (D717). The Statement is checked by exact equality and
// removed from an output before it is scanned (D717a).
var Banned = []string{
	"protected", "protects", "protection", "compliant", "certified", "secure", "safe", "score", "percent",
	"blocked", "clean", "none found",
}

var bannedRE = regexp.MustCompile(`(?i)\b(` + strings.Join(Banned, "|") + `)\b`)

// BannedWord returns the first banned word in s, once every exact
// occurrence of the Statement is removed, or "" (D717a).
func BannedWord(s string) string {
	return bannedRE.FindString(strings.ReplaceAll(s, Statement, ""))
}

// Reason is why a lane is in its state (D713, closed).
type Reason string

// Reasons.
const (
	ReasonControlOff           Reason = "CONTROL_OFF"
	ReasonNoRoutes             Reason = "NO_ROUTES"
	ReasonNoEnforcedRoute      Reason = "NO_ENFORCED_ROUTE"
	ReasonRoutesNotEnforced    Reason = "ROUTES_NOT_ENFORCED"
	ReasonSubtechniquesOnly    Reason = "SUBTECHNIQUES_ONLY"
	ReasonEditionRequired      Reason = "EDITION_REQUIRED"
	ReasonRuleOff              Reason = "RULE_OFF"
	ReasonRuleSuppressed       Reason = "RULE_SUPPRESSED"
	ReasonRuleSilent           Reason = "RULE_SILENT"
	ReasonEngineLive           Reason = "ENGINE_LIVE"
	ReasonInputRecent          Reason = "INPUT_RECENT"
	ReasonTriggerRuleOff       Reason = "TRIGGER_RULE_OFF"
	ReasonNarrowedTrigger      Reason = "NARROWED_TRIGGER"
	ReasonPlaybookDisabled     Reason = "PLAYBOOK_DISABLED"
	ReasonPlaybookNotInstalled Reason = "PLAYBOOK_NOT_INSTALLED"
	ReasonScenarioChanged      Reason = "SCENARIO_CHANGED"
	ReasonReportedOnly         Reason = "REPORTED_ONLY"
	ReasonNoScenario           Reason = "NO_SCENARIO"
	ReasonNeverRun             Reason = "NEVER_RUN"
	ReasonTestFailed           Reason = "TEST_FAILED"
	ReasonTestStale            Reason = "TEST_STALE"
	ReasonStated               Reason = "STATED"
	ReasonNoneShipped          Reason = "NONE_SHIPPED"
	ReasonOutside              Reason = "OUTSIDE"
	ReasonUnaddressed          Reason = "UNADDRESSED"
)

// reasonTexts are the fixed texts of the reasons.
var reasonTexts = map[Reason]string{
	ReasonControlOff:           "No mapped control is switched on in this organization.",
	ReasonNoRoutes:             "No active agent in scope has a route to check.",
	ReasonNoEnforcedRoute:      "No route in scope is enforced through PantherClaw.",
	ReasonRoutesNotEnforced:    "Some routes in scope are not enforced through PantherClaw.",
	ReasonSubtechniquesOnly:    "Only sub-techniques are mapped in this lane.",
	ReasonEditionRequired:      "This needs a higher edition.",
	ReasonRuleOff:              "The rule is turned off.",
	ReasonRuleSuppressed:       "An active suppression silences the rule across the organization.",
	ReasonRuleSilent:           "No input this rule reads has arrived in the last 7 days.",
	ReasonEngineLive:           "The rule listens for events that exist only when the act happens; the engine is reading this organization's events.",
	ReasonInputRecent:          "Input this rule reads arrived in the last 7 days.",
	ReasonTriggerRuleOff:       "The automation is active, but the rule that triggers it is off or not licensed.",
	ReasonNarrowedTrigger:      "The automation's trigger also tests something other than the rule, so it may not run on every alert of the rule.",
	ReasonPlaybookDisabled:     "The automation is not active.",
	ReasonPlaybookNotInstalled: "A Hub playbook responds to a mapped rule, and it is not installed.",
	ReasonScenarioChanged:      "A result was recorded for an earlier version of the scenario and is not counted.",
	ReasonReportedOnly:         "The newest pass was reported by the runner, not observed by the server, and is not counted.",
	ReasonNoScenario:           "No library scenario tests this technique.",
	ReasonNeverRun:             "No mapped scenario has a counted result.",
	ReasonTestFailed:           "A mapped scenario failed in the last 30 days.",
	ReasonTestStale:            "The newest counted result is older than 30 days.",
	ReasonStated:               "Only this organization's own rule or automation is mapped: a statement, not evidence.",
	ReasonNoneShipped:          "PantherClaw ships no control for this lane.",
	ReasonOutside:              "Outside PantherClaw: another kind of tool covers it.",
	ReasonUnaddressed:          "PantherClaw ships no control for this technique.",
}

// Reasons lists every reason.
func Reasons() []Reason {
	out := make([]Reason, 0, len(reasonTexts))
	for r := range reasonTexts {
		out = append(out, r)
	}
	return out
}

// Text is the reason's fixed text.
func (r Reason) Text() string { return reasonTexts[r] }

// Label templates of fixes (D713). Names are inserted as plain text.
const (
	labelEnableRule       = "Turn rule %s back on"
	labelPublishRule      = "Publish rule %s"
	labelEndSuppression   = "End the suppression of rule %s"
	labelSendEvents       = "Send the events rule %s reads: %s"
	labelUpgradeEdition   = "Upgrade to %s"
	labelTurnOnContent    = "Turn content signals on (WATCHING or ACTIVE)"
	labelContentActive    = "Set content signals to ACTIVE"
	labelMCPEnforce       = "Set the MCP server catalog to ENFORCE"
	labelRouteNamed       = "Route these agents through a PantherClaw gateway: %s"
	labelRouteAny         = "Route your agents through a PantherClaw gateway"
	labelEnablePlaybook   = "Turn on automation %s"
	labelInstallHubItem   = "Install Hub playbook %s"
	labelRunScenario      = "Run the library scenarios for %s"
	labelNone             = "PantherClaw ships no control for this technique"
	commandRunScenario    = "pclaw redteam run --technique %s"
	subtechniquesOnlyText = "covers %d of %d sub-techniques"
)

// namesList names up to five, then "and N more".
func namesList(names []string) string {
	if len(names) <= 5 {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:5], ", ") + fmt.Sprintf(" and %d more", len(names)-5)
}

// SubtechniquesText is the SUBTECHNIQUES_ONLY detail (D712).
func SubtechniquesText(n, m int) string { return fmt.Sprintf(subtechniquesOnlyText, n, m) }
