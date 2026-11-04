// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain evaluates the threat map (G0 M28 D710, D712, D713): for
// each technique of a pinned MITRE catalog, four lanes (Prevent, Detect,
// Respond, Test) from the org's own records, a status, what was seen, and
// every gap with its fix. It is pure: it reads the catalog, the mappings and
// the inputs it is handed, never a database, so the server and an offline
// verifier (evidence/bundle) derive the same map from the same inputs.
package domain

import (
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// LaneState is what the records say of a Prevent, Detect or Respond lane.
type LaneState string

// Lane states (D713).
const (
	LaneEvidenced   LaneState = "EVIDENCED"
	LanePartial     LaneState = "PARTIAL"
	LaneGap         LaneState = "GAP"
	LaneStated      LaneState = "STATED"
	LaneNoneShipped LaneState = "NONE_SHIPPED"
)

// rank orders lane states for best-of: EVIDENCED > PARTIAL > GAP; STATED and
// NONE_SHIPPED only when nothing else holds.
func (s LaneState) rank() int {
	switch s {
	case LaneEvidenced:
		return 4
	case LanePartial:
		return 3
	case LaneGap:
		return 2
	case LaneStated:
		return 1
	case LaneNoneShipped:
	}
	return 0
}

// TestState is what the org's own range results say.
type TestState string

// Test states (D713).
const (
	TestPassed TestState = "PASSED"
	TestFailed TestState = "FAILED"
	TestStale  TestState = "STALE"
	TestNotRun TestState = "NOT_RUN"
)

// Status is a technique's color.
type Status string

// Statuses (D713).
const (
	StatusEvidenced Status = "EVIDENCED"
	StatusPartial   Status = "PARTIAL"
	StatusGap       Status = "GAP"
	StatusOutside   Status = "OUTSIDE"
)

// Statuses lists every status in display order.
func Statuses() []Status { return []Status{StatusEvidenced, StatusPartial, StatusGap, StatusOutside} }

// Lane names a lane.
type Lane string

// Lanes (D713).
const (
	LanePrevent Lane = "PREVENT"
	LaneDetect  Lane = "DETECT"
	LaneRespond Lane = "RESPOND"
	LaneTest    Lane = "TEST"
)

// OrgWideLanes are the lanes that ignore the agent or environment filter.
func OrgWideLanes() []Lane { return []Lane{LaneDetect, LaneRespond, LaneTest} }

// FixKind is how to close a gap (D713, closed).
type FixKind string

// Fix kinds.
const (
	FixEnableRule          FixKind = "ENABLE_RULE"
	FixEndSuppression      FixKind = "END_SUPPRESSION"
	FixSendEvents          FixKind = "SEND_EVENTS"
	FixUpgradeEdition      FixKind = "UPGRADE_EDITION"
	FixTurnOnSetting       FixKind = "TURN_ON_SETTING"
	FixRouteThroughGateway FixKind = "ROUTE_THROUGH_GATEWAY"
	FixEnablePlaybook      FixKind = "ENABLE_PLAYBOOK"
	FixInstallHubItem      FixKind = "INSTALL_HUB_ITEM"
	FixRunScenario         FixKind = "RUN_SCENARIO"
	FixNone                FixKind = "NONE"
)

// FixKinds lists every fix kind.
func FixKinds() []FixKind {
	return []FixKind{
		FixEnableRule, FixEndSuppression, FixSendEvents, FixUpgradeEdition, FixTurnOnSetting,
		FixRouteThroughGateway, FixEnablePlaybook, FixInstallHubItem, FixRunScenario, FixNone,
	}
}

// Fix is how to close one gap. Label is a fixed template; names in it are
// shown as plain text.
type Fix struct {
	Kind     FixKind `json:"kind"`
	TargetID string  `json:"target_id,omitzero"`
	Label    string  `json:"label"`
	Command  string  `json:"command,omitzero"`
}

// Gap is one PARTIAL or GAP lane (or a Test lane that is not PASSED) and its
// fix.
type Gap struct {
	Lane        Lane   `json:"lane"`
	TechniqueID string `json:"technique_id"`
	Reason      Reason `json:"reason"`
	Fix         Fix    `json:"fix"`
}

// Scope narrows Prevent and Seen to one agent or one environment; Detect,
// Respond and Test are org-wide (D713). At most one is set.
type Scope struct {
	AgentID       string `json:"agent_id,omitzero"`
	EnvironmentID string `json:"environment_id,omitzero"`
}

// Key is the snapshot scope key: "" for the org, "env:<id>" for an
// environment (D719). An agent scope has no snapshot.
func (s Scope) Key() string {
	if s.EnvironmentID != "" {
		return "env:" + s.EnvironmentID
	}
	return ""
}

// Editions are the entitlements the evaluator reads (D713).
type Editions struct {
	AdvancedDetections  bool `json:"advanced_detections"`
	CustomDetections    bool `json:"custom_detections"`
	BehaviorAnalytics   bool `json:"behavior_analytics"`
	ContentSignals      bool `json:"content_signals"`
	Automations         bool `json:"automations"`
	AutomationPlaybooks bool `json:"automation_playbooks"`
}

// Agent is one agent of the org.
type Agent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	EnvironmentID string `json:"environment_id,omitzero"`
	Active        bool   `json:"active"`
	// LastRealTransaction is the newest real (not simulated) transaction's
	// time; zero when none.
	LastRealTransaction time.Time `json:"last_real_transaction,omitzero"`
}

// Route is the latest coverage record of one (agent, connection,
// operation).
type Route struct {
	AgentID      string `json:"agent_id"`
	ConnectionID string `json:"connection_id"`
	Operation    string `json:"operation"`
	// State is ENFORCED, PARTIAL, OBSERVE_ONLY or UNKNOWN.
	State string `json:"state"`
	// ExpiresAt is when an ENFORCED record lapses (coverage freshness).
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// RuleSource says whose rule a Detect row is.
type RuleSource string

// Rule sources.
const (
	SourceBuiltin RuleSource = "BUILTIN"
	SourceKind    RuleSource = "KIND"
	SourceHub     RuleSource = "HUB"
	SourceCustom  RuleSource = "CUSTOM"
)

// Rule is one detection rule's state in the org: every built-in rule, and
// every custom rule the org has (Hub-origin or its own).
type Rule struct {
	ID     string     `json:"id"`
	Title  string     `json:"title"`
	Source RuleSource `json:"source"`
	// Business is a built-in rule of the Business edition.
	Business bool `json:"business,omitzero"`
	// Published is a custom rule's PUBLISHED state (built-ins: true).
	Published bool `json:"published"`
	// Disabled is detection_rule_state.disabled_at set.
	Disabled bool `json:"disabled,omitzero"`
	// DisabledAt is when it was turned off: the evaluator does not read it;
	// the posture queue dates a rule_off finding by it (G0 M28 D724a).
	DisabledAt time.Time `json:"disabled_at,omitzero"`
	// Suppressed is an active org-wide suppression of the rule.
	Suppressed  bool      `json:"suppressed,omitzero"`
	LastInputAt time.Time `json:"last_input_at,omitzero"`
	// Inputs are the kinds the rule reads (on and sequence steps).
	Inputs []string `json:"inputs"`
	// Techniques are a custom rule's own atlas and attack tags; a
	// built-in or Hub rule's come from the mapping.
	Techniques []string `json:"techniques,omitzero"`
}

// Cursor is the org's detection cursor.
type Cursor struct {
	// CaughtUp is the cursor at the ledger head.
	CaughtUp bool `json:"caught_up"`
	// AdvancedAt is when it last moved.
	AdvancedAt time.Time `json:"advanced_at,omitzero"`
}

// Automation is one org automation (not RETIRED).
type Automation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// State is ACTIVE, DRAFT or PAUSED.
	State string `json:"state"`
	// TriggerRules are the rule ids its alert trigger names (D713).
	TriggerRules []string `json:"trigger_rules,omitzero"`
	HasContain   bool     `json:"has_contain,omitzero"`
	// Narrowed: the trigger also tests something other than the rule id, so
	// it may not fire on every alert of its rules (G0 M30 D948).
	Narrowed bool `json:"narrowed,omitzero"`
	// HubItem is the Hub item it was installed from, if any.
	HubItem string `json:"hub_item,omitzero"`
}

// Result is the newest result of one library scenario in the org's
// FINISHED library ranges.
type Result struct {
	ScenarioID string `json:"scenario_id"`
	Title      string `json:"title,omitzero"`
	RangeID    string `json:"range_id"`
	Digest     string `json:"digest"`
	// Verdict is PASS, FAIL, ERROR, SKIPPED or MISSING.
	Verdict string `json:"verdict"`
	// ObservedBy is SERVER, CLIENT, MIXED or NONE: who observed the steps.
	ObservedBy string    `json:"observed_by"`
	RecordedAt time.Time `json:"recorded_at"`
}

// AlertGroup counts the in-scope non-test alerts first seen in the window
// that carry exactly these technique ids.
type AlertGroup struct {
	Techniques []string `json:"techniques"`
	Count      int64    `json:"count"`
}

// DecisionCount counts real in-scope transactions in the window by decision
// and decisive reason code.
type DecisionCount struct {
	ReasonCode string `json:"reason_code"`
	// Decision is DENY or REQUIRE_APPROVAL.
	Decision string `json:"decision"`
	Count    int64  `json:"count"`
}

// OutcomeCount counts real in-scope executions in the window that a connector
// refused, by outcome code (G0 M30 D948, F-M28-2).
type OutcomeCount struct {
	Code  string `json:"code"`
	Count int64  `json:"count"`
}

// Inputs is every record the evaluator reads (D720: a pack carries them all,
// so an offline verifier derives the same map).
type Inputs struct {
	Framework   catalog.Framework `json:"framework"`
	Scope       Scope             `json:"scope"`
	EvaluatedAt time.Time         `json:"evaluated_at"`
	Editions    Editions          `json:"editions"`
	// ContentMode is OFF, WATCHING or ACTIVE.
	ContentMode string `json:"content_mode"`
	// MCPCatalogEnforcing is the MCP catalog mode ENFORCE.
	MCPCatalogEnforcing bool            `json:"mcp_catalog_enforcing"`
	Agents              []Agent         `json:"agents"`
	Routes              []Route         `json:"routes"`
	Rules               []Rule          `json:"rules"`
	Cursor              Cursor          `json:"cursor"`
	Automations         []Automation    `json:"automations"`
	Results             []Result        `json:"results"`
	Alerts              []AlertGroup    `json:"alerts"`
	Decisions           []DecisionCount `json:"decisions"`
	// Outcomes are the connector refusals counted by outcome code (D948).
	Outcomes []OutcomeCount `json:"outcomes,omitzero"`
}

// TechniqueMap is what PantherClaw maps to one technique or sub-technique
// (the evaluator's view of mapset.TechniqueMappings).
type TechniqueMap struct {
	Prevent      []string                  `json:"prevent,omitzero"`
	Rules        []string                  `json:"rules,omitzero"`
	Kinds        []string                  `json:"kinds,omitzero"`
	Scenarios    []string                  `json:"scenarios,omitzero"`
	Campaigns    []string                  `json:"campaigns,omitzero"`
	HubRules     []string                  `json:"hub_rules,omitzero"`
	HubPlaybooks []string                  `json:"hub_playbooks,omitzero"`
	Outside      *mapping.OutsideEntry     `json:"outside,omitzero"`
	Unaddressed  *mapping.UnaddressedEntry `json:"unaddressed,omitzero"`
}

// Scenario is what the evaluator reads of a library scenario.
type Scenario struct {
	Digest string            `json:"digest"`
	Why    map[string]string `json:"why,omitzero"`
}

// BuiltinRule is what the evaluator reads of a built-in rule that maps a
// technique.
type BuiltinRule struct {
	Title    string   `json:"title"`
	Business bool     `json:"business,omitzero"`
	Inputs   []string `json:"inputs"`
}

// Mapping is every mapping field the evaluator reads (D714c M2): a pack
// carries it so an offline verifier derives from it, not from its own build.
type Mapping struct {
	// Digest is mapset's digest of the whole mapping document.
	Digest     string                         `json:"digest"`
	Techniques map[string]TechniqueMap        `json:"techniques"`
	Controls   []mapping.PreventControl       `json:"controls"`
	Kinds      map[string]mapping.KindMapping `json:"kinds"`
	Builtins   map[string]BuiltinRule         `json:"builtins"`
	Scenarios  map[string]Scenario            `json:"scenarios"`
	// HubPlaybookRules are each Hub playbook's trigger rule ids.
	HubPlaybookRules map[string][]string `json:"hub_playbook_rules"`
}
