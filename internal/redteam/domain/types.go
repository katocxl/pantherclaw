// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the adversarial range's scenario model (HR-223): the
// strict scenario file format, its validation against a closed step
// catalogue, scenario digests, step results and the baseline comparison
// (HR-226). It is pure data and rules; running a scenario is internal/redteam/app.
package domain

import "encoding/json/jsontext"

// APIVersion is the only scenario format version.
const APIVersion = "pantherclaw.range/v1"

// Limits (D9).
const (
	MaxFileBytes  = 64 << 10
	MaxSteps      = 40
	MaxStringLen  = 4 << 10
	MaxArgsDepth  = 8
	MaxTitleLen   = 200
	MaxWaitSecond = 10
)

// Scenario is one attack scenario file.
type Scenario struct {
	APIVersion  string   `json:"apiVersion"`
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Suite       string   `json:"suite"`
	Tier        string   `json:"tier"`
	Attacker    string   `json:"attacker"`
	Threats     []string `json:"threats"`
	Rules       []string `json:"rules"`
	Requires    []string `json:"requires,omitempty"`
	HarnessOnly bool     `json:"harness_only,omitzero"`
	Steps       []Step   `json:"steps"`
}

// Step is one action of a scenario. With holds the kind's arguments as JSON;
// Validate decodes it strictly per kind.
type Step struct {
	ID     string            `json:"id"`
	Do     string            `json:"do"`
	With   jsontext.Value    `json:"with,omitempty"`
	Save   map[string]string `json:"save,omitempty"`
	Expect Expect            `json:"expect,omitzero"`
}

// Expect is what a step must observe. Empty fields are not checked.
type Expect struct {
	Outcome         Outcome `json:"outcome,omitempty"`
	Reason          string  `json:"reason,omitempty"`
	Code            string  `json:"code,omitempty"`
	SameDecisionAs  string  `json:"same_decision_as,omitempty"`
	DecisiveControl string  `json:"decisive_control,omitempty"`
}

// Outcome is what a step observed.
type Outcome string

// The closed set of outcomes.
const (
	OutcomeAllow           Outcome = "ALLOW"
	OutcomeDeny            Outcome = "DENY"
	OutcomeHold            Outcome = "HOLD"
	OutcomeCannotAuthorize Outcome = "CANNOT_AUTHORIZE"
	OutcomeRefused         Outcome = "REFUSED"
	OutcomeBlocked         Outcome = "BLOCKED"
	OutcomeTargetRefused   Outcome = "TARGET_REFUSED"
	OutcomeNotFound        Outcome = "NOT_FOUND"
	OutcomeConfirmed       Outcome = "CONFIRMED"
	OutcomeUnknown         Outcome = "UNKNOWN"
)

var outcomes = map[Outcome]bool{
	OutcomeAllow: true, OutcomeDeny: true, OutcomeHold: true, OutcomeCannotAuthorize: true,
	OutcomeRefused: true, OutcomeBlocked: true, OutcomeTargetRefused: true,
	OutcomeNotFound: true, OutcomeConfirmed: true, OutcomeUnknown: true,
}

// Valid reports whether o is in the closed set.
func (o Outcome) Valid() bool { return outcomes[o] }

// Verdict is the result of a scenario.
type Verdict string

// The verdicts.
const (
	VerdictPass    Verdict = "PASS"
	VerdictFail    Verdict = "FAIL"
	VerdictError   Verdict = "ERROR"
	VerdictSkipped Verdict = "SKIPPED"
)

// Observation is what a driver saw for one step.
type Observation struct {
	Outcome       Outcome
	Reason, Code  string
	DecisionHash  string
	TransactionID string
	ProbeReportID string
	Response      []byte // JSON, at most 64 KiB
	Detail        string
}

// MaxResponseBytes bounds Observation.Response.
const MaxResponseBytes = 64 << 10

// StepResult is one executed step with its comparison.
type StepResult struct {
	StepID   string
	Expect   Expect
	Observed Observation
	Matched  bool
	Mismatch string
}

// Result is the outcome of one scenario.
type Result struct {
	ScenarioID string
	Digest     string
	Verdict    Verdict
	Detail     string
	Steps      []StepResult
}
