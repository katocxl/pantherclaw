// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pack

import (
	"encoding/json/v2"
	"fmt"
)

// AssuranceFormat identifies assurance.json (G0 M12, D13, HR-224).
const AssuranceFormat = "pantherclaw.assurance/v1"

// AssurancePath is where a range pack holds its report.
const AssurancePath = "assurance.json"

// ExpectedStatement is the sentence the manifest of a pack of this scope
// must carry: the fixed one, or the range's (HR-224).
func (s Scope) ExpectedStatement() string {
	if s.Kind == ScopeRange {
		return RangeStatement
	}
	return Statement
}

// AssuranceExpect is what a step expected or observed.
type AssuranceExpect struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitzero"`
	Code    string `json:"code,omitzero"`
}

// AssuranceStep is one step of a scenario.
type AssuranceStep struct {
	ID       string          `json:"id"`
	Expect   AssuranceExpect `json:"expect"`
	Observed AssuranceExpect `json:"observed"`
	// ObservedBy is SERVER (read from the server's own records) or CLIENT
	// (the runner's word, which the report cannot confirm).
	ObservedBy string `json:"observed_by"`
	// Mismatch: the runner claimed otherwise; Claimed is the claim.
	Mismatch    bool             `json:"mismatch,omitzero"`
	Claimed     *AssuranceExpect `json:"claimed,omitzero"`
	Matched     bool             `json:"matched"`
	Decisive    string           `json:"decisive_control,omitzero"`
	Transaction string           `json:"transaction,omitzero"`
	Probe       string           `json:"probe_report,omitzero"`
	Kind        string           `json:"kind"`
	ProbeKind   string           `json:"probe_kind,omitzero"`
}

// AssuranceScenario is one scenario's recorded result.
type AssuranceScenario struct {
	ID       string `json:"id"`
	Title    string `json:"title,omitzero"`
	Digest   string `json:"digest"`
	Category string `json:"category"`
	Tier     string `json:"tier"`
	Suite    string `json:"suite"`
	// StepCount is how many steps the scenario has; a PASS records all.
	StepCount int    `json:"step_count"`
	Verdict   string `json:"verdict"`
	// ClaimedVerdict is the runner's verdict when the server's differs.
	ClaimedVerdict string          `json:"claimed_verdict,omitzero"`
	Steps          []AssuranceStep `json:"steps"`
}

// AssuranceCounts counts scenarios by verdict.
type AssuranceCounts struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Error   int `json:"error"`
	Skipped int `json:"skipped"`
	Missing int `json:"missing"`
}

// AssuranceMismatch names a step whose claim the server overwrote.
type AssuranceMismatch struct {
	Scenario string `json:"scenario"`
	Step     string `json:"step"`
}

// AssuranceVersion is a policy or package version in force when the range
// started.
type AssuranceVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	ID      string `json:"id"`
}

// Assurance is assurance.json: the report of one range.
type Assurance struct {
	Format            string `json:"format"`
	Range             string `json:"range"`
	Org               string `json:"org"`
	Agent             string `json:"agent"`
	Started           string `json:"started_at"`
	Finished          string `json:"finished_at"`
	RunnerVersion     string `json:"runner_version"`
	ScenarioSetDigest string `json:"scenario_set_digest"`
	BaselineRange     string `json:"baseline_range,omitzero"`
	// PolicyVersions and PackageVersions are what the agent ran under when
	// the range started.
	PolicyVersions  []AssuranceVersion  `json:"policy_versions"`
	PackageVersions []AssuranceVersion  `json:"package_versions"`
	Scenarios       []AssuranceScenario `json:"scenarios"`
	// Totals counts all scenarios; Categories counts them per category
	// (functional, boundary, recovery, explanation).
	Totals     AssuranceCounts            `json:"totals"`
	Categories map[string]AssuranceCounts `json:"categories"`
	// Mismatches lists every step whose claim the server overwrote.
	Mismatches []AssuranceMismatch `json:"mismatches"`
	Statement  string              `json:"statement"`
}

// DecodeAssurance decodes assurance.json strictly.
func DecodeAssurance(b []byte) (*Assurance, error) {
	var a Assurance
	if err := json.Unmarshal(b, &a, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("assurance report: %v", err)
	}
	if a.Format != AssuranceFormat || a.Range == "" || a.Org == "" || a.Agent == "" {
		return nil, invalid("assurance report: format %q, or it names no range, org or agent", truncate(fmt.Sprint(a.Format)))
	}
	return &a, nil
}
