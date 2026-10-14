// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the server-side rules of adversarial ranges (G0 M12,
// HR-224, T-091): what a range and its recorded results are, how a step's
// observation is derived from the server's own records instead of the
// runner's claim, and how a scenario's verdict is recomputed from its steps.
// It has no I/O.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// State is where a range is in its life.
type State string

// States.
const (
	Running   State = "RUNNING"
	Finished  State = "FINISHED"
	Abandoned State = "ABANDONED"
)

// AbandonAfter is how long a range may run before the janitor abandons it.
const AbandonAfter = 24 * time.Hour

// Verdict is a scenario's verdict. Missing is server-only.
type Verdict string

// Verdicts.
const (
	Pass    Verdict = "PASS"
	Fail    Verdict = "FAIL"
	Errored Verdict = "ERROR"
	Skipped Verdict = "SKIPPED"
	Missing Verdict = "MISSING"
)

// ObservedBy says who observed a step's result.
type ObservedBy string

// Observers.
const (
	Server ObservedBy = "SERVER"
	Client ObservedBy = "CLIENT"
)

// Outcomes a step may expect or observe.
const (
	OutcomeAllow           = "ALLOW"
	OutcomeDeny            = "DENY"
	OutcomeHold            = "HOLD"
	OutcomeCannotAuthorize = "CANNOT_AUTHORIZE"
	OutcomeRefused         = "REFUSED"
	OutcomeBlocked         = "BLOCKED"
	OutcomeTargetRefused   = "TARGET_REFUSED"
	OutcomeNotFound        = "NOT_FOUND"
	OutcomeConfirmed       = "CONFIRMED"
	OutcomeUnknown         = "UNKNOWN"
)

// Categories and tiers.
const (
	TierCommunity = "community"
	TierBusiness  = "business"
)

// Categories lists the report's categories in report order.
var Categories = []string{"functional", "boundary", "recovery", "explanation"}

// Statement is what every assurance report says it is (D13).
const Statement = "Tested-control evidence against simulated targets. Not a compliance certification."

// Expect is what a step expects or observed. For an expectation an empty
// Reason or Code is not checked; for an observation it means none.
type Expect struct {
	Outcome string
	Reason  string
	Code    string
}

// Matches reports whether observed meets the expectation.
func (e Expect) Matches(observed Expect) bool {
	return e.Outcome == observed.Outcome &&
		(e.Reason == "" || e.Reason == observed.Reason) &&
		(e.Code == "" || e.Code == observed.Code)
}

// Scenario is a scenario a range declared at its start.
type Scenario struct {
	ID       string
	Digest   string
	Tier     string
	Category string
	Suite    string
	Title    string
}

// SetDigest is the SHA-256 (hex) over the sorted "id:digest" lines of the
// declared scenarios (D9).
func SetDigest(set []Scenario) string {
	lines := make([]string, 0, len(set))
	for _, s := range set {
		lines = append(lines, s.ID+":"+s.Digest+"\n")
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:])
}

// VersionRef names a policy or package version in force when a range
// started.
type VersionRef struct {
	Name    string
	Version string
	ID      string
}

// Versions are the policy and package versions the range's agent ran under
// when the range started, as the server recorded them.
type Versions struct {
	Policies []VersionRef
	Packages []VersionRef
}

// Range is one range.
type Range struct {
	ID            ids.UUID
	Agent         ids.UUID
	StartedBy     string
	RunnerVersion string
	SetDigest     string
	Scenarios     []Scenario
	Versions      Versions
	Baseline      *ids.UUID
	State         State
	Started       time.Time
	Finished      *time.Time
}

// Step is one recorded step.
type Step struct {
	ID         string
	Expect     Expect
	Observed   Expect
	ObservedBy ObservedBy
	// Mismatch: the runner's claim differed from the server's records and
	// was overwritten with them; Claimed holds the claim.
	Mismatch bool
	Claimed  Expect
	Matched  bool
	// Transaction and Probe are the records the step names, when it does.
	Transaction *ids.UUID
	Probe       *ids.UUID
	Decisive    string
}

// Result is one scenario's recorded result.
type Result struct {
	Scenario Scenario
	Verdict  Verdict
	// Claimed is the runner's verdict when it differs from Verdict.
	Claimed  Verdict
	Steps    []Step
	Recorded time.Time
}

// Counts counts results by verdict.
type Counts struct{ Pass, Fail, Error, Skipped, Missing int }

// Count counts results by verdict.
func Count(results []Result) Counts {
	var c Counts
	for _, r := range results {
		switch r.Verdict {
		case Pass:
			c.Pass++
		case Fail:
			c.Fail++
		case Errored:
			c.Error++
		case Skipped:
			c.Skipped++
		case Missing:
			c.Missing++
		}
	}
	return c
}

// StepInput is a step as the runner claimed it.
type StepInput struct {
	ID          string
	Expect      Expect
	Observed    Expect
	Transaction *ids.UUID
	Probe       *ids.UUID
	Decisive    string
}

// TransactionRecord is what the server's own records say about a
// transaction a step names.
type TransactionRecord struct {
	ID          ids.UUID
	Agent       ids.UUID
	Simulated   bool
	Created     time.Time
	Decision    string // ALLOW, ALLOW_WITH_OBLIGATIONS, REQUIRE_APPROVAL, REQUIRE_STEP_UP, DENY, CANNOT_AUTHORIZE
	Reason      string
	EffectState string // empty until an effect was observed
}

// ProbeRecord is what the signed sandbox probe records say about a probe
// report a step names (HR-215).
type ProbeRecord struct {
	ID       ids.UUID
	Agent    ids.UUID
	Recorded time.Time
	// Outcome is the step outcome the verified report supports (BLOCKED
	// when the probe's attempt was blocked, otherwise ALLOW).
	Outcome string
}

// Belongs reports whether the transaction may back a step of a range of
// agent that started at start: it is simulated, the range agent's, and was
// created after the range started (HR-224).
func (t TransactionRecord) Belongs(agent ids.UUID, start time.Time) bool {
	return t.Simulated && t.Agent == agent && !t.Created.Before(start)
}

// Belongs reports whether the probe report may back a step of a range of
// agent that started at start.
func (p ProbeRecord) Belongs(agent ids.UUID, start time.Time) bool {
	return p.Agent == agent && !p.Recorded.Before(start)
}

// Observe derives the outcome and reason a transaction's record supports.
// Effect outcomes (CONFIRMED, UNKNOWN) come from the effect state when the
// step expects one; every other outcome from the decision. The server
// knows no gateway or target refusal code, so Code is always empty.
func (t TransactionRecord) Observe(expect Expect) Expect {
	if expect.Outcome == OutcomeConfirmed || expect.Outcome == OutcomeUnknown {
		switch t.EffectState {
		case "CONFIRMED":
			return Expect{Outcome: OutcomeConfirmed, Reason: t.Reason}
		case "UNKNOWN":
			return Expect{Outcome: OutcomeUnknown, Reason: t.Reason}
		}
	}
	out := Expect{Reason: t.Reason}
	switch t.Decision {
	case "ALLOW", "ALLOW_WITH_OBLIGATIONS":
		out.Outcome = OutcomeAllow
	case "REQUIRE_APPROVAL", "REQUIRE_STEP_UP":
		out.Outcome = OutcomeHold
	case "DENY":
		out.Outcome = OutcomeDeny
	default:
		out.Outcome = OutcomeCannotAuthorize
	}
	return out
}

// Observe is the probe record's observation.
func (p ProbeRecord) Observe() Expect { return Expect{Outcome: p.Outcome} }

// Resolve turns the runner's step into the recorded one. server is the
// observation the server derived from its own records, or nil when the step
// names no record (or none the server can read): then the step is
// observed_by CLIENT and the claim stands. Otherwise the server's value
// wins; a claim that differs on the outcome, on a reason it names, or by
// naming a code the server has none for marks the step MISMATCH (T-091).
func Resolve(in StepInput, server *Expect) Step {
	st := Step{
		ID: in.ID, Expect: in.Expect, Observed: in.Observed, ObservedBy: Client,
		Transaction: in.Transaction, Probe: in.Probe, Decisive: in.Decisive,
	}
	if server != nil {
		st.ObservedBy, st.Observed = Server, *server
		if in.Observed.Outcome != server.Outcome ||
			(in.Observed.Reason != "" && in.Observed.Reason != server.Reason) ||
			in.Observed.Code != server.Code {
			st.Mismatch, st.Claimed = true, in.Observed
		}
	}
	st.Matched = in.Expect.Matches(st.Observed)
	return st
}

// Derive recomputes a scenario's verdict from its steps. A claimed PASS or
// FAIL is replaced by what the steps say (PASS when every step matched its
// expectation, with the server's observations); ERROR and SKIPPED are the
// runner's to report and kept. A claimed PASS or FAIL with no steps cannot
// be derived: ok is false.
func Derive(claimed Verdict, steps []Step) (v Verdict, ok bool) {
	switch claimed {
	case Errored, Skipped:
		return claimed, true
	case Pass, Fail:
		if len(steps) == 0 {
			return "", false
		}
		for _, s := range steps {
			if !s.Matched {
				return Fail, true
			}
		}
		return Pass, true
	case Missing:
		// The server's alone.
	}
	return "", false
}

// Finalize returns the results of a finished range: every recorded result
// and a MISSING one for each declared scenario never recorded, in the
// declared order.
func Finalize(declared []Scenario, recorded []Result, at time.Time) []Result {
	by := map[string]Result{}
	for _, r := range recorded {
		by[r.Scenario.ID] = r
	}
	out := make([]Result, 0, len(declared))
	for _, s := range declared {
		if r, ok := by[s.ID]; ok {
			out = append(out, r)
			continue
		}
		out = append(out, Result{Scenario: s, Verdict: Missing, Recorded: at})
	}
	return out
}
