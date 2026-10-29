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

// Origins (G0 M17 D124): the server derives a scenario's origin from its
// id, never from the runner. RT-### is the PantherClaw library, CX-### is
// customer-authored.
const (
	OriginLibrary  = "library"
	OriginCustomer = "customer"
)

// OriginOf returns the origin of a scenario id.
func OriginOf(id string) string {
	if strings.HasPrefix(id, "CX-") {
		return OriginCustomer
	}
	return OriginLibrary
}

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
	// StepCount is how many steps the scenario has: a PASS records exactly
	// that many.
	StepCount int
	// Origin is OriginOf(ID), set by the server.
	Origin string
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
	// Origin is every scenario's origin: a range is all library or all
	// customer (D126).
	Origin    string
	Scenarios []Scenario
	Versions  Versions
	Baseline  *ids.UUID
	State     State
	Started   time.Time
	Finished  *time.Time
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
	// Kind is the scenario step kind and ProbeKind the result of the cited
	// probe report the step is based on.
	Kind      string
	ProbeKind string
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
	Kind        string
	ProbeKind   string
}

// TransactionRecord is what the server's own records say about a
// transaction a step names.
type TransactionRecord struct {
	ID        ids.UUID
	Agent     ids.UUID
	Simulated bool
	Created   time.Time
	Decision  string // ALLOW, ALLOW_WITH_OBLIGATIONS, REQUIRE_APPROVAL, REQUIRE_STEP_UP, DENY, CANNOT_AUTHORIZE
	// Reason is the decision's decisive reason; Reasons are all of them,
	// from its receipt.
	Reason      string
	Reasons     []string
	EffectState string // empty until an effect was observed
}

// ProbeRecord is what the signed sandbox probe records say about a probe
// report a step names (HR-215).
type ProbeRecord struct {
	ID       ids.UUID
	Agent    ids.UUID
	Recorded time.Time
	// Results maps each probe result's name to what it observed ("blocked",
	// "reachable" or "error").
	Results map[string]string
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

// DerivesFromTransaction reports whether the server derives a step's
// observation from the transaction it cites: only agent.* and wait steps
// that expect a decision or an effect outcome (D34). Every other step
// (person.*, check.receipt, target.replay, server.read, and REFUSED,
// TARGET_REFUSED, BLOCKED or NOT_FOUND expectations) is observed by the
// runner; a transaction it cites is then only a reference.
func DerivesFromTransaction(kind string, expect Expect) bool {
	if !strings.HasPrefix(kind, "agent.") && kind != "wait" {
		return false
	}
	switch expect.Outcome {
	case OutcomeAllow, OutcomeDeny, OutcomeHold, OutcomeCannotAuthorize, OutcomeConfirmed, OutcomeUnknown:
		return true
	}
	return false
}

// Derived is an observation the server derived from its own records.
type Derived struct {
	Observed Expect
	// Reasons are every reason the observation accepts for a claim or an
	// expectation (all reasons of a decision).
	Reasons []string
}

// Observe derives the outcome and reason a transaction's record supports.
// Effect outcomes (CONFIRMED, UNKNOWN) come from the effect state when the
// step expects one; every other outcome from the decision. An expected
// reason that is any reason of the decision is the observed one; otherwise
// the decisive reason is. The server knows no gateway or target refusal
// code, so Code is always empty.
func (t TransactionRecord) Observe(expect Expect) Derived {
	d := Derived{Reasons: slices.Clone(t.Reasons)}
	if t.Reason != "" && !slices.Contains(d.Reasons, t.Reason) {
		d.Reasons = append(d.Reasons, t.Reason)
	}
	reason := t.Reason
	if expect.Reason != "" && slices.Contains(d.Reasons, expect.Reason) {
		reason = expect.Reason
	}
	if expect.Outcome == OutcomeConfirmed || expect.Outcome == OutcomeUnknown {
		switch t.EffectState {
		case "CONFIRMED":
			d.Observed = Expect{Outcome: OutcomeConfirmed, Reason: reason}
			return d
		case "UNKNOWN":
			d.Observed = Expect{Outcome: OutcomeUnknown, Reason: reason}
			return d
		}
	}
	d.Observed.Reason = reason
	switch t.Decision {
	case "ALLOW", "ALLOW_WITH_OBLIGATIONS":
		d.Observed.Outcome = OutcomeAllow
	case "REQUIRE_APPROVAL", "REQUIRE_STEP_UP":
		d.Observed.Outcome = OutcomeHold
	case "DENY":
		d.Observed.Outcome = OutcomeDeny
	default:
		d.Observed.Outcome = OutcomeCannotAuthorize
	}
	return d
}

// Observe is the probe record's observation of one probe's result: BLOCKED
// when it was blocked, ALLOW when it got through. ok is false when the
// report has no such result, or it errored.
func (p ProbeRecord) Observe(kind string) (d Derived, ok bool) {
	switch p.Results[kind] {
	case "blocked":
		return Derived{Observed: Expect{Outcome: OutcomeBlocked}}, true
	case "reachable":
		return Derived{Observed: Expect{Outcome: OutcomeAllow}}, true
	}
	return Derived{}, false
}

// MatchesIgnoringCode reports whether the expectation is met by observed, ignoring the
// code: a derived step has no code (the server knows none).
func (e Expect) MatchesIgnoringCode(observed Expect) bool {
	e.Code = ""
	return e.Matches(observed)
}

// Resolve turns the runner's step into the recorded one. derived is the
// observation the server derived from its own records, or nil when the step
// is the runner's to observe (it names no record, or none the server
// derives from): then the step is observed_by CLIENT and the claim stands.
// Otherwise the server's value wins; a claim that differs on the outcome or
// names a reason the decision does not have marks the step MISMATCH
// (T-091). The expectation's code is ignored on a derived step.
func Resolve(in StepInput, derived *Derived) Step {
	st := Step{
		ID: in.ID, Expect: in.Expect, Observed: in.Observed, ObservedBy: Client,
		Transaction: in.Transaction, Probe: in.Probe, Decisive: in.Decisive, Kind: in.Kind, ProbeKind: in.ProbeKind,
	}
	if derived == nil {
		st.Matched = in.Expect.Matches(st.Observed)
		return st
	}
	st.ObservedBy, st.Observed = Server, derived.Observed
	reasonOK := in.Observed.Reason == "" || in.Observed.Reason == derived.Observed.Reason || slices.Contains(derived.Reasons, in.Observed.Reason)
	if in.Observed.Outcome != derived.Observed.Outcome || !reasonOK {
		st.Mismatch, st.Claimed = true, in.Observed
	}
	st.Matched = in.Expect.MatchesIgnoringCode(st.Observed)
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
