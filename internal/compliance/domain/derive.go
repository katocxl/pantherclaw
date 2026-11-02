// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/v2"
	"fmt"
	"slices"
)

// State is a control's state (D302). There are no others, and no total.
type State string

// The states.
const (
	// Evidenced: every record the control reads holds real activity in the
	// period, and no test it reads failed or went unexercised.
	Evidenced State = "EVIDENCED"
	// Partial: something holds, not all of it.
	Partial State = "PARTIAL"
	// Gap: nothing holds (F801, D306: not exercised is a gap, not a pass).
	Gap State = "GAP"
	// Stated: a person said so. PantherClaw has no evidence either way.
	Stated State = "STATED"
)

// Gap reasons.
const (
	ReasonOutsidePermission = "outside_permission" // the reader may not read this source (D312)
	ReasonNoRecords         = "no_records"         // no record in the period
	ReasonSimulatedOnly     = "simulated_only"     // only simulated activity (F630)
	ReasonNotExercised      = "not_exercised"      // no test ran it (D306)
	ReasonTestFailed        = "test_failed"        // a test of it did not hold
	ReasonReportedOnly      = "reported_only"      // a report no server record confirms
	ReasonNotStated         = "not_stated"         // no person stated it
	ReasonOutsideRecords    = "outside_records"    // no PantherClaw record reaches it
	ReasonLimit             = "limit"              // more results than a report reads
)

// Ref points at a record behind a count.
type Ref struct {
	// Type is transaction, approval, grant, coverage, range or campaign.
	Type string `json:"type"`
	ID   string `json:"id"`
	// Simulated is what the record itself says.
	Simulated bool `json:"simulated"`
}

// Ref types.
const (
	RefTransaction = "transaction"
	RefApproval    = "approval"
	RefGrant       = "grant"
	RefCoverage    = "coverage"
	RefRange       = "range"
	RefCampaign    = "campaign"
)

// SourceCount is what one source held in the period. Readable false means
// the reader may not read it: its counts are zero and say nothing.
type SourceCount struct {
	Source    Source `json:"source"`
	Readable  bool   `json:"readable"`
	Real      int64  `json:"real"`
	Simulated int64  `json:"simulated"`
	Refs      []Ref  `json:"refs"`
	// Truncated: the source held more than a report reads, so its counts are
	// of the newest results only.
	Truncated bool `json:"truncated,omitzero"`
}

// TestCount is one tag's results from one test source.
type TestCount struct {
	Tag    string `json:"tag"`
	Source Source `json:"source"`
	// Held: the server saw the boundary hold. Failed: it did not.
	Held   int64 `json:"held"`
	Failed int64 `json:"failed"`
	// Reported: a client or edge report no server record confirms.
	Reported int64 `json:"reported"`
	// NotExercised: the test ran but this part of it did not (error, skipped,
	// missing, not reached).
	NotExercised int64 `json:"not_exercised"`
	Refs         []Ref `json:"refs"`
}

// StatedCount is one stated field across the org's agents.
type StatedCount struct {
	Field    StatedField `json:"field"`
	Readable bool        `json:"readable"`
	Stated   int64       `json:"stated"`
	Unset    int64       `json:"unset"`
}

// Inputs is everything a report derives from.
type Inputs struct {
	Sources []SourceCount `json:"sources"`
	Tests   []TestCount   `json:"tests"`
	Stated  []StatedCount `json:"stated"`
}

// ControlGap is one thing a control lacks.
type ControlGap struct {
	Reason string `json:"reason"`
	Source Source `json:"source,omitzero"`
	Detail string `json:"detail"`
}

// ControlResult is one control of a report.
type ControlResult struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	State State  `json:"state"`
	// Evidence lists the sources that held something for this control.
	Evidence []Source `json:"evidence"`
	// SimulatedOnly: everything in Evidence is simulated.
	SimulatedOnly bool         `json:"simulated_only"`
	Gaps          []ControlGap `json:"gaps"`
}

// Evaluate derives every control of a framework from what the records hold.
// It is pure, so `pclaw verify` runs the same rule on the report's own inputs
// (HR-604). A source it is not given reads as unreadable.
func Evaluate(f Framework, in Inputs) ([]ControlResult, error) {
	if !f.Known() {
		return nil, fmt.Errorf("compliance: unknown framework %q", f)
	}
	table := Controls(f)
	out := make([]ControlResult, 0, len(table))
	for _, c := range table {
		out = append(out, evaluate(c, in))
	}
	return out, nil
}

func evaluate(c Control, in Inputs) ControlResult {
	r := ControlResult{ID: c.ID, Title: c.Title, Evidence: []Source{}, Gaps: []ControlGap{}}
	switch {
	case c.Stated != "":
		return stated(c, in, r)
	case c.Outside != "":
		r.State = Gap
		r.Gaps = append(r.Gaps, ControlGap{Reason: ReasonOutsideRecords, Detail: c.Outside})
		return r
	}
	real, simulated := records(c, in, &r)
	if tests(c, in, &r) {
		simulated = true
	}
	switch {
	case real && len(r.Gaps) == 0:
		r.State = Evidenced
	case real || simulated:
		r.State = Partial
	default:
		r.State = Gap
	}
	r.SimulatedOnly = simulated && !real
	return r
}

func stated(c Control, in Inputs, r ControlResult) ControlResult {
	i := slices.IndexFunc(in.Stated, func(s StatedCount) bool { return s.Field == c.Stated })
	switch {
	case i < 0 || !in.Stated[i].Readable:
		r.State = Gap
		r.Gaps = append(r.Gaps, ControlGap{
			Reason: ReasonOutsidePermission, Source: SourceStated, Detail: "you may not read what is stated about every agent",
		})
		return r
	case in.Stated[i].Stated == 0:
		r.State = Gap
		r.Gaps = append(r.Gaps, ControlGap{Reason: ReasonNotStated, Source: SourceStated, Detail: "no person has stated this for any agent"})
		return r
	}
	r.State = Stated
	r.Evidence = append(r.Evidence, SourceStated)
	if n := in.Stated[i].Unset; n > 0 {
		r.Gaps = append(r.Gaps, ControlGap{
			Reason: ReasonNotStated, Source: SourceStated, Detail: fmt.Sprintf("%d agents have no statement", n),
		})
	}
	return r
}

func sourceOf(in Inputs, s Source) (SourceCount, bool) {
	i := slices.IndexFunc(in.Sources, func(x SourceCount) bool { return x.Source == s })
	if i < 0 || !in.Sources[i].Readable {
		return SourceCount{}, false
	}
	return in.Sources[i], true
}

// records reads a control's production records and says whether any holds
// real activity and whether any holds only simulated activity.
func records(c Control, in Inputs, r *ControlResult) (real, simulated bool) {
	for _, s := range c.Records {
		n, ok := sourceOf(in, s)
		switch {
		case !ok:
			r.Gaps = append(r.Gaps, ControlGap{
				Reason: ReasonOutsidePermission, Source: s, Detail: "you may not read these records across the org",
			})
		case n.Real > 0:
			real = true
			r.Evidence = append(r.Evidence, s)
		case n.Simulated > 0:
			simulated = true
			r.Evidence = append(r.Evidence, s)
			r.Gaps = append(r.Gaps, ControlGap{
				Reason: ReasonSimulatedOnly, Source: s, Detail: "only simulated activity in the period: it does not count as real use",
			})
		default:
			r.Gaps = append(r.Gaps, ControlGap{Reason: ReasonNoRecords, Source: s, Detail: "no record in the period"})
		}
	}
	return real, simulated
}

// tests reads a control's tagged test results and says whether anything was
// exercised. They are one kind of evidence, whichever source ran them: a
// range or a campaign that held is enough, and a failure in either stays a
// gap.
func tests(c Control, in Inputs, r *ControlResult) bool {
	if len(c.Tests) == 0 {
		return false
	}
	var held, failed, reported, notExercised int64
	seen := map[Source]bool{}
	for _, t := range in.Tests {
		if !slices.Contains(c.Tests, t.Tag) {
			continue
		}
		held += t.Held
		failed += t.Failed
		reported += t.Reported
		notExercised += t.NotExercised
		if t.Held > 0 {
			seen[t.Source] = true
		}
	}
	for _, s := range TestSources() {
		if seen[s] {
			r.Evidence = append(r.Evidence, s)
		}
		n, ok := sourceOf(in, s)
		switch {
		case !ok:
			r.Gaps = append(r.Gaps, ControlGap{
				Reason: ReasonOutsidePermission, Source: s, Detail: "you may not read these results across the org",
			})
		case n.Truncated:
			// An older failure could be among what was not read.
			r.Gaps = append(r.Gaps, ControlGap{
				Reason: ReasonLimit, Source: s, Detail: "the period holds more results than a report reads: narrow it",
			})
		}
	}
	exercised := held > 0 || reported > 0
	if len(c.Records) == 0 && exercised {
		// Nothing but tests reads this control: no real use is in evidence.
		r.Gaps = append(r.Gaps, ControlGap{
			Reason: ReasonSimulatedOnly, Detail: "only simulated tests read this control: they do not count as real use",
		})
	}
	if failed > 0 {
		r.Gaps = append(r.Gaps, ControlGap{
			Reason: ReasonTestFailed, Detail: fmt.Sprintf("%d tagged test results did not hold", failed),
		})
	}
	if reported > 0 {
		r.Gaps = append(r.Gaps, ControlGap{
			Reason: ReasonReportedOnly, Detail: fmt.Sprintf("%d tagged results were reported, and no server record confirms them", reported),
		})
	}
	switch {
	case notExercised > 0:
		r.Gaps = append(r.Gaps, ControlGap{
			Reason: ReasonNotExercised, Detail: fmt.Sprintf("%d tagged results did not run to an end", notExercised),
		})
	case !exercised && failed == 0:
		r.Gaps = append(r.Gaps, ControlGap{Reason: ReasonNotExercised, Detail: "no tagged test ran in the period"})
	}
	return exercised
}

// Format identifies compliance.json.
const Format = "pantherclaw.compliance/v1"

// Report is compliance.json: what a pack of scope compliance holds and what
// GetFrameworkCoverage returns. It holds no timestamp of its own, so the same
// records under the same parameters give the same bytes (D303).
type Report struct {
	Format        string          `json:"format"`
	Org           string          `json:"org"`
	Framework     Framework       `json:"framework"`
	CatalogDigest string          `json:"catalog_digest"`
	PeriodStart   string          `json:"period_start"`
	PeriodEnd     string          `json:"period_end"`
	Split         Split           `json:"split"`
	Inputs        Inputs          `json:"inputs"`
	Controls      []ControlResult `json:"controls"`
	Statement     string          `json:"statement"`
}

// Decode decodes compliance.json strictly.
func Decode(b []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(b, &r, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("compliance report: %w", err)
	}
	if r.Format != Format {
		return nil, fmt.Errorf("compliance report: format %.64q", r.Format)
	}
	return &r, nil
}

// Split is the header's real and simulated activity (F630, D312).
type Split struct {
	Real      int64 `json:"real"`
	Simulated int64 `json:"simulated"`
}

// SplitOf adds up what the record sources held.
func SplitOf(in Inputs) Split {
	var s Split
	for _, c := range in.Sources {
		if slices.Contains(RecordSources(), c.Source) {
			s.Real += c.Real
			s.Simulated += c.Simulated
		}
	}
	return s
}
