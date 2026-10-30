// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package outcomes

import (
	"math"
	"slices"
	"time"
)

// Why a case or a window was not measured.
const (
	ReasonCollectionNotStarted = "COLLECTION_NOT_STARTED"
	ReasonNoMeasurableCase     = "NO_MEASURABLE_CASE"
	ReasonNotRecorded          = "NOT_RECORDED"

	ReasonEnrolledBeforeTracking = "ENROLLED_BEFORE_TRACKING"
	ReasonOpenNoEnforcedDecision = "OPEN_NO_ENFORCED_DECISION"
	ReasonRouteNeverEnforced     = "ROUTE_NEVER_ENFORCED"

	ReasonUnread = "UNREAD"

	ReasonOpenNotContained      = "OPEN_NOT_CONTAINED"
	ReasonRequestedNotConfirmed = "REQUESTED_NOT_CONFIRMED"
	ReasonFailedOrUnsupported   = "FAILED_OR_UNSUPPORTED"
	ReasonDeclaredNotConfirmed  = "DECLARED_NOT_CONFIRMED"
	ReasonNoContainmentNeeded   = "NO_CONTAINMENT_NEEDED"
	ReasonConfirmedBeforeOpened = "CONFIRMED_BEFORE_OPENED"
	ReasonGrantRevokeNotLinked  = "GRANT_REVOKE_NOT_LINKED"

	ReasonOpenWaiting    = "OPEN_WAITING"
	ReasonEndedUndecided = "ENDED_UNDECIDED"

	ReasonFollowUpRunning = "FOLLOW_UP_RUNNING"

	ReasonEmergencyChange       = "EMERGENCY_CHANGE"
	ReasonStageHistoryMissing   = "STAGE_HISTORY_MISSING"
	ReasonRolloutHistoryUnknown = "ROLLOUT_HISTORY_NOT_RECORDED"
)

// Windows are the lengths the rollup samples, in days. Percentiles of one
// window cannot be built from shorter ones, so each is computed in full.
var Windows = []int{7, 30}

// Window is the half-open range [Start, End), whole UTC days.
type Window struct {
	Start, End time.Time
}

// windowOf is the days-long window ending at end.
func windowOf(end time.Time, days int) Window {
	return Window{Start: end.AddDate(0, 0, -days), End: end}
}

func (w Window) holds(t time.Time) bool { return !t.Before(w.Start) && t.Before(w.End) }

// Reason is why some cases were not measured.
type Reason struct {
	Code             string   `json:"code"`
	Count            int64    `json:"count"`
	OldestAgeSeconds *float64 `json:"oldest_age_seconds,omitempty"`
}

// Sample is one metric, dimension and window. Without a measured case it
// has no value (HR-537): P50, P90 and Share stay nil, never 0.
type Sample struct {
	Metric     string
	Dimension  string
	Window     Window
	P50, P90   *float64
	Share      *float64
	Measured   int64
	Unmeasured int64
	Reasons    []Reason
	// Why is why the whole window has no value, when no case says so.
	Why string
}

// Collected reports whether the sample has a value.
func (s Sample) Collected() bool { return s.Measured > 0 }

// finish totals the reasons and says why a sample without a value has none.
// Reasons is never nil: the column holds a JSON array, never null.
func (s Sample) finish() Sample {
	s.Reasons = slices.DeleteFunc(append([]Reason{}, s.Reasons...), func(r Reason) bool { return r.Count == 0 })
	s.Unmeasured = 0
	for _, r := range s.Reasons {
		s.Unmeasured += r.Count
	}
	if !s.Collected() && len(s.Reasons) == 0 {
		if s.Why == "" {
			s.Why = ReasonNoMeasurableCase
		}
		s.Reasons = []Reason{{Code: s.Why}}
	}
	return s
}

// duration is a distribution of seconds; nil seconds is not collected.
func duration(metric string, w Window, seconds []float64, reasons []Reason) Sample {
	s := Sample{Metric: metric, Window: w, Reasons: reasons, Measured: int64(len(seconds))}
	if len(seconds) > 0 {
		sorted := slices.Sorted(slices.Values(seconds))
		p50, p90 := percentile(sorted, 0.5), percentile(sorted, 0.9)
		s.P50, s.P90 = &p50, &p90
	}
	return s.finish()
}

// share is part over whole; a whole of 0 is not collected, never 0%.
func share(metric, dim string, w Window, part, whole int64, reasons []Reason) Sample {
	s := Sample{Metric: metric, Dimension: dim, Window: w, Reasons: reasons, Measured: whole}
	if whole > 0 {
		v := float64(part) / float64(whole)
		s.Share = &v
	}
	return s.finish()
}

// notCollected is a sample that says only why it has no value.
func notCollected(metric, dim string, w Window, code string) Sample {
	return Sample{Metric: metric, Dimension: dim, Window: w, Why: code}
}

// percentile interpolates linearly, as percentile_cont does; sorted is
// sorted and not empty.
func percentile(sorted []float64, p float64) float64 {
	rank := p * float64(len(sorted)-1)
	lo, hi := int(math.Floor(rank)), int(math.Ceil(rank))
	return sorted[lo] + (sorted[hi]-sorted[lo])*(rank-float64(lo))
}

// reasonWith is a reason with its oldest case's age.
func reasonWith(code string, n int64, oldest float64) Reason {
	return Reason{Code: code, Count: n, OldestAgeSeconds: &oldest}
}

// tally counts cases by reason and keeps the oldest age of each.
type tally struct {
	order []string
	by    map[string]*Reason
}

func (t *tally) add(code string, age time.Duration) {
	if t.by == nil {
		t.by = map[string]*Reason{}
	}
	r, ok := t.by[code]
	if !ok {
		r = &Reason{Code: code}
		t.by[code] = r
		t.order = append(t.order, code)
	}
	r.Count++
	if a := age.Seconds(); r.OldestAgeSeconds == nil || a > *r.OldestAgeSeconds {
		r.OldestAgeSeconds = &a
	}
}

func (t *tally) reasons() []Reason {
	out := make([]Reason, 0, len(t.order))
	for _, c := range t.order {
		out = append(out, *t.by[c])
	}
	return out
}

// JourneyCase is one tracked agent (M1).
type JourneyCase struct {
	Enrolled time.Time
	Enforced *time.Time
	// Observed: it has monitor-mode decisions only.
	Observed bool
}

// journeys classifies tracked agents for a window: an agent counts when its
// first enforced decision falls inside it, and is open while it has none by
// the window's end.
func journeys(w Window, cases []JourneyCase) ([]float64, []Reason) {
	var seconds []float64
	var open tally
	for _, c := range cases {
		switch {
		case c.Enforced != nil && w.holds(*c.Enforced):
			seconds = append(seconds, c.Enforced.Sub(c.Enrolled).Seconds())
		case !c.Enrolled.Before(w.End):
		case c.Enforced != nil && c.Enforced.Before(w.Start):
		case c.Observed:
			open.add(ReasonRouteNeverEnforced, w.End.Sub(c.Enrolled))
		default:
			open.add(ReasonOpenNoEnforcedDecision, w.End.Sub(c.Enrolled))
		}
	}
	return seconds, open.reasons()
}

// Episode is one case, or one incident without a case (M3).
type Episode struct {
	Started time.Time
	// Confirmed is its first confirmed containment. Nothing else sets it:
	// a request or a declaration leaves it nil (HR-538).
	Confirmed           *time.Time
	OpenRequests        int64
	Failed              int64
	Declared            bool
	NoContainmentNeeded bool
	Ended               bool
}

// episodes classifies episodes for a window: one counts when its containment
// was confirmed inside it. One still unconfirmed at the window's end is
// reported by what stands in the way, if it began in the window or stays open.
func episodes(w Window, all []Episode) ([]float64, []Reason) {
	var seconds []float64
	var out tally
	for _, e := range all {
		switch {
		case e.Confirmed != nil && w.holds(*e.Confirmed):
			if e.Confirmed.Before(e.Started) {
				out.add(ReasonConfirmedBeforeOpened, 0)
				continue
			}
			seconds = append(seconds, e.Confirmed.Sub(e.Started).Seconds())
		case !e.Started.Before(w.End):
		case e.Confirmed != nil && e.Confirmed.Before(w.Start):
		case e.Ended && !w.holds(e.Started):
		default:
			out.add(blocker(e), w.End.Sub(e.Started))
		}
	}
	return seconds, out.reasons()
}

func blocker(e Episode) string {
	switch {
	case e.NoContainmentNeeded:
		return ReasonNoContainmentNeeded
	case e.OpenRequests > 0:
		return ReasonRequestedNotConfirmed
	case e.Failed > 0:
		return ReasonFailedOrUnsupported
	case e.Declared:
		return ReasonDeclaredNotConfirmed
	}
	return ReasonOpenNotContained
}
