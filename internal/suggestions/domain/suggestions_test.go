// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	to   = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	from = to.Add(-Window)
)

func at(days float64) time.Time { return from.Add(time.Duration(days * 24 * float64(time.Hour))) }

func sample(r Route, state string, day float64, expires ...float64) Sample {
	s := Sample{Route: r, State: state, At: at(day)}
	if len(expires) > 0 {
		e := at(expires[0])
		s.ExpiresAt = &e
	}
	return s
}

// TestHR443_UncertaintyNeverLowWithAPartialOrUnknownRoute (D91): LOW only
// when every route was ENFORCED (unexpired) or OBSERVE_ONLY for the whole
// window; a PARTIAL stretch, an ENFORCED snapshot that lapsed, or a route
// downgraded inside the window makes it MEDIUM; an UNKNOWN stretch, a
// route not assessed at the window's start, no routes, or a gap in the
// evidence makes it HIGH. Every route that was not ENFORCED is a coverage
// limit, worst first, and every level above LOW gives its reasons.
//
// Covers: F185
func TestHR443_UncertaintyNeverLowWithAPartialOrUnknownRoute(t *testing.T) {
	agent, conn := ids.NewV7(), ids.NewV7()
	a := Route{Agent: agent, Connection: conn, Operation: "payments.refund.create"}
	b := Route{Agent: agent, Connection: conn, Operation: "payments.payout.create"}
	for _, c := range []struct {
		name    string
		routes  []Route
		samples []Sample
		gaps    Gaps
		want    Uncertainty
		reason  string
		limited []string
	}{
		{"enforced throughout", []Route{a}, []Sample{sample(a, CoverageEnforced, -2, 40)}, nil, Low, "", nil},
		{"observe only", []Route{a, b}, []Sample{sample(a, CoverageEnforced, -1, 31), sample(b, CoverageObserveOnly, -5)}, nil, Low, "", []string{CoverageObserveOnly}},
		{"renewed in time", []Route{a}, []Sample{sample(a, CoverageEnforced, -2, 12), sample(a, CoverageEnforced, 11, 40)}, nil, Low, "", nil},
		{"partial in the window", []Route{a, b}, []Sample{sample(a, CoverageEnforced, -1, 40), sample(b, CoverageEnforced, -1, 40), sample(b, CoveragePartial, 20)}, nil, Medium, ReasonRoutePartial, []string{CoveragePartial}},
		{"enforced lapsed", []Route{a}, []Sample{sample(a, CoverageEnforced, -2, 10)}, nil, Medium, ReasonRoutePartial, []string{CoveragePartial}},
		{"partial before, enforced in the window", []Route{a}, []Sample{sample(a, CoveragePartial, -3), sample(a, CoverageEnforced, 1, 40)}, nil, Medium, ReasonRoutePartial, []string{CoveragePartial}},
		{"unknown in the window", []Route{a, b}, []Sample{sample(a, CoveragePartial, -1), sample(b, CoverageEnforced, -1, 40), sample(b, CoverageUnknown, 29)}, nil, High, ReasonRouteUnknown, []string{CoverageUnknown, CoveragePartial}},
		{"first assessed inside the window", []Route{a}, []Sample{sample(a, CoverageEnforced, 3, 40)}, nil, High, ReasonCoverageNotAssessed, []string{CoverageUnknown}},
		{"never assessed", []Route{a}, nil, nil, High, ReasonCoverageNotAssessed, []string{CoverageUnknown}},
		{"no routes", nil, nil, nil, High, ReasonNoRoutes, nil},
		{"a gap", []Route{a}, []Sample{sample(a, CoverageEnforced, -1, 40)}, Gaps{ReasonRetentionShort}, High, ReasonRetentionShort, nil},
		{"superseded before the window", []Route{a}, []Sample{sample(a, CoverageUnknown, -10), sample(a, CoverageEnforced, -1, 40)}, nil, Low, "", nil},
	} {
		got := Assess(WindowCoverage(c.routes, c.samples, from, to), c.gaps)
		if got.Uncertainty != c.want {
			t.Errorf("%s: %s %v", c.name, got.Uncertainty, got.Reasons)
			continue
		}
		if c.want != Low && (len(got.Reasons) == 0 || !slices.Contains(got.Reasons, c.reason)) {
			t.Errorf("%s: reasons %v, want %s", c.name, got.Reasons, c.reason)
		}
		var states []string
		for _, l := range got.Limits {
			states = append(states, l.State)
			if (l.State == CoveragePartial || l.State == CoverageUnknown) && got.Uncertainty == Low {
				t.Errorf("%s: LOW with a %s limit", c.name, l.State)
			}
		}
		if !slices.Equal(states, c.limited) {
			t.Errorf("%s: limits %v, want %v", c.name, states, c.limited)
		}
	}

	// However many routes are fine, one UNKNOWN keeps it HIGH, and limits
	// past the cap are cut worst first with a reason.
	var routes []Route
	var samples []Sample
	for i := range MaxCoverageLimits + 5 {
		r := Route{Agent: agent, Connection: conn, Operation: fmt.Sprintf("payments.op.n%d", i)}
		routes = append(routes, r)
		samples = append(samples, sample(r, CoverageObserveOnly, -1))
	}
	routes = append(routes, a)
	got := Assess(WindowCoverage(routes, samples, from, to), nil)
	if got.Uncertainty != High || len(got.Limits) != MaxCoverageLimits || got.Limits[0].State != CoverageUnknown ||
		!slices.Contains(got.Reasons, ReasonLimitsTruncated) {
		t.Fatalf("many routes: %s %d %v", got.Uncertainty, len(got.Limits), got.Reasons)
	}
}

// TestHR445_UncollectedDataReportedAsNotCollected (D90): counts come only
// from recorded transactions; with none collected the effect has no
// counts at all (not zeros) and says why; a PARTIAL or UNKNOWN route and a
// retention shorter than the window are listed as not collected next to
// the counts; a restriction never holds, so newly_held is 0.
//
// Covers: F185
func TestHR445_UncollectedDataReportedAsNotCollected(t *testing.T) {
	agent, conn := ids.NewV7(), ids.NewV7()
	a := Route{Agent: agent, Connection: conn, Operation: "payments.refund.create"}
	b := Route{Agent: agent, Connection: conn, Operation: "payments.payout.create"}
	enforced := WindowCoverage([]Route{a}, []Sample{sample(a, CoverageEnforced, -1, 40)}, from, to)
	mixed := WindowCoverage([]Route{a, b}, []Sample{sample(a, CoverageEnforced, -1, 40), sample(b, CoveragePartial, -1)}, from, to)

	for _, c := range []struct {
		name    string
		e       Effect
		listed  []string
		counted bool
	}{
		{"nothing recorded", ExpectedEffect(nil, 0, enforced), []string{NotCollectedRetention}, false},
		{"retention but no counts", ExpectedEffect(nil, WindowDays, enforced), []string{NotCollectedNoRoutes}, false},
		{"no routes", ExpectedEffect(&Counts{Matching: 4}, WindowDays, nil), []string{NotCollectedNoRoutes}, false},
		{"all collected", ExpectedEffect(&Counts{Matching: 4, NotDenied: 3}, WindowDays, enforced), nil, true},
		{"short retention", ExpectedEffect(&Counts{Matching: 4, NotDenied: 3}, 7, enforced), []string{NotCollectedRetention}, true},
		{"a partial route", ExpectedEffect(&Counts{Matching: 4, NotDenied: 3}, WindowDays, mixed), []string{NotCollectedRoute + b.Key()}, true},
	} {
		if c.e.Collected != c.counted || !slices.Equal(c.e.NotCollected, c.listed) {
			t.Errorf("%s: %+v", c.name, c.e)
		}
		raw, err := json.Marshal(c.e)
		if err != nil {
			t.Fatal(err)
		}
		has := strings.Contains(string(raw), "matching_actions")
		if has != c.counted || strings.Contains(string(raw), "newly_denied") != c.counted {
			t.Errorf("%s: counts present %v in %s", c.name, has, raw)
		}
		if c.counted && (*c.e.MatchingActions != 4 || *c.e.NewlyDenied != 3 || *c.e.NewlyHeld != 0) {
			t.Errorf("%s: counts %d %d %d", c.name, *c.e.MatchingActions, *c.e.NewlyDenied, *c.e.NewlyHeld)
		}
		if !c.counted && len(c.e.NotCollected) == 0 {
			t.Errorf("%s: not collected and says nothing", c.name)
		}
	}

	// Many routes not enforced: the list is bounded and ends with MORE.
	var routes []Route
	for i := range MaxNotCollected + 10 {
		routes = append(routes, Route{Agent: agent, Connection: conn, Operation: fmt.Sprintf("payments.op.r%d", i)})
	}
	e := ExpectedEffect(&Counts{}, WindowDays, WindowCoverage(routes, nil, from, to))
	if len(e.NotCollected) != MaxNotCollected || e.NotCollected[MaxNotCollected-1] != NotCollectedMore {
		t.Fatalf("bounded: %d %v", len(e.NotCollected), e.NotCollected[len(e.NotCollected)-1])
	}
}

// TestT196_SuggestionInputsAreBounded (T-196): a dismissal needs a reason
// of 10 to 1000 characters with no control, format or bidi character
// (HR-102); the observed operations are capped and say so; affected paths
// that are not operation paths propose nothing.
//
// Covers: F185
func TestT196_SuggestionInputsAreBounded(t *testing.T) {
	for _, r := range []string{
		"", "   short  ", strings.Repeat("x", MaxDismissReason+1),
		"the owner " + string(rune(0x202e)) + "still needs it", // right-to-left override
		"the owner " + string(rune(0x2066)) + "still needs it", // left-to-right isolate
		"the owner " + string(rune(0x200b)) + "still needs it", // zero-width space
		"the owner\x1b[2Jstill needs it",                       // terminal escape
		"the owner\nstill needs it",
		"the owner \xffstill needs it", // invalid UTF-8
	} {
		if CheckDismissReason(r) == nil {
			t.Errorf("reason %q accepted", r)
		}
	}
	if err := CheckDismissReason("the owner still needs it"); err != nil {
		t.Fatal(err)
	}
	rows, order := map[string]int64{}, []string{}
	for i := range MaxObserved + 3 {
		op := fmt.Sprintf("payments.op.o%d", i)
		rows[op], order = int64(i), append(order, op)
	}
	out, truncated := Observed(rows, order)
	if len(out) != MaxObserved || !truncated {
		t.Fatalf("observed %d truncated %v", len(out), truncated)
	}
	if _, ops := RoutesOf([]string{"agent:x", "not a path"}); len(ops) != 0 {
		t.Fatalf("operations from non-operation paths: %v", ops)
	}
}
