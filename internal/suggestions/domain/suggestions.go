// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds evidence-backed policy suggestions (G0 M16 D90–D92;
// F185; HR-442..445): what an unused-authority posture finding's
// suggestion says about its evidence. Its window is the last 30 days; its
// coverage limits are the routes that were not ENFORCED for the whole
// window; its uncertainty is LOW only when every route was ENFORCED or
// OBSERVE_ONLY throughout (HR-443); its expected effect counts recorded
// transactions only and lists what was not collected, never as zero
// (HR-445). Everything here is pure.
package domain

import (
	"cmp"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Kind is a suggestion kind (D90).
type Kind string

// Kinds.
const UnusedAuthority Kind = "UNUSED_AUTHORITY"

// State is a suggestion's lifecycle state (D90).
type State string

// States.
const (
	Open      State = "OPEN"
	Drafted   State = "DRAFTED"
	Dismissed State = "DISMISSED"
	Stale     State = "STALE"
)

// Uncertainty is how far a suggestion's evidence can be trusted (D91).
type Uncertainty string

// Uncertainties.
const (
	Low    Uncertainty = "LOW"
	Medium Uncertainty = "MEDIUM"
	High   Uncertainty = "HIGH"
)

// Coverage states, as coverage snapshots record them.
const (
	CoverageUnknown     = "UNKNOWN"
	CoverageObserveOnly = "OBSERVE_ONLY"
	CoveragePartial     = "PARTIAL"
	CoverageEnforced    = "ENFORCED"
)

// The evidence window (D91).
const (
	WindowDays = 30
	Window     = WindowDays * 24 * time.Hour
)

// Bounds of what a suggestion keeps (D90).
const (
	MaxObserved       = 100
	MaxCoverageLimits = 100
	MaxNotCollected   = 32
	MaxRoutes         = 1000
	MinDismissReason  = 10
	MaxDismissReason  = 1000
)

// Uncertainty reasons, stable codes.
const (
	ReasonRoutePartial        = "ROUTE_PARTIAL"
	ReasonRouteUnknown        = "ROUTE_UNKNOWN"
	ReasonCoverageNotAssessed = "COVERAGE_NOT_ASSESSED" // no coverage at the window's start
	ReasonSnapshotMissing     = "SNAPSHOT_MISSING"
	ReasonSnapshotIncomplete  = "SNAPSHOT_INCOMPLETE"
	ReasonRetentionShort      = "RETENTION_SHORTER_THAN_WINDOW"
	ReasonNoRoutes            = "NO_ROUTES"
	ReasonRoutesTruncated     = "ROUTES_TRUNCATED"
	ReasonHistoryTruncated    = "COVERAGE_HISTORY_TRUNCATED"
	ReasonObservedTruncated   = "OBSERVED_TRUNCATED"
	ReasonLimitsTruncated     = "COVERAGE_LIMITS_TRUNCATED"
)

// Not-collected entries of an expected effect.
const (
	NotCollectedRetention = "RETENTION_SHORTER_THAN_WINDOW"
	NotCollectedNoRoutes  = "NO_ROUTES"
	// NotCollectedRoute prefixes a route whose actions may not all have
	// passed PantherClaw (PARTIAL or UNKNOWN coverage).
	NotCollectedRoute = "ROUTE_NOT_ENFORCED:"
	NotCollectedMore  = "MORE"
)

// ErrDismissReason is a dismissal without a usable reason.
var ErrDismissReason = errors.New("suggestions: a dismissal needs a reason of 10-1000 characters")

// CheckDismissReason validates a dismissal's reason.
func CheckDismissReason(reason string) error {
	n := utf8.RuneCountInString(strings.TrimSpace(reason))
	if n < MinDismissReason || n > MaxDismissReason {
		return ErrDismissReason
	}
	return nil
}

// Route is one path a grant reaches.
type Route struct {
	Agent      ids.UUID
	Connection ids.UUID
	Operation  string
}

// Key is the route as "<agent>|<connection>|<operation>".
func (r Route) Key() string {
	return r.Agent.String() + "|" + r.Connection.String() + "|" + r.Operation
}

func compareRoutes(a, b Route) int {
	return cmp.Or(strings.Compare(a.Agent.String(), b.Agent.String()),
		strings.Compare(a.Connection.String(), b.Connection.String()), strings.Compare(a.Operation, b.Operation))
}

// RoutesOf parses the routes and operations of posture path keys
// ("<agent>|<connection>|<operation>|<group>|<verb>"); keys without an
// agent, a connection or an operation name none.
func RoutesOf(paths []string) (routes []Route, operations []string) {
	for _, p := range paths {
		parts := strings.Split(p, "|")
		if len(parts) != 5 || parts[2] == "" {
			continue
		}
		a, err := ids.ParseUUID(parts[0])
		if err != nil {
			continue
		}
		c, err := ids.ParseUUID(parts[1])
		if err != nil {
			continue
		}
		routes = append(routes, Route{Agent: a, Connection: c, Operation: parts[2]})
		operations = append(operations, parts[2])
	}
	return SortRoutes(routes), sortedSet(operations)
}

// SortRoutes sorts and de-duplicates routes.
func SortRoutes(rs []Route) []Route {
	rs = slices.Clone(rs)
	slices.SortFunc(rs, compareRoutes)
	return slices.Compact(rs)
}

func sortedSet(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

// Sample is one coverage snapshot of a route.
type Sample struct {
	Route
	State     string
	At        time.Time
	ExpiresAt *time.Time
}

// RouteCoverage is how a route was covered over the window: its worst
// state, and whether it was ENFORCED (or OBSERVE_ONLY) throughout.
type RouteCoverage struct {
	Route
	// Worst is the worst state the route had in the window: UNKNOWN when
	// it was not assessed at the window's start.
	Worst string
	// Enforced: ENFORCED for the whole window.
	Enforced bool
	// NotAssessed: no coverage snapshot was in force at the window's start.
	NotAssessed bool
}

// rank orders states by how little they vouch for (D91): ENFORCED and
// OBSERVE_ONLY are LOW, PARTIAL MEDIUM, UNKNOWN (and anything unknown) HIGH.
func rank(state string) int {
	switch state {
	case CoverageEnforced:
		return 0
	case CoverageObserveOnly:
		return 1
	case CoveragePartial:
		return 2
	default:
		return 3
	}
}

// WindowCoverage folds each route's coverage history over [from, to):
// the snapshot in force at from, then each one computed in the window. An
// ENFORCED snapshot past its expiry no longer vouches: until the next one
// the route is PARTIAL (HR-211). A route with no snapshot in force at from
// was UNKNOWN until its first one.
func WindowCoverage(routes []Route, samples []Sample, from, to time.Time) []RouteCoverage {
	by := map[Route][]Sample{}
	for _, s := range samples {
		by[s.Route] = append(by[s.Route], s)
	}
	out := make([]RouteCoverage, 0, len(routes))
	for _, r := range SortRoutes(routes) {
		ss := by[r]
		slices.SortStableFunc(ss, func(a, b Sample) int { return a.At.Compare(b.At) })
		rc := RouteCoverage{Route: r, Worst: CoverageEnforced}
		worse := func(st string) {
			if rank(st) > rank(rc.Worst) {
				rc.Worst = st
			}
		}
		if len(ss) == 0 || ss[0].At.After(from) {
			rc.NotAssessed = true
			worse(CoverageUnknown)
		}
		for i, s := range ss {
			end := to
			if i+1 < len(ss) && ss[i+1].At.Before(to) {
				end = ss[i+1].At
			}
			if !end.After(from) {
				continue // superseded before the window
			}
			worse(s.State)
			if s.State == CoverageEnforced && (s.ExpiresAt == nil || s.ExpiresAt.Before(end)) {
				worse(CoveragePartial)
			}
		}
		rc.Enforced = rc.Worst == CoverageEnforced
		out = append(out, rc)
	}
	return out
}

// Limit is a coverage limit: a route that was not ENFORCED for the whole
// window, and its worst state (D90).
type Limit struct {
	Agent      string `json:"agent"`
	Connection string `json:"connection"`
	Operation  string `json:"operation"`
	State      string `json:"state"`
}

// Gaps are what makes the window's evidence incomplete, whatever the
// routes say: each is a reason and makes the uncertainty HIGH (D91).
type Gaps []string

// Assessment is a suggestion's coverage limits and uncertainty.
type Assessment struct {
	Limits      []Limit
	Uncertainty Uncertainty
	Reasons     []string
}

// Assess derives the coverage limits and the uncertainty (D91, HR-443):
// LOW only when every route was ENFORCED or OBSERVE_ONLY for the whole
// window and nothing is missing; MEDIUM when any was PARTIAL; HIGH when any
// was UNKNOWN, there are no routes, or the window has gaps. Limits are
// worst first, at most MaxCoverageLimits.
func Assess(cov []RouteCoverage, gaps Gaps) Assessment {
	a := Assessment{Uncertainty: Low}
	reasons := slices.Clone(gaps)
	worst := 0
	for _, rc := range cov {
		if rc.Enforced {
			continue
		}
		a.Limits = append(a.Limits, Limit{
			Agent: rc.Agent.String(), Connection: rc.Connection.String(), Operation: rc.Operation, State: rc.Worst,
		})
		worst = max(worst, rank(rc.Worst))
		switch {
		case rc.NotAssessed:
			reasons = append(reasons, ReasonCoverageNotAssessed)
		case rank(rc.Worst) == 3:
			reasons = append(reasons, ReasonRouteUnknown)
		case rc.Worst == CoveragePartial:
			reasons = append(reasons, ReasonRoutePartial)
		}
	}
	if len(cov) == 0 {
		reasons = append(reasons, ReasonNoRoutes)
	}
	slices.SortStableFunc(a.Limits, func(x, y Limit) int { return rank(y.State) - rank(x.State) })
	if len(a.Limits) > MaxCoverageLimits {
		a.Limits = a.Limits[:MaxCoverageLimits]
		reasons = append(reasons, ReasonLimitsTruncated)
	}
	switch {
	case len(gaps) > 0 || len(cov) == 0 || worst == 3:
		a.Uncertainty = High
	case worst == 2:
		a.Uncertainty = Medium
	}
	a.Reasons = sortedSet(reasons)
	if a.Reasons == nil {
		a.Reasons = []string{}
	}
	return a
}

// Effect is a suggestion's expected effect (D90, HR-445): counts of the
// recorded transactions in the window that the proposed restriction would
// match, deny anew or hold anew. The counts are present only when recorded
// data was collected; NotCollected lists what was not, which is never
// counted as zero.
type Effect struct {
	Collected       bool     `json:"collected"`
	MatchingActions *int64   `json:"matching_actions,omitzero"`
	NewlyDenied     *int64   `json:"newly_denied,omitzero"`
	NewlyHeld       *int64   `json:"newly_held,omitzero"`
	NotCollected    []string `json:"not_collected,omitzero"`
}

// Counts are the recorded transactions an effect counts.
type Counts struct {
	// Matching are the agent's recorded actions on the proposed operations.
	Matching int64
	// NotDenied are those the recorded decision did not deny.
	NotDenied int64
}

// ExpectedEffect builds the expected effect of a FORBID restriction.
// collectedDays is how much of the window the recorded transactions still
// cover (retention); counts is nil when nothing could be counted. Routes
// that were PARTIAL or UNKNOWN may have carried actions PantherClaw never
// recorded: they are listed as not collected. A FORBID never holds, so
// newly held is zero whenever counts were collected.
func ExpectedEffect(counts *Counts, collectedDays int, cov []RouteCoverage) Effect {
	e := Effect{}
	if collectedDays < WindowDays {
		e.NotCollected = append(e.NotCollected, NotCollectedRetention)
	}
	if len(cov) == 0 {
		e.NotCollected = append(e.NotCollected, NotCollectedNoRoutes)
	}
	for _, rc := range cov {
		if rank(rc.Worst) < 2 {
			continue
		}
		if len(e.NotCollected) == MaxNotCollected-1 {
			e.NotCollected = append(e.NotCollected, NotCollectedMore)
			break
		}
		e.NotCollected = append(e.NotCollected, NotCollectedRoute+rc.Key())
	}
	if counts != nil && collectedDays > 0 && len(cov) > 0 {
		m, d, h := counts.Matching, counts.NotDenied, int64(0)
		e.Collected, e.MatchingActions, e.NewlyDenied, e.NewlyHeld = true, &m, &d, &h
	}
	if !e.Collected && len(e.NotCollected) == 0 {
		e.NotCollected = []string{NotCollectedNoRoutes}
	}
	return e
}

// Observed caps the observed operation counts (D90): at most MaxObserved
// operations, the most used first as given. truncated reports more.
func Observed(rows map[string]int64, order []string) (out map[string]int64, truncated bool) {
	out = map[string]int64{}
	for _, op := range order {
		if len(out) == MaxObserved {
			return out, true
		}
		out[op] = rows[op]
	}
	return out, false
}
