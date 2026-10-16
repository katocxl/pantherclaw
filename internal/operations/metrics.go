// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import (
	"context"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	"github.com/katocxl/pantherclaw/internal/search"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Operating metrics (G0 M10 D33, F301; Team): hourly samples of
// consequential outcomes, coverage, bypass routes, exposure by resource
// group and the reconciliation backlog. A source this server does not
// collect is sampled as "not collected", never as zero (HR-258). Each
// point carries a structured search for its drill-down.

// Metric names.
const (
	MetricDecisionsAllowed      = "decisions.allowed"
	MetricDecisionsDenied       = "decisions.denied"
	MetricDecisionsHeld         = "decisions.held"
	MetricDecisionsShadow       = "decisions.shadow"
	MetricEffectsConfirmed      = "effects.confirmed"
	MetricCoverageEnforced      = "coverage.enforced"
	MetricCoverageNotEnforced   = "coverage.not_enforced"
	MetricBypassRoutes          = "bypass.routes"
	MetricBypassOldestHours     = "bypass.oldest_age_hours"
	MetricExposureUsable        = "exposure.usable_rights"
	MetricReconciliationBacklog = "reconciliation.backlog"
	MetricAutomationOutcomes    = "automation.outcomes"
)

// Metrics lists every metric, in display order.
var Metrics = []string{
	MetricDecisionsAllowed, MetricDecisionsDenied, MetricDecisionsHeld, MetricDecisionsShadow, MetricEffectsConfirmed,
	MetricCoverageEnforced, MetricCoverageNotEnforced, MetricBypassRoutes, MetricBypassOldestHours,
	MetricExposureUsable, MetricReconciliationBacklog, MetricAutomationOutcomes,
}

// Limits on a metrics read.
const (
	maxMetricRange = 30 * 24 * time.Hour
	// MaxCollectLag is how many past hours one collection fills in.
	MaxCollectLag = 24
)

// Entitlements reads the org's licence.
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// ErrEdition refuses metrics below Team (D5).
var ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "operating metrics need the Team edition or higher")

// ErrMetricsScope refuses metrics to a viewer without operations.read at
// the org: they are org-wide aggregates, which would count rows outside a
// narrower scope (D8).
var ErrMetricsScope = pcerr.New(pcerr.PermissionDenied, "PERMISSION_DENIED",
	"operating metrics need operations.read across the organization")

// sample is one value to record; collected false means "not collected".
type sample struct {
	metric, dimension string
	value             float64
	collected         bool
}

// Collector writes the hourly samples (a per-org job).
type Collector struct {
	Pool     *db.Pool
	Ents     Entitlements
	Failures reflexports.FailureSink
}

func entitled(ctx context.Context, e Entitlements) (bool, error) {
	if e == nil {
		return false, nil
	}
	ent, err := e.Current(ctx)
	if err != nil {
		return false, err
	}
	return ent.ReflexTeam(), nil
}

// Collect samples the hours since the org's last sample (at most
// MaxCollectLag), up to the last full hour. A lapsed edition stops quietly
// and records one owned failure while it is open (D5).
func (c *Collector) Collect(ctx context.Context, org ids.OrgID) (int, error) {
	ok, err := entitled(ctx, c.Ents)
	if err != nil {
		return 0, err
	}
	written := 0
	err = c.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if !ok {
			return c.lapsed(ctx, tx, org)
		}
		now, err := q.OpsDBNow(ctx)
		if err != nil {
			return err
		}
		last := now.UTC().Truncate(time.Hour).Add(-time.Hour)
		for h := MaxCollectLag - 1; h >= 0; h-- {
			bucket := last.Add(-time.Duration(h) * time.Hour)
			// Point-in-time sources are sampled only for the last hour:
			// their past values are not reconstructable.
			ss, err := sampleHour(ctx, q, org, bucket, h == 0)
			if err != nil {
				return err
			}
			for _, s := range ss {
				v := pgtype.Float8{Float64: s.value, Valid: s.collected}
				n, err := q.InsertMetricSample(ctx, dbq.InsertMetricSampleParams{
					OrgID: org, ID: ids.NewV7(), Metric: s.metric, Dimension: s.dimension, Bucket: bucket, Value: v, Collected: s.collected,
				})
				if err != nil {
					return err
				}
				written += int(n)
			}
		}
		return nil
	})
	return written, err
}

func (c *Collector) lapsed(ctx context.Context, tx db.TenantTx, org ids.OrgID) error {
	// Only an org that once collected has something to lose.
	rows, err := dbq.New(tx).ListMetricSamples(ctx, dbq.ListMetricSamplesParams{
		OrgID: org, Metrics: Metrics, RangeStart: time.Unix(0, 0), RangeEnd: time.Now().Add(time.Hour),
	})
	if err != nil || len(rows) == 0 || c.Failures == nil {
		return err
	}
	_, err = c.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: org, Kind: "operations.metrics_edition_lapsed", DedupeKey: "operations.metrics_edition_lapsed",
		Summary:  "Operating metrics stopped: the edition no longer includes them. Earlier samples are kept.",
		NextStep: "Renew a Team or higher licence to resume the hourly samples.",
		Deadline: time.Now().Add(7 * 24 * time.Hour),
	})
	return err
}

// sampleHour reads every source for one hour. Hourly counts are
// reconstructable for any past hour; point-in-time sources only when
// current is set, and are otherwise left unsampled.
func sampleHour(ctx context.Context, q *dbq.Queries, org ids.OrgID, bucket time.Time, current bool) ([]sample, error) {
	end := bucket.Add(time.Hour)
	var out []sample
	ds, err := q.MetricDecisions(ctx, org, bucket, end)
	if err != nil {
		return nil, err
	}
	counts := map[string]float64{
		MetricDecisionsAllowed: 0, MetricDecisionsDenied: 0, MetricDecisionsHeld: 0, MetricDecisionsShadow: 0,
	}
	for _, d := range ds {
		switch {
		case d.Mode == "monitor":
			counts[MetricDecisionsShadow] += float64(d.N)
		case d.Decision == "ALLOW":
			counts[MetricDecisionsAllowed] += float64(d.N)
		case d.Decision == "DENY" || d.Decision == "CANNOT_AUTHORIZE":
			counts[MetricDecisionsDenied] += float64(d.N)
		case d.Decision == "REQUIRE_APPROVAL" || d.Decision == "REQUIRE_STEP_UP":
			counts[MetricDecisionsHeld] += float64(d.N)
		}
	}
	for _, m := range []string{MetricDecisionsAllowed, MetricDecisionsDenied, MetricDecisionsHeld, MetricDecisionsShadow} {
		out = append(out, sample{metric: m, value: counts[m], collected: true})
	}
	n, err := q.MetricEffectsConfirmed(ctx, org, bucket, end)
	if err != nil {
		return nil, err
	}
	out = append(out, sample{metric: MetricEffectsConfirmed, value: float64(n), collected: true})
	autos, err := automationOutcomes(ctx, q, org, bucket, end)
	if err != nil {
		return nil, err
	}
	out = append(out, autos...)
	if !current {
		return out, nil
	}
	cov, err := q.MetricCoverageStates(ctx, org)
	if err != nil {
		return nil, err
	}
	var enforced, other float64
	for _, c := range cov {
		if c.State == "ENFORCED" {
			enforced += float64(c.N)
		} else {
			other += float64(c.N)
		}
	}
	out = append(out, sample{metric: MetricCoverageEnforced, value: enforced, collected: true},
		sample{metric: MetricCoverageNotEnforced, value: other, collected: true})
	by, err := q.MetricBypassRoutes(ctx, org)
	if err != nil {
		return nil, err
	}
	out = append(out, sample{metric: MetricBypassRoutes, value: float64(by.N), collected: true},
		sample{metric: MetricBypassOldestHours, value: by.OldestHours, collected: true})
	backlog, err := q.MetricReconciliationBacklog(ctx, org)
	if err != nil {
		return nil, err
	}
	out = append(out, sample{metric: MetricReconciliationBacklog, value: float64(backlog), collected: true})
	snap, err := q.MetricLatestExposureSnapshot(ctx, org)
	switch {
	case db.IsNoRows(err):
		out = append(out, sample{metric: MetricExposureUsable})
	case err != nil:
		return nil, err
	default:
		groups, err := q.MetricExposureByGroup(ctx, org, snap)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			out = append(out, sample{metric: MetricExposureUsable, dimension: g.ResourceGroup, value: float64(g.N), collected: true})
		}
		if len(groups) == 0 {
			out = append(out, sample{metric: MetricExposureUsable, value: 0, collected: true})
		}
	}
	return out, nil
}

// PointState says what a point holds.
type PointState string

// Point states.
const (
	Collected    PointState = "COLLECTED"
	NotCollected PointState = "NOT_COLLECTED"
	NoSample     PointState = "NO_SAMPLE"
	// Restricted: the viewer may not read the metric's source across the
	// organization (D69 M7); nothing of it is read.
	PointRestricted PointState = "RESTRICTED"
)

// Point is one hourly value with its drill-down.
type Point struct {
	Bucket time.Time
	State  PointState
	Value  float64
	Drill  *search.Spec
}

// Series is one metric and dimension over the range.
type Series struct {
	Metric    string
	Dimension string
	Points    []Point
}

// MetricsResult is a metrics read.
type MetricsResult struct {
	AsOf   time.Time
	Start  time.Time
	End    time.Time
	Series []Series
}

// GetMetrics returns the hourly series of the named metrics (all when
// none) over [start, end), at most 30 days. Every hour of the range has a
// point: COLLECTED, NOT_COLLECTED (the source is not collected) or
// NO_SAMPLE (no sample was taken; a gap).
func (s *Service) GetMetrics(ctx context.Context, metrics []string, start, end time.Time) (MetricsResult, error) {
	c, err := operator(ctx)
	if err != nil {
		return MetricsResult{}, err
	}
	if !c.Can(td.PermOperationsRead, td.OrgPath(c.Org)) {
		return MetricsResult{}, ErrMetricsScope
	}
	if len(metrics) == 0 {
		metrics = Metrics
	}
	for _, m := range metrics {
		if !slices.Contains(Metrics, m) {
			return MetricsResult{}, pcerr.New(pcerr.InvalidArgument, "INVALID_METRIC", "unknown metric "+m)
		}
	}
	start, end = start.UTC().Truncate(time.Hour), end.UTC().Truncate(time.Hour)
	if !end.After(start) || end.Sub(start) > maxMetricRange {
		return MetricsResult{}, pcerr.New(pcerr.InvalidArgument, "INVALID_RANGE", "the range must end after it starts and span at most 30 days")
	}
	ok, err := entitled(ctx, s.Ents)
	if err != nil {
		return MetricsResult{}, err
	}
	if !ok {
		return MetricsResult{}, ErrEdition
	}
	out := MetricsResult{Start: start, End: end}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.OpsDBNow(ctx)
		if err != nil {
			return err
		}
		out.AsOf = now.UTC()
		readable, hidden := splitByPermission(c, metrics)
		rows, err := q.ListMetricSamples(ctx, dbq.ListMetricSamplesParams{OrgID: c.Org, Metrics: readable, RangeStart: start, RangeEnd: end})
		if err != nil {
			return err
		}
		out.Series = series(readable, rows, start, end)
		for _, m := range hidden {
			sr := Series{Metric: m}
			for b := start; b.Before(end); b = b.Add(time.Hour) {
				sr.Points = append(sr.Points, Point{Bucket: b, State: PointRestricted})
			}
			out.Series = append(out.Series, sr)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// series lays the samples out hour by hour, one series per metric and
// dimension (a metric without samples gets one series of NO_SAMPLE).
func series(metrics []string, rows []dbq.ListMetricSamplesRow, start, end time.Time) []Series {
	type key struct{ metric, dim string }
	byKey := map[key]map[time.Time]dbq.ListMetricSamplesRow{}
	var order []key
	for _, r := range rows {
		k := key{r.Metric, r.Dimension}
		if byKey[k] == nil {
			byKey[k] = map[time.Time]dbq.ListMetricSamplesRow{}
			order = append(order, k)
		}
		byKey[k][r.Bucket.UTC()] = r
	}
	for _, m := range metrics {
		if !slices.ContainsFunc(order, func(k key) bool { return k.metric == m }) {
			order = append(order, key{metric: m})
		}
	}
	slices.SortStableFunc(order, func(a, b key) int {
		ia, ib := slices.Index(Metrics, a.metric), slices.Index(Metrics, b.metric)
		if ia != ib {
			return ia - ib
		}
		switch {
		case a.dim < b.dim:
			return -1
		case a.dim > b.dim:
			return 1
		}
		return 0
	})
	out := make([]Series, 0, len(order))
	for _, k := range order {
		sr := Series{Metric: k.metric, Dimension: k.dim}
		for b := start; b.Before(end); b = b.Add(time.Hour) {
			p := Point{Bucket: b, State: NoSample, Drill: drill(k.metric, k.dim, b)}
			if r, ok := byKey[k][b]; ok {
				if r.Collected && r.Value.Valid {
					p.State, p.Value = Collected, r.Value.Float64
				} else {
					p.State = NotCollected
				}
			}
			sr.Points = append(sr.Points, p)
		}
		out = append(out, sr)
	}
	return out
}

// drill is the structured search behind a point (F301: drillable to its
// records). Point-in-time metrics drill into what stands now.
func drill(metric, dim string, bucket time.Time) *search.Spec {
	start, end := bucket, bucket.Add(time.Hour)
	tx := func(f search.Filters) *search.Spec {
		f.Start, f.End = &start, &end
		return &search.Spec{Query: &search.Query{Entity: search.EntityTransactions, Filters: f}}
	}
	switch metric {
	case MetricDecisionsAllowed:
		return tx(search.Filters{Decisions: []string{"ALLOW"}, Modes: []string{"enforce"}})
	case MetricDecisionsDenied:
		return tx(search.Filters{Decisions: []string{"DENY", "CANNOT_AUTHORIZE"}, Modes: []string{"enforce"}})
	case MetricDecisionsHeld:
		return tx(search.Filters{Decisions: []string{"REQUIRE_APPROVAL", "REQUIRE_STEP_UP"}, Modes: []string{"enforce"}})
	case MetricDecisionsShadow:
		return tx(search.Filters{Modes: []string{"monitor"}})
	case MetricEffectsConfirmed:
		return tx(search.Filters{})
	case MetricCoverageEnforced, MetricCoverageNotEnforced, MetricBypassRoutes, MetricBypassOldestHours:
		return &search.Spec{Query: &search.Query{Entity: search.EntityConnections}}
	case MetricExposureUsable:
		if dim == "" {
			return &search.Spec{Builtin: &search.BuiltinQuery{Name: search.BuiltinWidestExposure}}
		}
		return &search.Spec{Builtin: &search.BuiltinQuery{Name: search.BuiltinWhoCanWrite, Params: search.Params{Resource: dim}}}
	case MetricReconciliationBacklog:
		return &search.Spec{Query: &search.Query{Entity: search.EntityTransactions, Filters: search.Filters{Modes: []string{"enforce"}}}}
	default:
		return nil
	}
}

// metricPerm is the permission that reads each metric's source (D69 M7):
// an aggregate is shown only to a viewer who may read its source across
// the organization, so it never counts rows the viewer may not read.
var metricPerm = map[string]td.Permission{
	MetricDecisionsAllowed:      td.PermEvidenceRead,
	MetricDecisionsDenied:       td.PermEvidenceRead,
	MetricDecisionsHeld:         td.PermEvidenceRead,
	MetricDecisionsShadow:       td.PermEvidenceRead,
	MetricEffectsConfirmed:      td.PermEvidenceRead,
	MetricReconciliationBacklog: td.PermEvidenceRead,
	MetricCoverageEnforced:      td.PermCoverageRead,
	MetricCoverageNotEnforced:   td.PermCoverageRead,
	MetricBypassRoutes:          td.PermCoverageRead,
	MetricBypassOldestHours:     td.PermCoverageRead,
	MetricExposureUsable:        td.PermExposureRead,
	MetricAutomationOutcomes:    td.PermAutomationRead,
}

// splitByPermission splits metrics into those the viewer may read at the
// org and those it may not.
func splitByPermission(c tenancy.Caller, metrics []string) (readable, hidden []string) {
	for _, m := range metrics {
		if p, ok := metricPerm[m]; ok && c.Can(p, td.OrgPath(c.Org)) {
			readable = append(readable, m)
		} else {
			hidden = append(hidden, m)
		}
	}
	if readable == nil {
		readable = []string{}
	}
	return readable, hidden
}

// Automation outcome dimensions (G0 M11 D38): "<automation>/<outcome>",
// and "/interventions" for automation exceptions resolved org-wide.
const (
	OutcomeCompleted     = "completed_with_evidence"
	OutcomePartial       = "partial"
	OutcomeFailed        = "failed"
	OutcomeReconcile     = "needs_reconciliation"
	OutcomeInterventions = "interventions"
	OutcomeRefused       = "triggers_refused"
)

// automationOutcomes samples an hour's automation outcomes, one point per
// automation and outcome; an hour with none is a collected zero, never
// "not collected" (HR-258). Routine success is counted, never notified.
func automationOutcomes(ctx context.Context, q *dbq.Queries, org ids.OrgID, bucket, end time.Time) ([]sample, error) {
	rows, err := q.MetricAutomationOutcomes(ctx, org, bucket, end)
	if err != nil {
		return nil, err
	}
	var out []sample
	for _, r := range rows {
		out = append(out, sample{
			metric: MetricAutomationOutcomes, dimension: r.AutomationID.String() + "/" + r.Outcome, value: float64(r.N), collected: true,
		})
	}
	resolved, err := q.MetricAutomationResolved(ctx, org, bucket, end)
	if err != nil {
		return nil, err
	}
	if resolved > 0 {
		out = append(out, sample{metric: MetricAutomationOutcomes, dimension: "/" + OutcomeInterventions, value: float64(resolved), collected: true})
	}
	if len(out) == 0 {
		out = append(out, sample{metric: MetricAutomationOutcomes, value: 0, collected: true})
	}
	return out, nil
}
