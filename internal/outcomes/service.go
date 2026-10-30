// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package outcomes

import (
	"context"
	"encoding/json/v2"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// maxRange is the longest read (D303): 30 days of daily points.
const maxRange = 30 * 24 * time.Hour

// Errors of a read.
var (
	// ErrEdition refuses outcome metrics below Business.
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "outcome metrics need the Business edition or higher")
	// ErrScope refuses a viewer without operations.read at the org: a metric
	// is an org-wide aggregate, which would count rows outside a narrower scope.
	ErrScope = pcerr.New(pcerr.PermissionDenied, "PERMISSION_DENIED", "outcome metrics need operations.read across the organization")
)

// PointState says what a point holds.
type PointState string

// Point states.
const (
	Collected    PointState = "COLLECTED"
	NotCollected PointState = "NOT_COLLECTED"
	NoSample     PointState = "NO_SAMPLE"
	Restricted   PointState = "RESTRICTED"
)

// Point is one window. A point that is not COLLECTED has no value.
type Point struct {
	Window     Window
	State      PointState
	P50, P90   *float64
	Share      *float64
	Measured   int64
	Unmeasured int64
	Reasons    []Reason
	// AsOf is when the rollup computed it (HR-540).
	AsOf time.Time
}

// Series is one metric and dimension over the range.
type Series struct {
	Definition Definition
	Dimension  string
	Scope      string
	Points     []Point
}

// Result is a read.
type Result struct {
	AsOf       time.Time
	Start, End time.Time
	WindowDays int
	Series     []Series
}

// Service reads the samples.
type Service struct {
	Pool *db.Pool
	Ents Entitlements
}

// GetMetrics returns the named metrics (all when none): for each day ending
// in (start, end], the window of windowDays that ended then. Every day has a
// point: COLLECTED, NOT_COLLECTED (with its reasons) or NO_SAMPLE (no rollup
// ran), or RESTRICTED for a viewer who may not read the metric's sources.
func (s *Service) GetMetrics(ctx context.Context, metrics []string, windowDays int, start, end time.Time) (Result, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Result{}, err
	}
	if !c.Can(td.PermOperationsRead, td.OrgPath(c.Org)) {
		return Result{}, ErrScope
	}
	defs, err := selected(metrics)
	if err != nil {
		return Result{}, err
	}
	if !slices.Contains(Windows, windowDays) {
		return Result{}, pcerr.New(pcerr.InvalidArgument, "INVALID_WINDOW", "the window must be 7 or 30 days")
	}
	start, end = start.UTC().Truncate(24*time.Hour), end.UTC().Truncate(24*time.Hour)
	if !end.After(start) || end.Sub(start) > maxRange {
		return Result{}, pcerr.New(pcerr.InvalidArgument, "INVALID_RANGE", "the range must end after it starts and span at most 30 days")
	}
	ok, err := entitled(ctx, s.Ents)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, ErrEdition
	}
	out := Result{Start: start, End: end, WindowDays: windowDays}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.OpsDBNow(ctx)
		if err != nil {
			return err
		}
		out.AsOf = now.UTC()
		readable := make([]string, 0, len(defs))
		for _, d := range defs {
			if mayRead(c, d) {
				readable = append(readable, d.Name)
			}
		}
		rows, err := q.ListOutcomeSamples(ctx, dbq.ListOutcomeSamplesParams{
			OrgID: c.Org, Metrics: readable, RangeStart: start, RangeEnd: end, WindowDays: int32(windowDays), //nolint:gosec // G115: 7 or 30
		})
		if err != nil {
			return err
		}
		out.Series, err = series(defs, readable, rows, windowDays, start, end)
		return err
	}, db.ReadOnly())
	return out, err
}

func selected(metrics []string) ([]Definition, error) {
	if len(metrics) == 0 {
		return Definitions, nil
	}
	out := make([]Definition, 0, len(metrics))
	for _, d := range Definitions {
		if slices.Contains(metrics, d.Name) {
			out = append(out, d)
		}
	}
	for _, m := range metrics {
		if _, ok := DefinitionOf(m); !ok {
			return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_METRIC", "unknown metric "+m)
		}
	}
	return out, nil
}

// mayRead reports whether the viewer may read all of a metric's sources
// across the organization, so an aggregate never counts rows it may not read.
func mayRead(c tenancy.Caller, d Definition) bool {
	for _, p := range d.Reads {
		if !c.Can(p, td.OrgPath(c.Org)) {
			return false
		}
	}
	return true
}

// series lays the samples out day by day, one series per metric and
// dimension; a metric without samples gets one series of NO_SAMPLE, and one
// the viewer may not read one of RESTRICTED, with no dimension.
func series(defs []Definition, readable []string, rows []dbq.PcOutcomeMetricSample, windowDays int, start, end time.Time) ([]Series, error) {
	type key struct{ metric, dim string }
	byKey := map[key]map[time.Time]dbq.PcOutcomeMetricSample{}
	var keys []key
	for _, r := range rows {
		k := key{r.Metric, r.Dimension}
		if byKey[k] == nil {
			byKey[k] = map[time.Time]dbq.PcOutcomeMetricSample{}
			keys = append(keys, k)
		}
		byKey[k][r.WindowEnd.UTC()] = r
	}
	var out []Series
	for _, d := range defs {
		dims := []string{}
		for _, k := range keys {
			if k.metric == d.Name {
				dims = append(dims, k.dim)
			}
		}
		if len(dims) == 0 {
			dims = []string{""}
		}
		for _, dim := range dims {
			sr := Series{Definition: d, Dimension: dim, Scope: ScopeOrganization}
			for e := start.AddDate(0, 0, 1); !e.After(end); e = e.AddDate(0, 0, 1) {
				p := Point{Window: windowOf(e, windowDays), State: NoSample}
				if !slices.Contains(readable, d.Name) {
					p.State = Restricted
				} else if r, ok := byKey[key{d.Name, dim}][e]; ok {
					var err error
					if p, err = pointOf(r); err != nil {
						return nil, err
					}
				}
				sr.Points = append(sr.Points, p)
			}
			out = append(out, sr)
		}
	}
	return out, nil
}

func value(v pgtype.Float8) *float64 {
	if !v.Valid {
		return nil
	}
	return &v.Float64
}

func pointOf(r dbq.PcOutcomeMetricSample) (Point, error) {
	p := Point{
		Window: Window{Start: r.WindowStart.UTC(), End: r.WindowEnd.UTC()}, State: NotCollected, Measured: r.Measured,
		Unmeasured: r.Unmeasured, AsOf: r.SampledAt.UTC(),
	}
	if r.Collected {
		p.State, p.P50, p.P90, p.Share = Collected, value(r.P50Seconds), value(r.P90Seconds), value(r.Share)
	}
	return p, json.Unmarshal(r.Reasons, &p.Reasons)
}
