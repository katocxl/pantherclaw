// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	defaultTrendDays = 30
	dayLayout        = "2006-01-02"
)

// DayState says whether the rollup ran for a day.
type DayState string

// States. A day with no run is NOT_COLLECTED, never zero (HR-581).
const (
	DayCollected    DayState = "COLLECTED"
	DayNotCollected DayState = "NOT_COLLECTED"
)

// TrendCount is one row of a collected day.
type TrendCount struct {
	Kind, Severity string
	Team           *ids.UUID
	Open           int32
	Closed         *int32
}

// TrendDay is one day of the rollup.
type TrendDay struct {
	Day              string
	State            DayState
	Counts           []TrendCount
	TruncatedSources []string
}

// Trends is one read.
type Trends struct {
	Days       []TrendDay
	Restricted bool
	AsOf       time.Time
}

func date(t time.Time) pgtype.Date { return pgtype.Date{Time: t, Valid: true} }

// utcDay is the start of t's UTC day.
func utcDay(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }

// teamsOf says which rollup rows a viewer below org scope may read: the teams
// it holds posture.read over as a whole. A narrower binding reaches part of a
// team, and a row counts the whole team.
func teamsOf(ctx context.Context, c tenancy.Caller, q *dbq.Queries) ([]ids.UUID, error) {
	rows, err := q.PostureQueueTeams(ctx, c.Org)
	if err != nil {
		return nil, err
	}
	out := []ids.UUID{}
	for _, r := range rows {
		p := td.OrgPath(c.Org)
		if r.BusinessUnitID != nil {
			p = p.Child(td.ScopeBusinessUnit, *r.BusinessUnitID)
		}
		if c.Can(td.PermPostureRead, p.Child(td.ScopeTeam, r.ID)) {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

// Trends returns one entry per day, oldest first. days zero means 30. A
// viewer below org scope reads only the teams it reaches whole, and never a
// row with no team (HR-580).
func (s *Service) Trends(ctx context.Context, days int32, kind string, team *ids.UUID) (Trends, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Trends{}, err
	}
	if !c.CanAnywhere(td.PermPostureRead) {
		return Trends{}, td.ErrPermissionDenied(td.PermPostureRead)
	}
	if err := s.entitled(ctx, billing.Entitlements.PostureTrends, ErrTrendsEdition); err != nil {
		return Trends{}, err
	}
	if days <= 0 {
		days = defaultTrendDays
	}
	out := Trends{Restricted: !c.Can(td.PermPostureRead, td.OrgPath(c.Org))}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if out.AsOf, err = q.DBNow(ctx); err != nil {
			return err
		}
		var teams []ids.UUID
		if out.Restricted {
			if teams, err = teamsOf(ctx, c, q); err != nil {
				return err
			}
		}
		last := utcDay(out.AsOf)
		first := last.AddDate(0, 0, 1-int(days))
		runs, err := q.ListPostureDailyRuns(ctx, c.Org, date(first), date(last))
		if err != nil {
			return err
		}
		rows, err := q.ListPostureDaily(ctx, c.Org, date(first), date(last))
		if err != nil {
			return err
		}
		for d := first; !d.After(last); d = d.AddDate(0, 0, 1) {
			out.Days = append(out.Days, TrendDay{Day: d.Format(dayLayout), State: DayNotCollected})
		}
		byDay := make(map[string]*TrendDay, len(out.Days))
		for i := range out.Days {
			byDay[out.Days[i].Day] = &out.Days[i]
		}
		for _, r := range runs {
			if d := byDay[r.Day.Time.Format(dayLayout)]; d != nil {
				d.State, d.TruncatedSources = DayCollected, r.TruncatedSources
			}
		}
		for _, r := range rows {
			d := byDay[r.Day.Time.Format(dayLayout)]
			switch {
			case d == nil,
				kind != "" && r.Kind != kind,
				team != nil && (r.TeamID == nil || *r.TeamID != *team),
				out.Restricted && (r.TeamID == nil || !slices.Contains(teams, *r.TeamID)):
				continue
			}
			d.Counts = append(d.Counts, TrendCount{Kind: r.Kind, Severity: r.Severity, Team: r.TeamID, Open: r.OpenCount, Closed: r.ClosedCount})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Rollup writes one org's daily counts (D206).
type Rollup struct {
	Service  *Service
	Failures reflexports.FailureSink
}

// Run counts what is open now, once per UTC day: an hourly dispatch only
// fills the day sooner, and a day it misses altogether stays NOT_COLLECTED.
// It reports whether it wrote a day. A lapsed edition stops quietly and
// records one owned failure while it is open.
func (r *Rollup) Run(ctx context.Context, org ids.OrgID) (bool, error) {
	ctx = tenantctx.WithOrg(ctx, org)
	s := r.Service
	if s.Ents == nil {
		return false, nil
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return false, err
	}
	var today time.Time
	done, seen := false, false
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		today = utcDay(now)
		runs, err := q.ListPostureDailyRuns(ctx, org, date(today.AddDate(0, 0, -30)), date(today))
		if err != nil {
			return err
		}
		seen = len(runs) > 0
		done = seen && runs[len(runs)-1].Day.Time.Equal(today)
		return nil
	}, db.ReadOnly())
	if err != nil {
		return false, err
	}
	if !e.PostureTrends() {
		if !seen || r.Failures == nil {
			return false, nil
		}
		return false, s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := r.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
				Org: org, Kind: "posture.trends_lapsed", DedupeKey: "posture.trends_lapsed",
				Summary:  "Posture trends stopped: the edition no longer includes them. Earlier days are kept, and days from now are not collected.",
				NextStep: "Renew a Business or higher licence to resume the daily rollup.",
				Deadline: time.Now().Add(7 * 24 * time.Hour),
			})
			return err
		})
	}
	if done {
		return false, nil
	}
	found, statuses, err := s.collect(ctx, orgViewer(org), domain.Filter{})
	if err != nil {
		return false, err
	}
	truncated := []string{}
	for _, st := range statuses {
		if st.State == SourceTruncated {
			truncated = append(truncated, string(st.Source))
		}
	}
	wrote := false
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.InsertPostureDailyRun(ctx, org, date(today), truncated)
		if err != nil || n == 0 {
			return err
		}
		wrote = true
		prev, collected, err := previous(ctx, q, org, today.AddDate(0, 0, -1))
		if err != nil {
			return err
		}
		for _, c := range domain.Rollup(found, today, prev, collected) {
			row := dbq.InsertPostureDailyParams{
				OrgID: org, Day: date(today), Kind: c.Kind, Severity: string(c.Severity), OpenCount: int32(c.Open), //nolint:gosec // G115: bounded by the sources' caps
			}
			if c.Team != (ids.UUID{}) {
				t := c.Team
				row.TeamID = &t
			}
			if c.Closed != nil {
				v := int32(*c.Closed) //nolint:gosec // G115: bounded by the sources' caps
				row.ClosedCount = &v
			}
			if err := q.InsertPostureDaily(ctx, row); err != nil {
				return err
			}
		}
		return nil
	})
	return wrote, err
}

// previous reads a day's counts and whether it was collected.
func previous(ctx context.Context, q *dbq.Queries, org ids.OrgID, day time.Time) ([]domain.DayCount, bool, error) {
	runs, err := q.ListPostureDailyRuns(ctx, org, date(day), date(day))
	if err != nil || len(runs) == 0 {
		return nil, false, err
	}
	rows, err := q.ListPostureDaily(ctx, org, date(day), date(day))
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.DayCount, 0, len(rows))
	for _, r := range rows {
		c := domain.DayCount{DayKey: domain.DayKey{Kind: r.Kind, Severity: domain.Severity(r.Severity)}, Open: int(r.OpenCount)}
		if r.TeamID != nil {
			c.Team = *r.TeamID
		}
		out = append(out, c)
	}
	return out, true, nil
}
