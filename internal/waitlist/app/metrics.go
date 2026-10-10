// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The metrics window, in days (PN-004.4).
const (
	DefaultMetricsDays = 30
	MaxMetricsDays     = 90
)

// SLA metrics are a Team feature (G0 M5 part 2, decision 19).
var (
	ErrEditionRequired = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "waitlist metrics need the Team edition or above")
	ErrBadWindow       = pcerr.New(pcerr.InvalidArgument, "BAD_WINDOW", "the metrics window is 1 to 90 days")
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// WithEntitlements adds the edition check that metrics need; without it
// they are refused.
func (rd *Reader) WithEntitlements(e Entitlements) *Reader {
	rd.ents = e
	return rd
}

// Metric aggregates the entries of one kind, or the entries of one kind a
// decider responded to or decided. Times are in seconds; a time with
// nothing to measure is zero.
type Metric struct {
	Kind                               string
	Decider                            ids.UUID
	Entries, Decided, RoutingFailures  int64
	FirstResponseP50, FirstResponseP90 float64
	DecisionP50, DecisionP90           float64
	ExpiryRate, EscalationRate         float64
}

// Metrics are the SLA metrics of the entries created in [Start, End).
type Metrics struct {
	ByKind, ByDecider []Metric
	Start, End        time.Time
}

// Metrics reports, per kind and per decider, the entries created in the
// last days (default 30, at most 90) that the caller may read: counts,
// median and 90th-percentile times to first response and to decision,
// expiry and escalation rates and routing failures (PN-004.4, Team). The
// entries are kept to the caller's agents before anything is aggregated
// (T-042).
func (rd *Reader) Metrics(ctx context.Context, days int, kinds []string) (Metrics, error) {
	if days == 0 {
		days = DefaultMetricsDays
	}
	if days < 1 || days > MaxMetricsDays {
		return Metrics{}, ErrBadWindow
	}
	if err := rd.teamWaitlist(ctx); err != nil {
		return Metrics{}, err
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Metrics{}, err
	}
	if kinds == nil {
		kinds = []string{}
	}
	var out Metrics
	err = rd.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		out.Start, out.End = now.Add(-time.Duration(days)*24*time.Hour), now
		p := dbq.WaitlistMetricsByKindParams{
			OrgID: c.Org, Since: out.Start, Until: out.End, Kinds: kinds, Agents: []ids.UUID{},
			AllAgents: c.Can(td.PermWaitlistRead, td.OrgPath(c.Org)),
		}
		if !p.AllAgents {
			if p.Agents, err = readableAgents(ctx, c, q, out.Start, out.End); err != nil {
				return err
			}
		}
		byKind, err := q.WaitlistMetricsByKind(ctx, p)
		if err != nil {
			return err
		}
		for _, r := range byKind {
			out.ByKind = append(out.ByKind, Metric{
				Kind: r.Kind, Entries: r.Entries, Decided: r.Decided, RoutingFailures: r.RoutingFailures,
				FirstResponseP50: r.FirstP50, FirstResponseP90: r.FirstP90, DecisionP50: r.DecisionP50, DecisionP90: r.DecisionP90,
				ExpiryRate: r.ExpiryRate, EscalationRate: r.EscalationRate,
			})
		}
		byDecider, err := q.WaitlistMetricsByDecider(ctx, dbq.WaitlistMetricsByDeciderParams(p))
		if err != nil {
			return err
		}
		for _, r := range byDecider {
			out.ByDecider = append(out.ByDecider, Metric{
				Kind: r.Kind, Decider: r.UserID, Entries: r.Entries, Decided: r.Decided, RoutingFailures: r.RoutingFailures,
				FirstResponseP50: r.FirstP50, FirstResponseP90: r.FirstP90, DecisionP50: r.DecisionP50, DecisionP90: r.DecisionP90,
				ExpiryRate: r.ExpiryRate, EscalationRate: r.EscalationRate,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// readableAgents are the agents of the window's entries whose entries the
// caller may read.
func readableAgents(ctx context.Context, c tenancy.Caller, q *dbq.Queries, since, until time.Time) ([]ids.UUID, error) {
	all, err := q.WaitlistMetricAgents(ctx, c.Org, since, until)
	if err != nil {
		return nil, err
	}
	out := []ids.UUID{}
	for _, a := range all {
		ok, err := canRead(ctx, c, q, a)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// teamWaitlist fails closed without entitlements wired.
func (rd *Reader) teamWaitlist(ctx context.Context) error {
	if rd.ents == nil {
		return ErrEditionRequired
	}
	e, err := rd.ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.TeamWaitlist() {
		return ErrEditionRequired
	}
	return nil
}
