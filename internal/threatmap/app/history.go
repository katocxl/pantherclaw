// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/ports"
)

// HistoryDay is one stored day's techniques by status, each technique once.
type HistoryDay struct {
	Day                              time.Time
	Evidenced, Partial, Gap, Outside int
}

// HistoryDrop is one lane that dropped from one stored day to the next.
type HistoryDrop struct {
	Day time.Time
	domain.Drop
}

// History is a scope's stored days and the drops between them.
type History struct {
	Days  []HistoryDay
	Drops []HistoryDrop
}

// History reads the last days stored days of the org or one environment
// (Business, D719). The drops compare each day with the stored day before
// it, from the day before the window on.
func (s *Service) History(ctx context.Context, f catalog.Framework, env ids.UUID, days int) (History, error) {
	c, _, err := s.editions(ctx, gateHistory)
	if err != nil {
		return History{}, err
	}
	days = min(max(days, 1), HistoryDays)
	sc := Scope{Environment: env}
	today := s.now().Truncate(24 * time.Hour)
	since := today.AddDate(0, 0, -(days - 1))
	var rows []ports.Snapshot
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := s.inScope(ctx, tx, c, sc); err != nil {
			return err
		}
		rows, err = s.Store.Snapshots(ctx, tx, c.Org, sc.domain().Key(), string(f), since.AddDate(0, 0, -1))
		return err
	}, db.ReadOnly(), db.RepeatableRead())
	if err != nil {
		return History{}, err
	}
	return history(rows, since), nil
}

// history counts each day from since on and lists its drops against the
// stored day before it.
func history(rows []ports.Snapshot, since time.Time) History {
	out := History{Days: []HistoryDay{}, Drops: []HistoryDrop{}}
	for i, r := range rows {
		if r.Day.Before(since) {
			continue
		}
		n := domain.StatusCounts(r.States)
		out.Days = append(out.Days, HistoryDay{
			Day: r.Day, Evidenced: n[domain.StatusEvidenced], Partial: n[domain.StatusPartial], Gap: n[domain.StatusGap],
			Outside: n[domain.StatusOutside],
		})
		if i == 0 {
			continue
		}
		for _, d := range domain.Drops(rows[i-1].States, r.States) {
			out.Drops = append(out.Drops, HistoryDrop{Day: r.Day, Drop: d})
		}
	}
	return out
}
