// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/cron"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Schedule dispatch (D17).
const (
	// ScheduleInterval is how often due schedules are looked at.
	ScheduleInterval = 15 * time.Second
	// MissedAfter is how late an occurrence may fire; later it is missed.
	MissedAfter = 2 * time.Minute
	// MaxCatchUpWindow bounds catch_up_window.
	MaxCatchUpWindow = 24 * time.Hour
)

// PreviewEntry is one previewed occurrence (D17, F672–F674).
type PreviewEntry struct {
	Local string
	UTC   time.Time
	Note  cron.Note
}

// MaxPreview bounds a preview.
const MaxPreview = 50

// PreviewSchedule lists up to count occurrences of a schedule after from:
// the local wall-clock time, the instant in UTC (zero when a DST gap
// skips it) and what daylight saving does to it.
func PreviewSchedule(expr, zone string, dstShift bool, from time.Time, count int) ([]PreviewEntry, error) {
	spec, err := cron.Parse(expr)
	if err != nil {
		return nil, err
	}
	loc, err := cron.LoadZone(zone)
	if err != nil {
		return nil, err
	}
	gap := cron.GapSkip
	if dstShift {
		gap = cron.GapShift
	}
	count = max(1, min(count, MaxPreview))
	occ := spec.Preview(from, loc, gap, count)
	out := make([]PreviewEntry, 0, len(occ))
	for _, o := range occ {
		e := PreviewEntry{Local: o.Scheduled, Note: o.Note}
		if o.Fires {
			e.UTC = o.At.UTC()
		}
		out = append(out, e)
	}
	return out, nil
}

// DispatchSchedules fires org's due schedule occurrences (D17): an
// occurrence more than two minutes late is missed — SKIP records it
// DISCARDED (MISSED); CATCH_UP fires at most the latest missed occurrence
// still inside its window. Each occurrence's key is
// schedule:<automation>:<instant>.
func (s *Service) DispatchSchedules(ctx context.Context, org ids.OrgID) (fired int, err error) {
	if ok, err := s.licensed(ctx); !ok {
		return 0, err
	}
	err = s.d.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		fired = 0
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ClaimDueSchedules(ctx, org, &now)
		if err != nil {
			return err
		}
		for _, r := range rows {
			n, err := s.dispatchOne(ctx, tx, r, now)
			if err != nil {
				return err
			}
			fired += n
		}
		return nil
	})
	return fired, err
}

func (s *Service) dispatchOne(ctx context.Context, tx db.TenantTx, r dbq.ClaimDueSchedulesRow, now time.Time) (int, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	advance := func(next, last *time.Time) error {
		_, err := q.AdvanceAutomationSchedule(ctx, dbq.AdvanceAutomationScheduleParams{
			NextFireAt: next, LastFireAt: last, OrgID: org, AutomationID: r.AutomationID, Expected: &r.NextFireAt,
		})
		return err
	}
	row, err := q.AutomationForTrigger(ctx, org, r.AutomationID)
	if db.IsNoRows(err) {
		return 0, q.DeleteAutomationSchedule(ctx, org, r.AutomationID)
	} else if err != nil {
		return 0, err
	}
	a, err := automationOf(row.ID, row.Name, row.State, row.Rollout, row.ServiceAccountID, row.OwnerUserID, row.VersionID, row.Definition)
	if err != nil {
		return 0, err
	}
	sch := a.Def.When.Schedule
	if sch == nil || a.Version != r.VersionID {
		// Activate re-materializes on every enable; a stale row stops.
		return 0, advance(nil, nil)
	}
	spec, err := cron.Parse(sch.Cron)
	if err != nil {
		return 0, advance(nil, nil)
	}
	loc, err := cron.LoadZone(sch.Timezone)
	if err != nil {
		return 0, advance(nil, nil)
	}
	gap := gapOf(sch)
	due := r.NextFireAt
	fireAt, missed := due, now.Sub(due) > MissedAfter
	if missed && sch.Missed == autodomain.MissedCatchUp {
		// The latest occurrence at or before now, if inside the window.
		latest := due
		for {
			o, ok := spec.Next(latest, loc, gap)
			if !ok || o.At.After(now) {
				break
			}
			latest = o.At.UTC()
		}
		window := min(max(sch.CatchUpWindow.D(), 0), MaxCatchUpWindow)
		if window == 0 {
			window = autodomain.DefaultCatchUpWindow
		}
		if now.Sub(latest) <= window {
			fireAt, missed = latest, false
		}
	}
	c := Candidate{
		Automation: a, Kind: autodomain.TriggerSchedule, Authenticity: autodomain.AuthScheduler,
		Detail:    map[string]string{"occurrence": fireAt.UTC().Format(time.RFC3339), "cron": sch.Cron, "timezone": sch.Timezone},
		SourceRef: "schedule:" + fireAt.UTC().Format(time.RFC3339), BaseKey: ScheduleKey(a.ID, fireAt),
		OccurredAt: fireAt, QueueOK: !missed,
	}
	fired := 0
	if missed {
		if err := s.recordMissed(ctx, tx, c); err != nil {
			return 0, err
		}
	} else if out, ok := s.FireInSavepoint(ctx, tx, c); ok && out.State.Started() {
		fired = 1
	}
	var next *time.Time
	if o, ok := spec.Next(maxTime(fireAt, now.Add(-MissedAfter)), loc, gap); ok {
		at := o.At.UTC()
		next = &at
	}
	return fired, advance(next, &fireAt)
}

// recordMissed records a missed occurrence DISCARDED (MISSED): it never
// starts work, now or on resume.
func (s *Service) recordMissed(ctx context.Context, tx db.TenantTx, c Candidate) error {
	q := dbq.New(tx)
	id := ids.NewV7()
	ref := autodomain.TriggerRef{ID: id, Automation: c.Automation.ID, Mode: autodomain.ModeLive, OccurredAt: c.OccurredAt}
	if c.Automation.Rollout == autodomain.RolloutShadow {
		ref.Mode = autodomain.ModeShadow
	}
	return s.insert(ctx, q, tx.OrgID(), id, c, ref, Lineage{Root: id}, StateDiscarded, ReasonMissed, nil)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// DaysNote explains a schedule whose day fields intersect (D75 T2): a
// stepped day field ("*/n") meets a restricted one, so a day must match
// both, as in Vixie cron. "" when the days are read the usual way.
func DaysNote(expr string) string {
	spec, err := cron.Parse(expr)
	if err != nil || !spec.Intersects() {
		return ""
	}
	return "A stepped day field (*/n) meets a restricted one, so a day must match both: " +
		"for example \"0 0 */2 * MON\" fires on odd-numbered Mondays only. " +
		"List the days instead to fire on either."
}
