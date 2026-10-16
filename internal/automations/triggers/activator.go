// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/cron"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Activator implements autoports.TriggerActivator (D11, D17, D23, D58):
// core calls it in the transaction that enables, pauses or resumes an
// automation.
type Activator struct{ s *Service }

var _ autoports.TriggerActivator = Activator{}

// Activator returns the service's TriggerActivator.
func (s *Service) Activator() Activator { return Activator{s: s} }

// ErrNoAutomation reports an automation the activator cannot see.
var ErrNoAutomation = errors.New("triggers: automation not found")

func adopt(ctx context.Context, tx pgx.Tx) (db.TenantTx, ids.OrgID, error) {
	var org string
	if err := tx.QueryRow(ctx, "SELECT coalesce(current_setting('app.org_id', true), '')").Scan(&org); err != nil {
		return db.TenantTx{}, ids.OrgID{}, err
	}
	o, err := ids.Parse[ids.Org](org)
	if err != nil {
		return db.TenantTx{}, ids.OrgID{}, db.ErrNoTenant
	}
	t, err := db.AdoptTenantTx(ctx, tx, o)
	return t, o, err
}

// Activate materializes the enabled version's triggers: a schedule row
// for a schedule trigger (next occurrence after now), none otherwise.
// Event, inbound, condition, threshold and manual triggers are matched
// against the enabled version when they occur. Condition episodes of an
// earlier version end.
func (a Activator) Activate(ctx context.Context, tx pgx.Tx, automation, version ids.UUID) error {
	t, org, err := adopt(ctx, tx)
	if err != nil {
		return err
	}
	q := dbq.New(t)
	v, err := q.AutomationVersionDefinition(ctx, org, version)
	if db.IsNoRows(err) {
		return ErrNoAutomation
	} else if err != nil {
		return err
	}
	if v.AutomationID != automation {
		return fmt.Errorf("triggers: version %s is not a version of automation %s", version, automation)
	}
	def, err := autodomain.Parse(v.Definition)
	if err != nil {
		return err
	}
	if err := q.ClearConditionEpisodes(ctx, org, automation); err != nil {
		return err
	}
	sch := def.When.Schedule
	if sch == nil {
		return q.DeleteAutomationSchedule(ctx, org, automation)
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	next, err := nextFire(sch, now)
	if err != nil {
		return err
	}
	return q.UpsertAutomationSchedule(ctx, dbq.UpsertAutomationScheduleParams{
		OrgID: org, AutomationID: automation, VersionID: version, Cron: sch.Cron, Timezone: sch.Timezone, NextFireAt: next,
	})
}

// nextFire is the schedule's first firing occurrence after t (nil when it
// never fires again).
func nextFire(sch *autodomain.Schedule, t time.Time) (*time.Time, error) {
	spec, err := cron.Parse(sch.Cron)
	if err != nil {
		return nil, err
	}
	loc, err := cron.LoadZone(sch.Timezone)
	if err != nil {
		return nil, err
	}
	o, ok := spec.Next(t, loc, gapOf(sch))
	if !ok {
		return nil, nil
	}
	at := o.At.UTC()
	return &at, nil
}

func gapOf(sch *autodomain.Schedule) cron.Gap {
	if sch.DSTGap == autodomain.DSTShift {
		return cron.GapShift
	}
	return cron.GapSkip
}

// Deactivate stops the schedule while paused; with policy DISCARD any
// queued triggers are discarded (D23). Retiring passes DISCARD too.
func (a Activator) Deactivate(ctx context.Context, tx pgx.Tx, automation ids.UUID, policy autodomain.PausedTriggers) error {
	t, org, err := adopt(ctx, tx)
	if err != nil {
		return err
	}
	q := dbq.New(t)
	if _, err := q.SetAutomationScheduleState(ctx, dbq.SetAutomationScheduleStateParams{
		State: "PAUSED", OrgID: org, AutomationID: automation,
	}); err != nil {
		return err
	}
	if policy == autodomain.PausedDiscard || policy == "" {
		reason := ReasonPaused
		_, err = q.DiscardQueuedTriggers(ctx, &reason, org, automation)
	}
	return err
}

// Resume restarts the schedule from now (a missed occurrence under SKIP
// never fires; CATCH_UP keeps its due occurrence for the dispatcher's
// window) and replays queued triggers of the enabled version through the
// Starter, which revalidates. Queued triggers of another version expire
// (VERSION_CHANGED, D58), and expired ones are marked so.
func (a Activator) Resume(ctx context.Context, tx pgx.Tx, automation ids.UUID) (int, error) {
	t, org, err := adopt(ctx, tx)
	if err != nil {
		return 0, err
	}
	q := dbq.New(t)
	row, err := q.AutomationForTrigger(ctx, org, automation)
	if db.IsNoRows(err) {
		return 0, ErrNoAutomation
	} else if err != nil {
		return 0, err
	}
	au, err := automationOf(row.ID, row.Name, row.State, row.Rollout, row.ServiceAccountID, row.OwnerUserID, row.VersionID, row.Definition)
	if err != nil {
		return 0, err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return 0, err
	}
	if sch := au.Def.When.Schedule; sch != nil {
		var next *time.Time
		if sch.Missed != autodomain.MissedCatchUp {
			if next, err = nextFire(sch, now); err != nil {
				return 0, err
			}
		}
		if _, err := q.SetAutomationScheduleState(ctx, dbq.SetAutomationScheduleStateParams{
			State: "ACTIVE", NextFireAt: next, OrgID: org, AutomationID: automation,
		}); err != nil {
			return 0, err
		}
	}
	if _, err := q.ExpireQueuedTriggers(ctx, org); err != nil {
		return 0, err
	}
	rows, err := q.LockQueuedTriggers(ctx, org, automation)
	if err != nil {
		return 0, err
	}
	replayed := 0
	for _, r := range rows {
		var to State
		var reason string
		var out Outcome
		switch {
		case r.VersionID != au.Version:
			to, reason = StateExpired, ReasonVersionChanged
		case au.State != autodomain.StateActive:
			continue
		default:
			ref, err := queuedRef(org, au, r)
			if err != nil {
				to, reason = StateRefusedInvalid, ReasonParams
				break
			}
			n, err := q.CountStartedTriggersSince(ctx, org, automation, now.Add(-time.Hour))
			if err != nil {
				return replayed, err
			}
			if int(n) >= au.Def.Limits.PerHourOrDefault() {
				to, reason = StateRefusedLimit, ReasonHourlyCap
				break
			}
			from := StateQueued
			st := StateAccepted
			if ref.Mode == autodomain.ModeShadow {
				st = StateShadow
			}
			if _, err := q.SetTriggerState(ctx, dbq.SetTriggerStateParams{
				ToState: string(st), OrgID: org, ID: r.ID, FromState: string(from),
			}); err != nil {
				return replayed, err
			}
			out, err = a.s.start(ctx, t, ref, Outcome{Trigger: r.ID, State: st})
			if err != nil {
				return replayed, err
			}
			if out.State.Started() {
				replayed++
				if err := a.s.audit(ctx, t, "automation.triggered", au.ID, r.ID, map[string]string{
					"version": au.Version.String(), "kind": r.Kind, "mode": string(ref.Mode), "replayed": "true",
					"authenticity": r.Authenticity, "execution": out.Execution.String(),
				}); err != nil {
					return replayed, err
				}
			}
			continue
		}
		if _, err := q.SetTriggerState(ctx, dbq.SetTriggerStateParams{
			ToState: string(to), Reason: &reason, OrgID: org, ID: r.ID, FromState: string(StateQueued),
		}); err != nil {
			return replayed, err
		}
		if err := q.ReleaseDedupeKeys(ctx, org, r.ID); err != nil {
			return replayed, err
		}
	}
	return replayed, nil
}

func queuedRef(org ids.OrgID, au Automation, r dbq.LockQueuedTriggersRow) (autodomain.TriggerRef, error) {
	ref := autodomain.TriggerRef{
		ID: r.ID, Org: org, Automation: au.ID, Version: r.VersionID, Kind: autodomain.TriggerKind(r.Kind),
		Mode: autodomain.Mode(r.Mode), Root: r.RootTriggerID, Ancestry: r.Ancestry, Depth: int(r.Depth),
		OccurredAt: r.OccurredAt,
	}
	if err := json.Unmarshal(r.Params, &ref.Params); err != nil {
		return ref, err
	}
	var subs []reflexdomain.Subject
	if err := json.Unmarshal(r.Subjects, &subs); err != nil {
		return ref, err
	}
	var ev []reflexdomain.EvidenceRef
	if err := json.Unmarshal(r.Evidence, &ev); err != nil {
		return ref, err
	}
	ref.Subjects, ref.Evidence = subs, ev
	return ref, nil
}
