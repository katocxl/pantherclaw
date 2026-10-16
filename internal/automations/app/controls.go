// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Owned failure kinds this package reports (D38).
const (
	FailureAuthorityChanged = "automation.authority_changed"
	FailureReviewDue        = "automation.review_due"
	FailureSweep            = "automation.sweep_failed"
)

var _ autoports.Pauser = (*Service)(nil)

// pausedPolicy is the version's paused-trigger policy.
func pausedPolicy(d *autodomain.Definition) autodomain.PausedTriggers {
	if d == nil || d.Paused == "" {
		return autodomain.PausedDiscard
	}
	return d.Paused
}

// pauseTx pauses one ACTIVE automation in tx and tells the triggers.
func (s *Service) pauseTx(ctx context.Context, tx db.TenantTx, q *dbq.Queries, a dbq.PcAutomation, reason autodomain.PauseReason) error {
	r := string(reason)
	n, err := q.PauseAutomation(ctx, &r, a.OrgID, a.ID)
	if err != nil || n == 0 {
		return err
	}
	if s.Triggers != nil {
		var d *autodomain.Definition
		if a.EnabledVersionID != nil {
			if v, err := loadVersion(ctx, q, a.OrgID, *a.EnabledVersionID, false); err == nil {
				d, _ = definitionOf(v)
			}
		}
		return s.Triggers.Deactivate(ctx, tx.Pgx(), a.ID, pausedPolicy(d))
	}
	return nil
}

// Pause implements autoports.Pauser (D14, D31): it pauses the ACTIVE
// automations sel chooses, in the caller's transaction, and returns them.
// The caller records the pause in its own audit event (the kill switch
// records how many it paused).
func (s *Service) Pause(ctx context.Context, tx pgx.Tx, org ids.OrgID, sel autodomain.PauseSelector, reason autodomain.PauseReason) ([]ids.UUID, error) {
	if !reason.Valid() {
		return nil, ErrState
	}
	q := dbq.New(tx)
	live, err := q.LiveAutomationVersions(ctx, org)
	if err != nil {
		return nil, err
	}
	var targets []ids.UUID
	for _, l := range live {
		if !sel.All && !slices.Contains(sel.Automations, l.ID) && !affects(l.Definition, sel) {
			continue
		}
		targets = append(targets, l.ID)
	}
	if len(targets) == 0 {
		return nil, nil
	}
	r := string(reason)
	paused, err := q.PauseActiveAutomations(ctx, dbq.PauseActiveAutomationsParams{Reason: &r, OrgID: org, Ids: targets})
	if err != nil {
		return nil, err
	}
	for _, id := range paused {
		if s.Triggers != nil {
			i := slices.IndexFunc(live, func(l dbq.LiveAutomationVersionsRow) bool { return l.ID == id })
			d, _ := autodomain.Parse(live[i].Definition)
			if err := s.Triggers.Deactivate(ctx, tx, id, pausedPolicy(d)); err != nil {
				return nil, err
			}
		}
	}
	return paused, nil
}

// affects reports whether a definition's ceiling reaches the selector's
// agent or operation.
func affects(raw []byte, sel autodomain.PauseSelector) bool {
	if sel.AffectingAgent == nil && sel.AffectingOperation == "" {
		return false
	}
	d, err := autodomain.Parse(raw)
	if err != nil || d.Authority.Ceiling == nil {
		return false
	}
	if sel.AffectingAgent != nil && slices.Contains(d.CeilingAgents(), *sel.AffectingAgent) {
		return true
	}
	ops := d.Authority.Ceiling.Bounds.Operations
	return sel.AffectingOperation != "" && ops != nil && ops.Matches(sel.AffectingOperation)
}

// failure reports an owned failure to the automation's owner (nil sink:
// nothing).
func (s *Service) failure(ctx context.Context, tx db.TenantTx, a dbq.PcAutomation, kind, summary, next, dedupe string) error {
	if s.Failures == nil {
		return nil
	}
	owner := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: a.OwnerUserID.String()}
	_, err := s.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: a.OrgID, Kind: kind, Summary: summary, NextStep: next,
		Scope: []reflexdomain.Subject{{Type: reflexdomain.SubjectAutomation, ID: a.ID.String()}},
		Owner: &owner, Deadline: s.now().Add(7 * 24 * time.Hour), DedupeKey: dedupe,
	})
	return err
}

// VoidCeiling voids an ACTIVE ceiling in its own transaction (D57): the
// ceiling VOID with the reason, the automation PAUSED (CEILING_VOID) and an
// owned failure for its owner. The engine calls it after a step failed
// with CEILING_VOID; the ceiling sweep calls it too. Shadow and simulation
// never do.
func (s *Service) VoidCeiling(ctx context.Context, org ids.OrgID, ceiling ids.UUID, reason string) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return s.endCeilingTx(ctx, tx, org, ceiling, autodomain.CeilingVoid, reason, autodomain.PauseCeilingVoid)
	})
}

func (s *Service) endCeilingTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, ceiling ids.UUID, state autodomain.CeilingState,
	reason string, pause autodomain.PauseReason,
) error {
	q := dbq.New(tx)
	c, err := q.LockAutomationCeiling(ctx, org, ceiling)
	if db.IsNoRows(err) || (err == nil && c.State != string(autodomain.CeilingActive)) {
		return nil // already ended
	} else if err != nil {
		return err
	}
	var vr *string
	if state == autodomain.CeilingVoid {
		vr = &reason
	}
	if err := oneRow(q.EndAutomationCeiling(ctx, dbq.EndAutomationCeilingParams{State: string(state), VoidReason: vr, OrgID: org, ID: ceiling})); err != nil {
		return err
	}
	a, err := loadAutomation(ctx, q, org, c.AutomationID, true)
	if err != nil {
		return err
	}
	if err := s.pauseTx(ctx, tx, q, a, pause); err != nil {
		return err
	}
	// Authority that changed revokes what was issued under it (D91 K2).
	var eff ControlEffect
	if err := s.revokeGrantsTx(ctx, tx, q, a, grantsapp.RevokeScopeCeiling, ceiling, "ceiling "+strings.ToLower(string(state)), &eff); err != nil {
		return err
	}
	if err := record(ctx, tx, systemActor, "automation.ceiling_ended", a.ID, map[string]string{
		"ceiling": ceiling.String(), "state": string(state), "reason": reason,
		"grants_revoked": itoa(len(eff.GrantsRevoked)), "runs_ended": itoa(len(eff.RunsEnded)),
	}); err != nil {
		return err
	}
	return s.failure(ctx, tx, a, FailureAuthorityChanged,
		"Automation "+a.Name+" was paused: its ceiling is "+string(state)+" ("+reason+").",
		"Review the automation, then enable a new version or confirm its authority again.", "ceiling:"+ceiling.String())
}

// revokeGrantsTx revokes the automation's grants of scope (CEILING: those
// of one authority row; AUTOMATION: those of every row, whatever its
// state) and every grant delegated from them, and ends the automation runs
// they bound, adding both to eff.
func (s *Service) revokeGrantsTx(ctx context.Context, tx db.TenantTx, q *dbq.Queries, a dbq.PcAutomation, scope string,
	ceiling ids.UUID, reason string, eff *ControlEffect,
) error {
	if s.Grants == nil {
		return ErrGrantsUnavailable
	}
	revoked, err := s.Grants.RevokeForAutomationTx(ctx, tx, grantsapp.AutomationRevoke{
		Org: a.OrgID, Automation: a.ID, Ceiling: ceiling, ServiceAccount: a.ServiceAccountID, Scope: scope, Reason: reason,
	})
	if err != nil {
		return err
	}
	for _, g := range revoked {
		eff.GrantsRevoked = append(eff.GrantsRevoked, g.UUID())
	}
	if s.Runs == nil || len(eff.GrantsRevoked) == 0 {
		return nil
	}
	runs, err := q.ActiveRunsOfGrants(ctx, a.OrgID, eff.GrantsRevoked)
	if err != nil {
		return err
	}
	for _, r := range runs {
		if r.AutomationExecutionID == nil || slices.Contains(eff.RunsEnded, r.ID) {
			continue
		}
		if _, err := s.Runs.EndForAutomationTx(ctx, tx, a.OrgID, *r.AutomationExecutionID, a.ServiceAccountID, r.ID, "authority_revoked"); err != nil {
			return err
		}
		eff.RunsEnded = append(eff.RunsEnded, r.ID)
	}
	return nil
}

// PauseAutomation stops new executions (HR-283); active executions go on
// unless cancelActive is set, when the engine cancels them at their next
// boundary.
func (s *Service) PauseAutomation(ctx context.Context, automation ids.UUID, cancelActive bool, reason string) (Automation, ControlEffect, error) {
	c, err := manager(ctx)
	if err != nil {
		return Automation{}, ControlEffect{}, err
	}
	var out Automation
	var eff ControlEffect
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := loadAutomation(ctx, q, c.Org, automation, true)
		if err != nil {
			return err
		}
		if a.State != string(autodomain.StateActive) {
			return ErrState
		}
		if cancelActive && s.Executions == nil {
			return ErrExecutionsUnavailable // never report a cancellation that did not happen (D91 K10)
		}
		if err := s.pauseTx(ctx, tx, q, a, autodomain.PauseUser); err != nil {
			return err
		}
		if cancelActive {
			e, err := s.Executions.CancelActive(ctx, tx.Pgx(), c.Org, a.ID, autodomain.ReasonCancelledByUser)
			if err != nil {
				return err
			}
			eff.add(e)
		}
		r, err := loadAutomation(ctx, q, c.Org, a.ID, false)
		if err != nil {
			return err
		}
		out = automationView(r)
		return record(ctx, tx, c.Actor(), "automation.paused", a.ID, map[string]string{
			"reason": string(autodomain.PauseUser), "cancel_active": boolString(cancelActive), "note_sha256": noteDigest(reason),
			"executions_canceled": itoa(len(eff.ExecutionsAffected)),
		})
	})
	return out, eff, err
}

// ResumeAutomation revalidates the owner, ceiling and its approvers, the
// identity, the principal, the edition and the kill switch, then resumes;
// missed irreversible work is never replayed (HR-283).
func (s *Service) ResumeAutomation(ctx context.Context, automation ids.UUID) (Automation, int, error) {
	c, err := manager(ctx)
	if err != nil {
		return Automation{}, 0, err
	}
	if err := s.edition(ctx); err != nil {
		return Automation{}, 0, err
	}
	var out Automation
	var replayed int
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := loadAutomation(ctx, q, c.Org, automation, true)
		if err != nil {
			return err
		}
		if a.State != string(autodomain.StatePaused) || a.EnabledVersionID == nil {
			return ErrState
		}
		if err := s.revalidate(ctx, tx, q, a); err != nil {
			return err
		}
		if err := oneRow(q.ResumeAutomation(ctx, c.Org, a.ID)); err != nil {
			return err
		}
		if s.Triggers != nil {
			if err := s.Triggers.Activate(ctx, tx.Pgx(), a.ID, *a.EnabledVersionID); err != nil {
				return err
			}
			if replayed, err = s.Triggers.Resume(ctx, tx.Pgx(), a.ID); err != nil {
				return err
			}
		}
		r, err := loadAutomation(ctx, q, c.Org, a.ID, false)
		if err != nil {
			return err
		}
		out = automationView(r)
		return record(ctx, tx, c.Actor(), "automation.resumed", a.ID, map[string]string{
			"was": deref2(a.PauseReason), "replayed": itoa(replayed),
		})
	})
	return out, replayed, err
}

func deref2(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// revalidate checks what an automation needs to act (HR-273): owner
// active, ACTIVE ceiling of the enabled version before its review date
// with qualifying approvers, identity and principal active, kill switch
// clear.
func (s *Service) revalidate(ctx context.Context, tx db.TenantTx, q *dbq.Queries, a dbq.PcAutomation) error {
	if ok, err := q.SubjectUserActive(ctx, a.OrgID, a.OwnerUserID); err != nil && !db.IsNoRows(err) {
		return err
	} else if !ok {
		return ErrOwner
	}
	if st, err := q.ServiceAccountState(ctx, a.OrgID, a.ServiceAccountID); err != nil || st != "ACTIVE" {
		return ErrRevalidation
	}
	if contained, err := q.IdentityContained(ctx, a.OrgID, a.ServiceAccountID); err != nil {
		return err
	} else if contained {
		return ErrContained
	}
	if err := q.InsertContainment(ctx, a.OrgID); err != nil {
		return err
	}
	if k, err := q.GetKillSwitch(ctx, a.OrgID); err != nil {
		return err
	} else if k.KillSwitch {
		return ErrKillSwitch
	}
	c, err := q.GetActiveAutomationCeiling(ctx, a.OrgID, a.ID)
	if db.IsNoRows(err) {
		return ErrRevalidation
	} else if err != nil {
		return err
	}
	if !c.InReview || c.VersionID != *a.EnabledVersionID {
		return ErrRevalidation
	}
	v, err := loadVersion(ctx, q, a.OrgID, c.VersionID, false)
	if err != nil {
		return err
	}
	d, err := definitionOf(v)
	if err != nil {
		return err
	}
	if p := principalOf(d, a.ServiceAccountID); p.Kind == "user" {
		if ok, err := q.SubjectUserActive(ctx, a.OrgID, p.ID); err != nil && !db.IsNoRows(err) {
			return err
		} else if !ok {
			return ErrRevalidation
		}
	}
	ok, _, err := s.Check(ctx, tx.Pgx(), autodomain.CeilingCheck{
		Org: a.OrgID, Automation: a.ID, Ceiling: c.ID, Approvers: c.ApprovedBy, Agents: d.CeilingAgents(), Kinds: d.Kinds(),
	})
	if err != nil {
		return err
	}
	if !ok {
		return ErrRevalidation
	}
	for _, k := range d.Kinds() {
		if !s.entitled(ctx, autodomain.Catalog[k].Edition) {
			return ErrEdition
		}
	}
	return nil
}

// RetireAutomation cancels active executions, retires the triggers, the
// versions and the ceiling and disables the identity. Final.
func (s *Service) RetireAutomation(ctx context.Context, automation ids.UUID, reason string) (Automation, ControlEffect, error) {
	c, err := manager(ctx)
	if err != nil {
		return Automation{}, ControlEffect{}, err
	}
	var out Automation
	var eff ControlEffect
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := loadAutomation(ctx, q, c.Org, automation, true)
		if err != nil {
			return err
		}
		if a.State == string(autodomain.StateRetired) {
			return ErrState
		}
		if s.Executions == nil {
			sa := a.ServiceAccountID
			if n, err := q.CountActiveAutomationRuns(ctx, c.Org, &sa); err != nil {
				return err
			} else if n > 0 {
				return ErrExecutionsUnavailable // D91 K10
			}
		} else {
			e, err := s.Executions.CancelActive(ctx, tx.Pgx(), c.Org, a.ID, autodomain.ReasonCancelledByUser)
			if err != nil {
				return err
			}
			eff.add(e)
		}
		if s.Triggers != nil {
			if err := s.Triggers.Deactivate(ctx, tx.Pgx(), a.ID, autodomain.PausedDiscard); err != nil {
				return err
			}
		}
		if _, err := q.EndActiveAutomationCeilings(ctx, dbq.EndActiveAutomationCeilingsParams{
			State: string(autodomain.CeilingRevoked), OrgID: c.Org, AutomationID: a.ID,
		}); err != nil {
			return err
		}
		if _, err := q.RetireAutomationVersions(ctx, c.Org, a.ID); err != nil {
			return err
		}
		if err := oneRow(q.RetireAutomation(ctx, c.Org, a.ID)); err != nil {
			return err
		}
		aid := a.ID
		if _, err := q.DisableAutomationServiceAccount(ctx, c.Org, a.ServiceAccountID, &aid); err != nil {
			return err
		}
		if s.Changes != nil {
			if _, err := s.Changes.Void(ctx, tx, c, changes.DomainAutomation, a.ID, VoidState); err != nil {
				return err
			}
		}
		r, err := loadAutomation(ctx, q, c.Org, a.ID, false)
		if err != nil {
			return err
		}
		out = automationView(r)
		return record(ctx, tx, c.Actor(), "automation.retired", a.ID, map[string]string{
			"note_sha256": noteDigest(reason), "executions_canceled": itoa(len(eff.ExecutionsAffected)),
		})
	})
	return out, eff, err
}

// RevokeAuthority revokes the ceiling and every grant issued under it,
// ends their runs and pauses the automation (AUTHORITY_REVOKED); it
// reports what it verifiably did (D28, HR-283).
func (s *Service) RevokeAuthority(ctx context.Context, automation ids.UUID, reason string) (Automation, ControlEffect, error) {
	c, err := manager(ctx)
	if err != nil {
		return Automation{}, ControlEffect{}, err
	}
	if reason == "" || len(reason) > 256 {
		return Automation{}, ControlEffect{}, ErrState
	}
	var out Automation
	var eff ControlEffect
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := loadAutomation(ctx, q, c.Org, automation, true)
		if err != nil {
			return err
		}
		if a.State == string(autodomain.StateRetired) {
			return ErrState
		}
		// The ACTIVE row, if any, ends; every grant of every row the
		// automation ever had is revoked (D91 K2): a superseded, void or
		// expired row's grants live until they expire otherwise.
		ended, err := q.EndActiveAutomationCeilings(ctx, dbq.EndActiveAutomationCeilingsParams{
			State: string(autodomain.CeilingRevoked), OrgID: c.Org, AutomationID: a.ID,
		})
		if err != nil {
			return err
		}
		if err := s.revokeGrantsTx(ctx, tx, q, a, grantsapp.RevokeScopeAutomation, ids.UUID{}, "authority revoked", &eff); err != nil {
			return err
		}
		if a.State == string(autodomain.StateActive) {
			if err := s.pauseTx(ctx, tx, q, a, autodomain.PauseAuthorityRevoked); err != nil {
				return err
			}
		}
		if s.Executions != nil {
			e, err := s.Executions.CancelActive(ctx, tx.Pgx(), c.Org, a.ID, autodomain.ReasonAuthorityChanged)
			if err != nil {
				return err
			}
			eff.add(e)
		}
		r, err := loadAutomation(ctx, q, c.Org, a.ID, false)
		if err != nil {
			return err
		}
		out = automationView(r)
		return record(ctx, tx, c.Actor(), "automation.authority_revoked", a.ID, map[string]string{
			"ceilings_revoked": itoa(len(ended)), "grants_revoked": itoa(len(eff.GrantsRevoked)), "runs_ended": itoa(len(eff.RunsEnded)),
			"note_sha256": noteDigest(reason),
		})
	})
	return out, eff, err
}

func noteDigest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hexDigest(sum[:])
}
