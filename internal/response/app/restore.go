// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ProposeRestore asks to lift the kill switch. A second person confirms it
// within RestoreWindow; until then nothing changes.
func (s *Service) ProposeRestore(ctx context.Context, su StepUp, reason string) (Restore, error) {
	if !reasonOK(reason) {
		return Restore{}, ErrReason
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Restore{}, err
	}
	var out Restore
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		st, now, err := s.state(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if err := person(ctx, q, c, su, now); err != nil {
			return err
		}
		switch {
		case !st.Engaged:
			return ErrNotEngaged
		case st.Pending != nil:
			return ErrRestorePending
		}
		if err := q.ExpireRestores(ctx, c.Org); err != nil {
			return err
		}
		r, err := q.InsertRestore(ctx, dbq.InsertRestoreParams{
			OrgID: c.Org, ID: ids.NewV7(), Epoch: st.Epoch, ProposedBy: c.Principal.ID, ProposerCred: su.Credential,
			Reason: reason, WindowMinutes: int32(RestoreWindow / time.Minute),
		})
		if db.IsUniqueViolation(err) {
			return ErrRestorePending
		} else if err != nil {
			return err
		}
		out = Restore{ID: r.ID, ProposedBy: r.ProposedBy, Reason: r.Reason, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
		if err := record(ctx, tx, c, auditkind.SecurityKillSwitchRestoreProposed, withReason(map[string]string{
			"proposal_id": r.ID.String(), "epoch": itoa(st.Epoch), "key_id": su.Credential.String(),
		}, reason)); err != nil {
			return err
		}
		return s.notifyOrg(ctx, tx, c, "security.kill_switch_restore_proposed")
	})
	return out, err
}

// ConfirmRestore lifts the kill switch: a second person, with a different
// security key and a fresh step-up, confirms a pending proposal. Clearing
// the switch raises the epoch in the same transaction.
func (s *Service) ConfirmRestore(ctx context.Context, su StepUp, id ids.UUID) (State, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return State{}, err
	}
	var out State
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		_, now, err := s.state(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if err := person(ctx, q, c, su, now); err != nil {
			return err
		}
		r, err := q.LockRestore(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrRestoreNotFound
		} else if err != nil {
			return err
		}
		switch {
		case r.State != "PENDING" || !r.Live:
			return ErrRestoreGone
		case r.ProposedBy == c.Principal.ID:
			return ErrSamePerson
		case r.ProposerCred == su.Credential:
			return ErrSameKey
		}
		epoch, err := q.ClearKillSwitch(ctx, c.Org)
		if db.IsNoRows(err) {
			return ErrNotEngaged
		} else if err != nil {
			return err
		}
		decider, cred := c.Principal.ID, su.Credential
		n, err := q.ConfirmRestore(ctx, dbq.ConfirmRestoreParams{DecidedBy: &decider, DeciderCred: &cred, OrgID: c.Org, ID: id})
		if err != nil {
			return err
		} else if n != 1 {
			return ErrRestoreGone
		}
		if err := record(ctx, tx, c, auditkind.SecurityKillSwitchRestored, map[string]string{
			"proposal_id": id.String(), "epoch": itoa(epoch), "proposed_by": r.ProposedBy.String(), "key_id": su.Credential.String(),
		}); err != nil {
			return err
		}
		if err := s.notifyOrg(ctx, tx, c, "security.kill_switch_restored"); err != nil {
			return err
		}
		out, _, err = s.state(ctx, q, c.Org)
		return err
	})
	return out, err
}

// CancelRestore withdraws a pending proposal. It keeps the kill switch
// engaged, so it needs the permission but no step-up; either person may
// cancel.
func (s *Service) CancelRestore(ctx context.Context, id ids.UUID) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if err := c.Require(td.PermContainmentKillSwitch, td.OrgPath(c.Org)); err != nil {
		return err
	}
	return s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockRestore(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrRestoreNotFound
		} else if err != nil {
			return err
		}
		if r.State != "PENDING" {
			return ErrRestoreGone
		}
		decider := c.Principal.ID
		if _, err := q.CancelRestore(ctx, &decider, c.Org, id); err != nil {
			return err
		}
		if err := record(ctx, tx, c, auditkind.SecurityKillSwitchRestoreCanceled, map[string]string{"proposal_id": id.String()}); err != nil {
			return err
		}
		return s.notifyOrg(ctx, tx, c, "security.kill_switch_restore_canceled")
	})
}
