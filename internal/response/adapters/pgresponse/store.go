// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgresponse stores graduated containment (G0 M10 D21, D22):
// response actions, the containment controls the Authority enforces, and
// the paths each action must reach. Every write runs in the caller's tenant
// transaction; adding or lifting a control raises the org's containment
// epoch in that transaction (the table's trigger, HR-248).
package pgresponse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// ErrNotFound reports a missing action or control.
var ErrNotFound = errors.New("pgresponse: not found")

// ErrConflict reports a conditional update that found another state.
var ErrConflict = errors.New("pgresponse: state changed")

// Action is a response action as requested.
type Action struct {
	ID         ids.UUID
	Kind       string
	ScopeType  string
	ScopeID    string
	Control    string
	Operation  string
	Reason     string
	CaseID     *ids.UUID
	IncidentID *ids.UUID
	Actor      string
	Source     string
	// PreviewDigest is the preview the requester confirmed (D23); a skip
	// records its reason and the step-up behind it.
	PreviewDigest []byte
	SkipReason    string
	SkipStepUpAt  *time.Time
	// IdempotencyKey and RequestDigest are set together.
	IdempotencyKey string
	RequestDigest  []byte
}

// Added is a committed control: its action, the control and the epoch the
// change raised the org to.
type Added struct {
	ActionID  ids.UUID
	ControlID ids.UUID
	Epoch     int64
	At        time.Time
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// InsertAction records a response action in tx.
func InsertAction(ctx context.Context, tx db.TenantTx, org ids.OrgID, a Action) (time.Time, error) {
	return dbq.New(tx).InsertResponseAction(ctx, dbq.InsertResponseActionParams{
		OrgID: org, ID: a.ID, Kind: a.Kind, ScopeType: a.ScopeType, ScopeID: a.ScopeID, Control: opt(a.Control),
		Operation: opt(a.Operation), Reason: a.Reason, CaseID: a.CaseID, IncidentID: a.IncidentID, Actor: a.Actor,
		Source: a.Source, PreviewDigest: a.PreviewDigest, SkipPreview: a.SkipReason != "", SkipReason: opt(a.SkipReason),
		SkipStepUpAt: a.SkipStepUpAt, IdempotencyKey: opt(a.IdempotencyKey), RequestDigest: a.RequestDigest,
	})
}

// AddControl records a CONTAIN action and its control in tx, which raises
// the containment epoch (HR-248), and records the new epoch on the action.
// expires may be nil.
func AddControl(ctx context.Context, tx db.TenantTx, org ids.OrgID, a Action, expires *time.Time) (Added, error) {
	if a.Kind != rdomain.KindContain {
		return Added{}, fmt.Errorf("pgresponse: a control comes from a CONTAIN action, not %s", a.Kind)
	}
	q := dbq.New(tx)
	if err := q.InsertContainment(ctx, org); err != nil {
		return Added{}, err
	}
	if _, err := InsertAction(ctx, tx, org, a); err != nil {
		return Added{}, err
	}
	out := Added{ActionID: a.ID, ControlID: ids.NewV7()}
	at, err := q.InsertContainmentControl(ctx, dbq.InsertContainmentControlParams{
		OrgID: org, ID: out.ControlID, ActionID: a.ID, ScopeType: a.ScopeType, ScopeID: a.ScopeID, Control: a.Control,
		Operation: opt(a.Operation), Reason: a.Reason, CaseID: a.CaseID, IncidentID: a.IncidentID, CreatedBy: a.Actor,
		ExpiresAt: expires,
	})
	if err != nil {
		return Added{}, err
	}
	out.At = at
	cont, err := q.GetContainmentNow(ctx, org)
	if err != nil {
		return Added{}, err
	}
	out.Epoch = cont.Epoch
	if err := q.SetResponseActionEpoch(ctx, pgtype.Int8{Int64: out.Epoch, Valid: true}, org, a.ID); err != nil {
		return Added{}, err
	}
	return out, nil
}

// LiftControl lifts an active control through a restoration plan in tx,
// which raises the epoch (HR-248). Only restoration calls it (D24).
func LiftControl(ctx context.Context, tx db.TenantTx, org ids.OrgID, control, plan ids.UUID, by string) error {
	n, err := dbq.New(tx).LiftContainmentControl(ctx, dbq.LiftContainmentControlParams{
		OrgID: org, ID: control, LiftedBy: &by, RestorationID: &plan,
	})
	switch {
	case err != nil:
		return err
	case n == 0:
		return ErrConflict
	}
	return nil
}

// Paths returns an action's paths.
func Paths(ctx context.Context, tx db.TenantTx, org ids.OrgID, action ids.UUID) ([]rdomain.Path, error) {
	rows, err := dbq.New(tx).ListResponsePaths(ctx, org, action)
	if err != nil {
		return nil, err
	}
	out := make([]rdomain.Path, 0, len(rows))
	for _, r := range rows {
		out = append(out, rdomain.Path{
			ID: r.ID, Type: r.PathType, SubjectType: r.SubjectType, SubjectID: r.SubjectID, Material: r.Material,
			Control: r.Control, Status: rdomain.PathStatus(r.Status),
		})
	}
	return out, nil
}

// Unsettled returns up to limit actions whose status is not final, oldest
// first.
func Unsettled(ctx context.Context, tx db.TenantTx, org ids.OrgID, limit int32) ([]dbq.PcResponseAction, error) {
	return dbq.New(tx).UnsettledResponseActions(ctx, org, limit)
}

// Settle moves an action from expected to status, conditionally (HR-249).
func Settle(ctx context.Context, tx db.TenantTx, org ids.OrgID, action ids.UUID, expected, status rdomain.Status, futureConfirmed bool, historicalOpen []byte) error {
	if historicalOpen == nil {
		historicalOpen = []byte("[]")
	}
	n, err := dbq.New(tx).SettleResponseAction(ctx, dbq.SettleResponseActionParams{
		OrgID: org, ID: action, Expected: string(expected), Status: string(status),
		FutureConfirmed: futureConfirmed, HistoricalOpen: historicalOpen,
	})
	switch {
	case err != nil:
		return err
	case n == 0:
		return ErrConflict
	}
	return nil
}

// GetAction reads one action.
func GetAction(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (dbq.PcResponseAction, error) {
	a, err := dbq.New(tx).GetResponseAction(ctx, org, id)
	if db.IsNoRows(err) {
		return a, ErrNotFound
	}
	return a, err
}
