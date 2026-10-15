// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// ErrRunNotActive refuses terminating a run that already ended.
var ErrRunNotActive = pcerr.New(pcerr.FailedPrecondition, "RUN_NOT_ACTIVE", "the run is not active")

// endTerminated is the end reason of a terminated run and of the approval
// requests it voids.
const endTerminated = "RUN_TERMINATED"

// Termination is a TERMINATE request (F134).
type Termination struct {
	Run        ids.UUID
	Reason     string
	CaseID     *ids.UUID
	IncidentID *ids.UUID
	Actor      reflexdomain.Subject
}

// TerminateIn terminates a run in tx (F134, D22): the run and its active
// descendants are revoked, so the Authority denies their next action
// (RUN_NOT_ACTIVE); the epoch is raised, so their outstanding permits fail
// BeginDispatch; their waiting approval requests are voided. Work already
// dispatched cannot be called back: each dispatch in flight is a material
// path, NOT_CANCELLABLE, confirmed once its dispatch ends, so the action is
// CONFIRMED only when nothing of the run is still running.
func (s *Containment) TerminateIn(ctx context.Context, tx db.TenantTx, t Termination) (reflexdomain.ContainResult, error) {
	org := tx.OrgID()
	q := dbq.New(tx)
	actor, source, evActor, err := actorOf(t.Actor)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if !reasonOK1000(t.Reason) {
		return reflexdomain.ContainResult{}, rdomain.ErrReason
	}
	if found, err := q.ScopeExists(ctx, rdomain.ScopeRun, org.UUID(), t.Run); err != nil {
		return reflexdomain.ContainResult{}, err
	} else if !found {
		return reflexdomain.ContainResult{}, ErrScopeNotFound
	}
	// The paths are those of the run while it is active: its agent's routes
	// and credentials too, so a bypass route keeps the action PARTIAL (D61).
	p, err := preview(ctx, tx, org, rdomain.Control{ScopeType: rdomain.ScopeRun, ScopeID: t.Run.String(), Control: rdomain.DenyAll})
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	rows, err := q.EndRunTree(ctx, dbq.EndRunTreeParams{OrgID: org, ID: t.Run, State: "REVOKED", Reason: "terminated"})
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if !ended(rows, t.Run) {
		return reflexdomain.ContainResult{}, ErrRunNotActive
	}
	runs := make([]ids.UUID, 0, len(rows))
	for _, r := range rows {
		runs = append(runs, r.ID)
	}
	waiting, err := q.WaitingRequestsOfRuns(ctx, org, runs)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	for _, w := range waiting {
		if err := pgapprovals.Invalidate(ctx, tx, org, w, endTerminated); err != nil {
			return reflexdomain.ContainResult{}, err
		}
	}
	if err := q.InsertContainment(ctx, org); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	epoch, err := q.BumpEpoch(ctx, org)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	a := pgresponse.Action{
		ID: ids.NewV7(), Kind: rdomain.KindTerminate, ScopeType: rdomain.ScopeRun, ScopeID: t.Run.String(), Reason: t.Reason,
		CaseID: t.CaseID, IncidentID: t.IncidentID, Actor: actor, Source: source,
	}
	if _, err := pgresponse.InsertAction(ctx, tx, org, a); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if err := q.SetResponseActionEpoch(ctx, pgtype.Int8{Int64: epoch, Valid: true}, org, a.ID); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	p.Runs = runs
	if err := planPaths(ctx, tx, a.ID, rdomain.KindTerminate, p, epoch); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	st, err := s.settle(ctx, tx, org, a.ID)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if err := recordAction(ctx, tx, evActor, "response.run_terminated", a.ID, map[string]string{
		"action": a.ID.String(), "run": t.Run.String(), "runs_revoked": strconv.Itoa(len(runs)),
		"approvals_voided": strconv.Itoa(len(waiting)), "epoch": strconv.FormatInt(epoch, 10),
	}, t.Reason); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	return reflexdomain.ContainResult{ActionID: a.ID, Status: string(st)}, nil
}

func ended(rows []dbq.PcRun, run ids.UUID) bool {
	for _, r := range rows {
		if r.ID == run {
			return true
		}
	}
	return false
}
