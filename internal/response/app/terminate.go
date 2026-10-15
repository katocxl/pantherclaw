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
	gws, err := q.ScopeGateways(ctx, org, rdomain.ScopeRun, t.Run.String())
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	need := map[string]string{"epoch": strconv.FormatInt(epoch, 10)}
	for _, g := range gws {
		if err := addPath(ctx, q, org, a.ID, rdomain.PathGateway, "gateway", g.String(), true, pathEpoch, rdomain.PathPending, need); err != nil {
			return reflexdomain.ContainResult{}, err
		}
	}
	inflight, err := q.InFlightTransactions(ctx, org, runs)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	notCancellable := "NOT_CANCELLABLE"
	for _, f := range inflight {
		if err := addPathCancel(ctx, q, org, a.ID, f, notCancellable); err != nil {
			return reflexdomain.ContainResult{}, err
		}
	}
	st, err := s.settle(ctx, tx, org, a.ID)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if err := recordAction(ctx, tx, evActor, "response.run_terminated", a.ID, map[string]string{
		"action": a.ID.String(), "run": t.Run.String(), "runs_revoked": strconv.Itoa(len(runs)),
		"approvals_voided": strconv.Itoa(len(waiting)), "in_flight": strconv.Itoa(len(inflight)), "epoch": strconv.FormatInt(epoch, 10),
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

func addPathCancel(ctx context.Context, q *dbq.Queries, org ids.OrgID, action ids.UUID, f dbq.InFlightTransactionsRow, capability string) error {
	ev, err := canonicalEvidence(map[string]string{"run": f.RunID.String(), "permit": f.State})
	if err != nil {
		return err
	}
	return q.InsertResponsePath(ctx, dbq.InsertResponsePathParams{
		OrgID: org, ActionID: action, ID: ids.NewV7(), PathType: rdomain.PathInFlight, SubjectType: "transaction",
		SubjectID: f.ID.String(), Material: true, Control: pathDispatched, Status: string(rdomain.PathPending), Evidence: ev,
		CancelCapability: &capability,
	})
}
