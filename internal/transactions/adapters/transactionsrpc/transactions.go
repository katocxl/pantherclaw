// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package transactionsrpc serves TransactionService over Connect (G0 M7
// track A): the transaction list and the evidence explorer.
package transactionsrpc

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/runs/adapters/runsrpc"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Transactions serves TransactionService.
type Transactions struct {
	pantherclawv1connect.UnimplementedTransactionServiceHandler
	svc *app.Explorer
}

// New returns the TransactionService handler.
func New(svc *app.Explorer) *Transactions { return &Transactions{svc: svc} }

// ListTransactions implements TransactionServiceHandler.
func (s *Transactions) ListTransactions(ctx context.Context, req *pantherclawv1.ListTransactionsRequest) (*pantherclawv1.ListTransactionsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var f app.Filter
	for _, p := range []struct {
		set bool
		s   string
		to  **ids.UUID
	}{
		{req.RunId != nil, req.GetRunId(), &f.Run},
		{req.AgentId != nil, req.GetAgentId(), &f.Agent},
		{req.ConnectionId != nil, req.GetConnectionId(), &f.Connection},
	} {
		if !p.set {
			continue
		}
		id, err := runsrpc.ParseID(p.s)
		if err != nil {
			return nil, err
		}
		*p.to = &id
	}
	for _, d := range req.GetDecisions() {
		f.Decisions = append(f.Decisions, strings.TrimPrefix(d.String(), "DECISION_"))
	}
	for _, e := range req.GetExecutionStates() {
		f.Executions = append(f.Executions, domain.ExecutionState(strings.TrimPrefix(e.String(), "EXECUTION_STATE_")))
	}
	for _, e := range req.GetEffectStates() {
		f.Effects = append(f.Effects, domain.EffectState(strings.TrimPrefix(e.String(), "EFFECT_STATE_")))
	}
	if req.StartTime != nil {
		t := req.GetStartTime().AsTime()
		f.Start = &t
	}
	if req.EndTime != nil {
		t := req.GetEndTime().AsTime()
		f.End = &t
	}
	p, err := s.svc.ListTransactions(ctx, pr, f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListTransactionsResponse{NextPageToken: p.Next}
	for _, t := range p.Items {
		out.Transactions = append(out.Transactions, TransactionProto(t))
	}
	return out, nil
}

// GetTransactionEvidence implements TransactionServiceHandler.
func (s *Transactions) GetTransactionEvidence(ctx context.Context, req *pantherclawv1.GetTransactionEvidenceRequest) (*pantherclawv1.GetTransactionEvidenceResponse, error) {
	id, err := runsrpc.ParseID(req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.svc.TransactionEvidence(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetTransactionEvidenceResponse{Transaction: TransactionProto(e.Transaction)}
	for _, d := range e.Decisions {
		out.DecisionReceipts = append(out.DecisionReceipts, &pantherclawv1.DecisionReceipt{
			Evaluation: int32(d.Evaluation), ReceiptJws: d.JWS, Integrity: integrity(d.Integrity), //nolint:gosec // G115: at most 64
			CreateTime: timestamppb.New(d.Created),
		})
	}
	if b := e.Basis; b != nil {
		out.Basis = &pantherclawv1.DecisionBasis{
			PolicyVersion: b.Policy, DefinitionDigest: b.Definition, FactsDigest: b.Facts, BasisDigest: b.Digest,
			ApprovalRequestId: b.Approval, ConnectionId: b.Connection,
		}
		for _, l := range b.Levels {
			out.Basis.Levels = append(out.Basis.Levels, &pantherclawv1.AuthorityLevel{Kind: l.Kind, Id: l.ID, Revision: int32(l.Revision)}) //nolint:gosec // G115: a revision
		}
	}
	if x := e.Execution; x != nil {
		out.Execution = &pantherclawv1.Execution{
			AttemptId: x.Attempt.String(), PermitId: x.Permit.String(), Outcome: outcome(x.Outcome),
			TargetStatus: int32(x.TargetStatus), RecordedBy: x.RecordedBy, TargetRef: x.TargetRef, //nolint:gosec // G115: an HTTP status
			DispatchMs: int32(x.DispatchMS), DispatchTime: timestamp(x.Dispatched), RecordTime: timestamppb.New(x.Recorded), //nolint:gosec // G115: milliseconds of one dispatch
			ReceiptJws: x.JWS, Integrity: integrity(x.Integrity),
		}
	}
	for _, o := range e.Observations {
		p := &pantherclawv1.Observation{
			Id: o.ID.String(), Source: o.Source, GatewayId: o.Gateway.String(), HttpStatus: int32(o.HTTPStatus), //nolint:gosec // G115: an HTTP status
			Outcome: outcome(o.Outcome), Found: o.Found, Complete: o.Complete, Fields: o.Fields,
			ResponseSha256: hex.EncodeToString(o.ResponseDigest), ObserveTime: timestamppb.New(o.Observed),
		}
		if o.Verification != nil {
			p.VerificationId = o.Verification.String()
		}
		out.Observations = append(out.Observations, p)
	}
	for _, f := range e.Effects {
		out.EffectReceipts = append(out.EffectReceipts, &pantherclawv1.EffectReceipt{
			Seq: int32(f.Seq), State: effectState(f.State), LevelRequired: level(string(f.Required)), //nolint:gosec // G115: at most 1000
			LevelAchieved: level(string(f.Achieved)), Basis: f.Basis, ReceiptJws: f.JWS, Integrity: integrity(f.Integrity),
			CreateTime: timestamppb.New(f.Created),
		})
	}
	for _, k := range e.Reconciliations {
		out.Reconciliations = append(out.Reconciliations, ReconciliationProto(k))
	}
	for _, l := range e.Links {
		out.Links = append(out.Links, &pantherclawv1.TransactionLink{
			FromTransactionId: l.From.String(), ToTransactionId: l.To.String(),
			Kind:      linkKind(l.Kind),
			CreatedBy: l.CreatedBy, CreateTime: timestamppb.New(l.Created),
		})
	}
	return out, nil
}

// TransactionProto converts a transaction summary.
func TransactionProto(t app.Summary) *pantherclawv1.Transaction {
	p := &pantherclawv1.Transaction{
		Id: t.ID.String(), RunId: t.Run.String(), AgentId: t.Agent.String(), Operation: t.Operation,
		Decision:       pantherclawv1.Decision(pantherclawv1.Decision_value["DECISION_"+t.Decision]),
		ReasonCode:     t.Reason,
		ExecutionState: pantherclawv1.ExecutionState(pantherclawv1.ExecutionState_value["EXECUTION_STATE_"+string(t.Execution)]),
		EffectState:    effectState(t.Effect), LevelRequired: level(string(t.Required)), LevelAchieved: level(string(t.Achieved)),
		Monitor: t.Monitor, Evaluations: int32(t.Evaluations), //nolint:gosec // G115: at most 64
		CreateTime: timestamppb.New(t.Created),
	}
	if t.Connection != nil {
		p.ConnectionId = t.Connection.String()
	}
	return p
}

// ReconciliationProto converts a reconciliation. The assertion a release
// carries never leaves the server.
func ReconciliationProto(k app.Reconciliation) *pantherclawv1.Reconciliation {
	p := &pantherclawv1.Reconciliation{
		Id: k.ID.String(), TransactionId: k.Transaction.String(),
		Kind:        pantherclawv1.ReconciliationKind(pantherclawv1.ReconciliationKind_value["RECONCILIATION_KIND_"+strings.ToUpper(string(k.Kind))]),
		State:       pantherclawv1.ReconciliationState(pantherclawv1.ReconciliationState_value["RECONCILIATION_STATE_"+string(k.State)]),
		ResolvedVia: string(k.Via), Basis: k.Basis, OpenTime: timestamppb.New(k.Opened), ResolveTime: timestamp(k.Resolved),
	}
	for _, id := range []struct {
		v  *ids.UUID
		to *string
	}{{k.Observation, &p.ObservationId}, {k.User, &p.ResolvedByUserId}, {k.WaitlistEntry, &p.WaitlistEntryId}} {
		if id.v != nil {
			*id.to = id.v.String()
		}
	}
	for _, e := range k.Evidence {
		p.Evidence = append(p.Evidence, e.String())
	}
	return p
}

func effectState(s domain.EffectState) pantherclawv1.EffectState {
	return pantherclawv1.EffectState(pantherclawv1.EffectState_value["EFFECT_STATE_"+string(s)])
}

func level(l string) pantherclawv1.VerificationLevel {
	return pantherclawv1.VerificationLevel(pantherclawv1.VerificationLevel_value["VERIFICATION_LEVEL_"+strings.ToUpper(l)])
}

func outcome(o string) pantherclawv1.Outcome {
	return pantherclawv1.Outcome(pantherclawv1.Outcome_value["OUTCOME_"+strings.ToUpper(o)])
}

var integrityStatus = map[app.IntegrityStatus]pantherclawv1.IntegrityStatus{
	app.IntegrityPending:      pantherclawv1.IntegrityStatus_INTEGRITY_STATUS_PENDING,
	app.IntegrityChained:      pantherclawv1.IntegrityStatus_INTEGRITY_STATUS_CHAINED,
	app.IntegrityCheckpointed: pantherclawv1.IntegrityStatus_INTEGRITY_STATUS_CHECKPOINTED,
	app.IntegrityAnchored:     pantherclawv1.IntegrityStatus_INTEGRITY_STATUS_ANCHORED,
}

// integrity reports how far an item is protected: chained, in a signed
// checkpoint, or in an anchored one (F466–F468), with the checkpoint and
// anchor that protect it.
func integrity(i app.Integrity) *pantherclawv1.Integrity {
	s := i.Status()
	p := &pantherclawv1.Integrity{LedgerEntryId: i.Entry.String(), Sequence: i.Seq, Status: integrityStatus[s]}
	if s == app.IntegrityCheckpointed || s == app.IntegrityAnchored {
		p.CheckpointSize = i.Checkpoint
	}
	if s == app.IntegrityAnchored {
		p.AnchoredSize, p.AnchorTime = i.Anchored, timestamp(i.AnchoredAt)
	}
	return p
}

func timestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}
