// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package transactionsrpc

import (
	"context"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/runs/adapters/runsrpc"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Reconciliations serves ReconciliationService.
type Reconciliations struct {
	pantherclawv1connect.UnimplementedReconciliationServiceHandler
	read *app.Explorer
	act  *app.Reconciler
}

// NewReconciliations returns the ReconciliationService handler.
func NewReconciliations(read *app.Explorer, act *app.Reconciler) *Reconciliations {
	return &Reconciliations{read: read, act: act}
}

// ListReconciliations implements ReconciliationServiceHandler.
func (s *Reconciliations) ListReconciliations(ctx context.Context, req *pantherclawv1.ListReconciliationsRequest) (*pantherclawv1.ListReconciliationsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var f app.ReconciliationFilter
	for _, st := range req.GetStates() {
		f.States = append(f.States, domain.TaskState(strings.TrimPrefix(st.String(), "RECONCILIATION_STATE_")))
	}
	for _, k := range req.GetKinds() {
		f.Kinds = append(f.Kinds, taskKindOf(k))
	}
	if req.TransactionId != nil {
		id, err := runsrpc.ParseID(req.GetTransactionId())
		if err != nil {
			return nil, err
		}
		f.Transaction = &id
	}
	p, err := s.read.ListReconciliations(ctx, pr, f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListReconciliationsResponse{NextPageToken: p.Next}
	for _, k := range p.Items {
		out.Reconciliations = append(out.Reconciliations, ReconciliationProto(k))
	}
	return out, nil
}

// GetReconciliation implements ReconciliationServiceHandler.
func (s *Reconciliations) GetReconciliation(ctx context.Context, req *pantherclawv1.GetReconciliationRequest) (*pantherclawv1.GetReconciliationResponse, error) {
	id, err := runsrpc.ParseID(req.GetId())
	if err != nil {
		return nil, err
	}
	k, t, err := s.read.Reconciliation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetReconciliationResponse{Reconciliation: ReconciliationProto(k), Transaction: TransactionProto(t)}, nil
}

// ResolveOccurred implements ReconciliationServiceHandler.
func (s *Reconciliations) ResolveOccurred(ctx context.Context, req *pantherclawv1.ResolveOccurredRequest) (*pantherclawv1.ResolveOccurredResponse, error) {
	id, err := runsrpc.ParseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r := app.Resolution{Reconciliation: id, Basis: req.GetBasis()}
	for _, e := range req.GetEvidence() {
		o, err := runsrpc.ParseID(e)
		if err != nil {
			return nil, err
		}
		r.Evidence = append(r.Evidence, o)
	}
	if req.ObservationId != nil {
		o, err := runsrpc.ParseID(req.GetObservationId())
		if err != nil {
			return nil, err
		}
		r.Authoritative = &o
	}
	k, err := s.act.ResolveOccurred(ctx, r)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ResolveOccurredResponse{Reconciliation: ReconciliationProto(k)}, nil
}

// RequestVerification implements ReconciliationServiceHandler.
func (s *Reconciliations) RequestVerification(ctx context.Context, req *pantherclawv1.RequestVerificationRequest) (*pantherclawv1.RequestVerificationResponse, error) {
	id, err := runsrpc.ParseID(req.GetTransactionId())
	if err != nil {
		return nil, err
	}
	v, err := s.act.RequestVerification(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestVerificationResponse{VerificationId: v.String()}, nil
}

// LinkTransaction implements ReconciliationServiceHandler.
func (s *Reconciliations) LinkTransaction(ctx context.Context, req *pantherclawv1.LinkTransactionRequest) (*pantherclawv1.LinkTransactionResponse, error) {
	var ends [2]ids.UUID
	for i, raw := range []string{req.GetFromTransactionId(), req.GetToTransactionId()} {
		id, err := runsrpc.ParseID(raw)
		if err != nil {
			return nil, err
		}
		ends[i] = id
	}
	kind := linkKindOf(req.GetKind())
	l, err := s.act.Link(ctx, app.LinkRequest{From: ends[0], To: ends[1], Kind: kind})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.LinkTransactionResponse{Link: &pantherclawv1.TransactionLink{
		FromTransactionId: l.From.String(), ToTransactionId: l.To.String(), Kind: linkKind(l.Kind), CreatedBy: l.CreatedBy,
		CreateTime: timestamppb.New(l.Created),
	}}, nil
}

func linkKind(k domain.LinkKind) pantherclawv1.LinkKind {
	return pantherclawv1.LinkKind(pantherclawv1.LinkKind_value["LINK_KIND_"+strings.ToUpper(string(k))])
}

func linkKindOf(k pantherclawv1.LinkKind) domain.LinkKind {
	return domain.LinkKind(strings.ToLower(strings.TrimPrefix(k.String(), "LINK_KIND_")))
}

func taskKindOf(k pantherclawv1.ReconciliationKind) domain.TaskKind {
	return domain.TaskKind(strings.ToLower(strings.TrimPrefix(k.String(), "RECONCILIATION_KIND_")))
}
