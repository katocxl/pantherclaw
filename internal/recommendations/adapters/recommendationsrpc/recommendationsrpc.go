// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package recommendationsrpc serves RecommendationService over Connect (G0
// M21 D302). Handlers only translate: authentication, the coarse permission
// check and protovalidate have run before a handler is called, and the use
// cases check scope and the edition.
package recommendationsrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/recommendations/app"
	"github.com/katocxl/pantherclaw/internal/recommendations/domain"
)

// Handler serves RecommendationService.
type Handler struct {
	pantherclawv1connect.UnimplementedRecommendationServiceHandler
	svc *app.Service
}

// New returns the RecommendationService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

var categories = map[domain.Category]pb.RecommendationCategory{
	domain.Identity:       pb.RecommendationCategory_RECOMMENDATION_CATEGORY_IDENTITY,
	domain.Classification: pb.RecommendationCategory_RECOMMENDATION_CATEGORY_CLASSIFICATION,
	domain.Approval:       pb.RecommendationCategory_RECOMMENDATION_CATEGORY_APPROVAL,
	domain.Incident:       pb.RecommendationCategory_RECOMMENDATION_CATEGORY_INCIDENT,
	domain.Export:         pb.RecommendationCategory_RECOMMENDATION_CATEGORY_EXPORT,
	domain.Unsupported:    pb.RecommendationCategory_RECOMMENDATION_CATEGORY_UNSUPPORTED,
}

var sources = map[domain.Source]pb.RecommendationEvidenceSource{
	domain.FromDiscoveries: pb.RecommendationEvidenceSource_RECOMMENDATION_EVIDENCE_SOURCE_DISCOVERIES,
	domain.FromCoverage:    pb.RecommendationEvidenceSource_RECOMMENDATION_EVIDENCE_SOURCE_COVERAGE,
	domain.FromOnboarding:  pb.RecommendationEvidenceSource_RECOMMENDATION_EVIDENCE_SOURCE_ONBOARDING,
	domain.FromAgents:      pb.RecommendationEvidenceSource_RECOMMENDATION_EVIDENCE_SOURCE_AGENTS,
}

func item(it app.Item) *pb.Recommendation {
	e := it.Entry
	out := &pb.Recommendation{
		Id: string(e.ID), Category: categories[e.Category], Title: e.Title, Detail: e.Detail,
		Enables: e.Enables, StillUnsupported: e.StillUnsupported, Dismissed: it.Dismissed,
		Evidence: &pb.RecommendationEvidence{
			Source: sources[it.Evidence.Source], Count: int32(it.Evidence.Count), Link: it.Evidence.Link, //nolint:gosec // G115: bounded by the org's rows
		},
	}
	for _, t := range e.Targets {
		out.Targets = append(out.Targets, &pb.RecommendationTarget{Name: t.Name, Package: t.Package})
	}
	for _, r := range it.Evidence.Records {
		out.Evidence.Records = append(out.Evidence.Records, &pb.RecommendationRecord{Kind: r.Kind, Id: r.ID.String()})
	}
	if d := it.Dismissal; d != nil {
		out.Dismissal = &pb.RecommendationDismissal{DismissedBy: d.By, Reason: d.Reason, DismissedAt: timestamppb.New(d.At)}
	}
	return out
}

// ListRecommendations implements RecommendationService.
func (h *Handler) ListRecommendations(ctx context.Context, req *pb.ListRecommendationsRequest) (*pb.ListRecommendationsResponse, error) {
	l, err := h.svc.List(ctx, req.GetIncludeDismissed())
	if err != nil {
		return nil, err
	}
	out := &pb.ListRecommendationsResponse{Restricted: l.Restricted, AsOf: timestamppb.New(l.AsOf)}
	for _, it := range l.Items {
		out.Recommendations = append(out.Recommendations, item(it))
	}
	return out, nil
}

// DismissRecommendation implements RecommendationService.
func (h *Handler) DismissRecommendation(ctx context.Context, req *pb.DismissRecommendationRequest) (*pb.DismissRecommendationResponse, error) {
	if err := h.svc.Dismiss(ctx, domain.ID(req.GetId()), req.GetReason()); err != nil {
		return nil, err
	}
	return &pb.DismissRecommendationResponse{}, nil
}

// UndismissRecommendation implements RecommendationService.
func (h *Handler) UndismissRecommendation(ctx context.Context, req *pb.UndismissRecommendationRequest) (*pb.UndismissRecommendationResponse, error) {
	if err := h.svc.Undismiss(ctx, domain.ID(req.GetId())); err != nil {
		return nil, err
	}
	return &pb.UndismissRecommendationResponse{}, nil
}
