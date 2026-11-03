// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package compliancerpc serves ComplianceService over Connect (G0 M25 D311).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases check
// the edition and each source's permission.
package compliancerpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/compliance/app"
	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// Handler serves ComplianceService.
type Handler struct {
	pantherclawv1connect.UnimplementedComplianceServiceHandler
	svc *app.Service
}

// New returns the ComplianceService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

var frameworks = map[domain.Framework]pb.ComplianceFramework{
	domain.OWASPASI:        pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_OWASP_ASI,
	domain.NISTAIRMF:       pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_NIST_AI_RMF,
	domain.EUAIActDeployer: pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_EU_AI_ACT_DEPLOYER,
	domain.ISO42001:        pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_ISO_42001,
	domain.SOC2:            pb.ComplianceFramework_COMPLIANCE_FRAMEWORK_SOC2,
}

var states = map[domain.State]pb.ControlState{
	domain.Evidenced: pb.ControlState_CONTROL_STATE_EVIDENCED,
	domain.Partial:   pb.ControlState_CONTROL_STATE_PARTIAL,
	domain.Gap:       pb.ControlState_CONTROL_STATE_GAP,
	domain.Stated:    pb.ControlState_CONTROL_STATE_STATED,
}

// FrameworkOf is the framework of a proto value, empty for none.
func FrameworkOf(f pb.ComplianceFramework) domain.Framework {
	for k, v := range frameworks {
		if v == f {
			return k
		}
	}
	return ""
}

// ListFrameworks implements ComplianceServiceHandler.
func (h *Handler) ListFrameworks(ctx context.Context, _ *pb.ListFrameworksRequest) (*pb.ListFrameworksResponse, error) {
	list, err := h.svc.ListFrameworks(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListFrameworksResponse{}
	for _, f := range list {
		out.Frameworks = append(out.Frameworks, &pb.ComplianceFrameworkInfo{
			Framework: frameworks[f.Framework], Title: f.Title, ControlCount: int32(f.Controls), //nolint:gosec // G115: a short table
			Available: f.Available,
		})
	}
	return out, nil
}

func refsOf(in []domain.Ref) []*pb.ComplianceEvidenceRef {
	out := make([]*pb.ComplianceEvidenceRef, 0, len(in))
	for _, r := range in {
		out = append(out, &pb.ComplianceEvidenceRef{Type: r.Type, Id: r.ID, Simulated: r.Simulated})
	}
	return out
}

func timestamp(s string) *timestamppb.Timestamp {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	return timestamppb.New(t)
}

// GetFrameworkCoverage implements ComplianceServiceHandler.
func (h *Handler) GetFrameworkCoverage(ctx context.Context, req *pb.GetFrameworkCoverageRequest) (*pb.GetFrameworkCoverageResponse, error) {
	r, err := h.svc.GetFrameworkCoverage(ctx, FrameworkOf(req.GetFramework()), req.GetStartTime().AsTime(), req.GetEndTime().AsTime())
	if err != nil {
		return nil, err
	}
	out := &pb.GetFrameworkCoverageResponse{
		Framework: req.GetFramework(), StartTime: timestamp(r.PeriodStart), EndTime: timestamp(r.PeriodEnd),
		RealRecords: r.Split.Real, SimulatedRecords: r.Split.Simulated, Statement: r.Statement,
	}
	for _, c := range r.Controls {
		pc := &pb.ComplianceControl{Id: c.ID, Title: c.Title, State: states[c.State], SimulatedOnly: c.SimulatedOnly}
		for _, s := range c.Evidence {
			pc.Evidence = append(pc.Evidence, string(s))
		}
		for _, g := range c.Gaps {
			pc.Gaps = append(pc.Gaps, &pb.ComplianceControlGap{Reason: g.Reason, Source: string(g.Source), Detail: g.Detail})
		}
		out.Controls = append(out.Controls, pc)
	}
	for _, s := range r.Inputs.Sources {
		out.Sources = append(out.Sources, &pb.ComplianceSourceCount{
			Source: string(s.Source), Readable: s.Readable, Real: s.Real, Simulated: s.Simulated, Refs: refsOf(s.Refs), Truncated: s.Truncated,
		})
	}
	for _, t := range r.Inputs.Tests {
		out.Tests = append(out.Tests, &pb.ComplianceTestCount{
			Tag: t.Tag, Source: string(t.Source), Held: t.Held, Failed: t.Failed, Reported: t.Reported,
			NotExercised: t.NotExercised, Refs: refsOf(t.Refs),
		})
	}
	for _, s := range r.Inputs.Stated {
		out.Stated = append(out.Stated, &pb.ComplianceStatedCount{
			Field: string(s.Field), Readable: s.Readable, Stated: s.Stated, Unset: s.Unset,
		})
	}
	return out, nil
}

// ListComplianceReports implements ComplianceServiceHandler.
func (h *Handler) ListComplianceReports(ctx context.Context, req *pb.ListComplianceReportsRequest) (*pb.ListComplianceReportsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.ListReports(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pb.ListComplianceReportsResponse{NextPageToken: p.Next}
	for _, r := range p.Items {
		out.Reports = append(out.Reports, &pb.ComplianceReportInfo{
			Id: r.ID.String(), PackId: r.Pack.String(), Framework: frameworks[r.Framework], StartTime: timestamppb.New(r.Start),
			EndTime: timestamppb.New(r.End), CreatedBy: r.CreatedBy.String(), CreateTime: timestamppb.New(r.Created), ReportSha256: r.SHA256,
		})
	}
	return out, nil
}
