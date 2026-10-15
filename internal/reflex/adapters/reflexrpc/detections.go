// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package reflexrpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
)

// DetectionHandler serves DetectionService.
type DetectionHandler struct {
	pantherclawv1connect.UnimplementedDetectionServiceHandler
	svc *reflexapp.Detections
}

// NewDetections returns the DetectionService handler.
func NewDetections(svc *reflexapp.Detections) *DetectionHandler { return &DetectionHandler{svc: svc} }

func ruleProto(r reflexapp.Rule) *pb.DetectionRule {
	out := &pb.DetectionRule{Digest: r.Digest, Builtin: r.Builtin, Licensed: r.Licensed}
	if x := r.Rule; x != nil {
		out.RuleId, out.Version, out.Title, out.Description = x.ID, x.Version, x.Title, x.Description
		out.Severity, out.Attention, out.Basis = string(x.Severity), string(x.Attention), string(x.Basis)
		out.Atlas, out.Owasp, out.Edition = x.ATLAS, x.OWASP, x.Edition
	}
	if c := r.Custom; c != nil {
		out.CustomId, out.CustomState, out.Content = c.ID.String(), c.State, c.Content
		if out.RuleId == "" {
			out.RuleId = c.RuleID
		}
	}
	if s := r.State; s != nil {
		out.DisableTime, out.DisabledReason, out.ConsecutiveErrors = tsp(s.DisabledAt), str(s.DisabledReason), s.ConsecutiveErrors
	}
	return out
}

func results(rs []engine.TestResult) []*pb.RuleTestResult {
	out := make([]*pb.RuleTestResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, &pb.RuleTestResult{Name: r.Name, Fires: r.Fires, Fired: r.Fired, Passed: r.Passed, Error: r.Error})
	}
	return out
}

// ListRules implements DetectionServiceHandler.
func (h *DetectionHandler) ListRules(ctx context.Context, _ *pb.ListRulesRequest) (*pb.ListRulesResponse, error) {
	l, err := h.svc.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListRulesResponse{PackVersion: l.PackVersion, PackVerified: l.Verified}
	for _, r := range l.Rules {
		out.Rules = append(out.Rules, ruleProto(r))
	}
	return out, nil
}

// GetDetectionStatus implements DetectionServiceHandler.
func (h *DetectionHandler) GetDetectionStatus(ctx context.Context, _ *pb.GetDetectionStatusRequest) (*pb.GetDetectionStatusResponse, error) {
	s, err := h.svc.GetStatus(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.GetDetectionStatusResponse{CursorSeq: s.Cursor, HeadSeq: s.Head, UpdateTime: tsp(s.Updated), Running: s.Running}, nil
}

// CreateCustomRule implements DetectionServiceHandler.
func (h *DetectionHandler) CreateCustomRule(ctx context.Context, req *pb.CreateCustomRuleRequest) (*pb.CreateCustomRuleResponse, error) {
	r, err := h.svc.CreateCustomRule(ctx, req.GetContent())
	if err != nil {
		return nil, err
	}
	return &pb.CreateCustomRuleResponse{Rule: ruleProto(r)}, nil
}

// TestCustomRule implements DetectionServiceHandler.
func (h *DetectionHandler) TestCustomRule(ctx context.Context, req *pb.TestCustomRuleRequest) (*pb.TestCustomRuleResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	rs, ok, err := h.svc.TestCustomRule(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.TestCustomRuleResponse{Results: results(rs), Passed: ok}, nil
}

// PublishCustomRule implements DetectionServiceHandler.
func (h *DetectionHandler) PublishCustomRule(ctx context.Context, req *pb.PublishCustomRuleRequest) (*pb.PublishCustomRuleResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, rs, err := h.svc.PublishCustomRule(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.PublishCustomRuleResponse{Rule: ruleProto(r), Results: results(rs)}, nil
}

// DisableCustomRule implements DetectionServiceHandler.
func (h *DetectionHandler) DisableCustomRule(ctx context.Context, req *pb.DisableCustomRuleRequest) (*pb.DisableCustomRuleResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.DisableCustomRule(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.DisableCustomRuleResponse{Rule: ruleProto(r)}, nil
}

// EnableRule implements DetectionServiceHandler.
func (h *DetectionHandler) EnableRule(ctx context.Context, req *pb.EnableRuleRequest) (*pb.EnableRuleResponse, error) {
	ok, err := h.svc.EnableRule(ctx, req.GetRuleId())
	if err != nil {
		return nil, err
	}
	return &pb.EnableRuleResponse{Enabled: ok}, nil
}
