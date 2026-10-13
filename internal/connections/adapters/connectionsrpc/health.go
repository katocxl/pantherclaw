// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// stamp is t, or unset for the zero time.
func stamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// GetConnectionHealth implements ConnectionServiceHandler.
func (h *Handler) GetConnectionHealth(ctx context.Context, req *pb.GetConnectionHealthRequest) (*pb.GetConnectionHealthResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	hl, err := h.s.Health(ctx, id)
	if err != nil {
		return nil, err
	}
	d := hl.Deliveries
	out := &pb.ConnectionHealth{
		Connection: connectionOf(hl.Connection), DependentAgentsHidden: hl.AgentsHidden,
		Deliveries: &pb.ConnectionDeliveries{
			SinceTime: timestamppb.New(d.Since), FailedCount: d.Failed, UnknownCount: d.Unknown,
			LastFailureTime: stamp(d.LastFailure), LastSuccessTime: stamp(d.LastSuccess), DelegatedCount: d.Delegated,
			LastDelegatedTime: stamp(d.LastDelegated),
		},
	}
	if out.ActiveCredential, err = h.activeCredential(ctx, out.Connection); err != nil {
		return nil, err
	}
	for _, c := range hl.Circuits {
		cc := &pb.ConnectionCircuit{
			GatewayId: c.Gateway.String(), Open: c.Open, UnknownCount: c.Unknown, TotalCount: c.Total, ReportTime: timestamppb.New(c.ReportedAt),
		}
		if c.Open && c.OpenedAt != nil {
			cc.OpenTime = timestamppb.New(*c.OpenedAt)
		}
		out.Circuits = append(out.Circuits, cc)
	}
	for _, p := range hl.Permissions {
		out.Permissions = append(out.Permissions, &pb.ConnectionPermission{Name: p.Name, Reasons: p.Reasons})
	}
	if hl.LastTest != nil {
		out.LastTest = testOf(*hl.LastTest)
	}
	if hl.LastPassedTest != nil {
		out.LastPassedTest = testOf(*hl.LastPassedTest)
	}
	for _, a := range hl.Agents {
		out.DependentAgents = append(out.DependentAgents, &pb.ConnectionDependentAgent{
			AgentId: a.Agent.String(), Name: a.Name, LastUseTime: timestamppb.New(a.LastUsed),
		})
	}
	for _, a := range hl.GrantedAgents {
		out.GrantedAgents = append(out.GrantedAgents, &pb.ConnectionDependentAgent{AgentId: a.Agent.String(), Name: a.Name})
	}
	return &pb.GetConnectionHealthResponse{Health: out}, nil
}
