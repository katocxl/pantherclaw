// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"context"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var levels = map[string]pb.CapabilityLevel{
	capp.Supported: pb.CapabilityLevel_CAPABILITY_LEVEL_SUPPORTED, capp.Partial: pb.CapabilityLevel_CAPABILITY_LEVEL_PARTIAL,
	capp.Unsupported: pb.CapabilityLevel_CAPABILITY_LEVEL_UNSUPPORTED,
}

func supportOf(s capp.Support) *pb.CapabilitySupport {
	return &pb.CapabilitySupport{Level: levels[s.Level], Detail: s.Detail}
}

// GetConnectionCapabilities implements ConnectionServiceHandler.
func (h *Handler) GetConnectionCapabilities(ctx context.Context, req *pb.GetConnectionCapabilitiesRequest) (*pb.GetConnectionCapabilitiesResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.Capabilities(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.ConnectionCapabilities{
		ConnectionId: id.String(), Discovery: supportOf(c.Discovery), Observation: supportOf(c.Observation),
		Enforcement: supportOf(c.Enforcement), Response: supportOf(c.Response), ResponseActions: c.ResponseActions,
		FailureBehavior: c.Failure,
	}
	for _, o := range c.Operations {
		out.Operations = append(out.Operations, &pb.ConnectionOperation{
			Operation: o.Operation, Summary: o.Summary, Route: o.Route, Access: o.Access, TargetType: o.TargetType,
			Reversibility: o.Reversibility, Verified: o.Verified, Mode: modeOf[o.Mode],
		})
	}
	for _, p := range c.Permissions {
		out.Permissions = append(out.Permissions, &pb.ConnectionPermission{Name: p.Name, Reasons: p.Reasons})
	}
	for _, l := range c.Limits {
		out.Limits = append(out.Limits, &pb.ConnectionLimit{Code: l.Code, Detail: l.Detail})
	}
	return &pb.GetConnectionCapabilitiesResponse{Capabilities: out}, nil
}
