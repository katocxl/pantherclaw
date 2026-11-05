// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"context"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// SetConnectionRuntimeTarget implements ConnectionServiceHandler (G0 M34
// D991).
func (h *Handler) SetConnectionRuntimeTarget(ctx context.Context, req *pb.SetConnectionRuntimeTargetRequest) (*pb.SetConnectionRuntimeTargetResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.SetRuntimeTarget(ctx, id, req.GetRuntimeTarget())
	if err != nil {
		return nil, err
	}
	return &pb.SetConnectionRuntimeTargetResponse{Connection: connectionOf(c)}, nil
}

// ClearConnectionRuntimeTarget implements ConnectionServiceHandler (G0 M34
// D991).
func (h *Handler) ClearConnectionRuntimeTarget(ctx context.Context, req *pb.ClearConnectionRuntimeTargetRequest) (*pb.ClearConnectionRuntimeTargetResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.ClearRuntimeTarget(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.ClearConnectionRuntimeTargetResponse{Connection: connectionOf(c)}, nil
}
