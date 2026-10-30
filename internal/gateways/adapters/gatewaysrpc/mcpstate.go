// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var mcpKinds = map[pb.MCPStateKind]string{
	pb.MCPStateKind_MCP_STATE_KIND_HOLD:        gwapp.MCPHold,
	pb.MCPStateKind_MCP_STATE_KIND_TASK:        gwapp.MCPTask,
	pb.MCPStateKind_MCP_STATE_KIND_SESSION:     gwapp.MCPSession,
	pb.MCPStateKind_MCP_STATE_KIND_ELICITATION: gwapp.MCPElicitation,
}

var mcpKindsBack = map[string]pb.MCPStateKind{
	gwapp.MCPHold: pb.MCPStateKind_MCP_STATE_KIND_HOLD, gwapp.MCPTask: pb.MCPStateKind_MCP_STATE_KIND_TASK,
	gwapp.MCPSession:     pb.MCPStateKind_MCP_STATE_KIND_SESSION,
	gwapp.MCPElicitation: pb.MCPStateKind_MCP_STATE_KIND_ELICITATION,
}

func optUUID(s string) (*ids.UUID, error) {
	if s == "" {
		return nil, nil
	}
	u, err := ids.ParseUUID(s)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func uuidStr(p *ids.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// PutMCPState implements GatewayServiceHandler, on the mTLS listener only
// (gateway.sync): writes one MCP state entry of the calling gateway (G0
// M15 D12, HR-411..413).
func (h *GatewayHandler) PutMCPState(ctx context.Context, req *pb.PutMCPStateRequest) (*pb.PutMCPStateResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	e := req.GetEntry()
	kind, ok := mcpKinds[e.GetKind()]
	conn, err1 := ids.ParseUUID(e.GetConnectionId())
	run, err2 := optUUID(e.GetRunId())
	inst, err3 := optUUID(e.GetInstanceId())
	if !ok || err1 != nil || err2 != nil || err3 != nil {
		return nil, gwapp.ErrMCPStateInvalid
	}
	v, err := h.s.PutMCPState(ctx, id, gwapp.MCPEntry{
		Kind: kind, Key: e.GetKey(), Connection: conn, Run: run, Instance: inst, JKT: e.GetJkt(), ActionID: e.GetActionId(),
		Status: e.GetStatus(), Busy: e.GetBusy(), SealedBody: e.GetSealedBody(), ExpireTime: e.GetExpireTime().AsTime(),
	}, req.GetIfVersion())
	if err != nil {
		return nil, err
	}
	return &pb.PutMCPStateResponse{Version: v}, nil
}

// GetMCPState implements GatewayServiceHandler (gateway.sync): one live
// MCP state entry of the calling gateway.
func (h *GatewayHandler) GetMCPState(ctx context.Context, req *pb.GetMCPStateRequest) (*pb.GetMCPStateResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	kind, ok := mcpKinds[req.GetKind()]
	if !ok {
		return nil, gwapp.ErrMCPStateInvalid
	}
	r, err := h.s.GetMCPState(ctx, id, kind, req.GetKey())
	if err != nil {
		return nil, err
	}
	return &pb.GetMCPStateResponse{Entry: entryOf(r)}, nil
}

// DeleteMCPState implements GatewayServiceHandler (gateway.sync).
func (h *GatewayHandler) DeleteMCPState(ctx context.Context, req *pb.DeleteMCPStateRequest) (*pb.DeleteMCPStateResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	kind, ok := mcpKinds[req.GetKind()]
	if !ok {
		return nil, gwapp.ErrMCPStateInvalid
	}
	deleted, err := h.s.DeleteMCPState(ctx, id, kind, req.GetKey(), req.GetIfVersion())
	if err != nil {
		return nil, err
	}
	return &pb.DeleteMCPStateResponse{Deleted: deleted}, nil
}

func entryOf(r dbq.PcGatewayMcpState) *pb.MCPStateEntry {
	return &pb.MCPStateEntry{
		Kind: mcpKindsBack[r.Kind], Key: r.Key, ConnectionId: r.ConnectionID.String(), RunId: uuidStr(r.RunID),
		InstanceId: uuidStr(r.InstanceID), Jkt: str(r.Jkt), ActionId: str(r.ActionID), Status: str(r.Status), Busy: r.Busy,
		SealedBody: r.SealedBody, Version: r.Version, ExpireTime: timestamppb.New(r.ExpireTime), UpdateTime: timestamppb.New(r.UpdateTime),
	}
}
