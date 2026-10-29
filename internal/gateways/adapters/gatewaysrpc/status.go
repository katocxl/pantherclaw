// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var servingStates = map[pb.ConnectionServingState]string{
	pb.ConnectionServingState_CONNECTION_SERVING_STATE_SERVING:           "SERVING",
	pb.ConnectionServingState_CONNECTION_SERVING_STATE_CIRCUIT_OPEN:      "CIRCUIT_OPEN",
	pb.ConnectionServingState_CONNECTION_SERVING_STATE_DRIFT_QUARANTINED: "DRIFT_QUARANTINED",
	pb.ConnectionServingState_CONNECTION_SERVING_STATE_NOT_LOADED:        "NOT_LOADED",
}

func optTime(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime()
	return &v
}

// ReportStatus implements GatewayServiceHandler, on the mTLS listener only
// (gateway.observe): one replica's status (G0 M15 D10, HR-410). The org and
// gateway come from the certificate alone; connections the gateway does
// not serve are dropped.
func (h *GatewayHandler) ReportStatus(ctx context.Context, req *pb.ReportStatusRequest) (*pb.ReportStatusResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	r := gwapp.ReplicaStatus{
		Replica: req.GetReplicaId(), Version: req.GetVersion(), Build: req.GetBuild(), StartTime: optTime(req.GetStartTime()),
		ConfigVersion: req.GetConfigVersion(),
	}
	for _, c := range req.GetConnections() {
		conn, err := ids.ParseUUID(c.GetConnectionId())
		state, ok := servingStates[c.GetState()]
		if err != nil || !ok {
			continue
		}
		r.Connections = append(r.Connections, gwapp.ConnectionStatus{Connection: conn, State: state, LastDriftCheck: optTime(c.GetLastDriftCheckTime())})
	}
	if err := h.s.ReportStatus(ctx, id, r); err != nil {
		return nil, err
	}
	return &pb.ReportStatusResponse{NextReportSeconds: gwapp.NextReportSeconds}, nil
}

func replicaOf(r dbq.PcGatewayReplica) *pb.GatewayReplica {
	out := &pb.GatewayReplica{
		ReplicaId: r.ReplicaID, Version: r.Version, Build: r.Build, ConfigVersion: r.ConfigVersion, LastSeenTime: timestamppb.New(r.LastSeen),
	}
	if r.StartTime != nil {
		out.StartTime = timestamppb.New(*r.StartTime)
	}
	return out
}

// withStatus adds what a gateway's replicas reported.
func withStatus(g *pb.Gateway, st gwapp.GatewayStatus) *pb.Gateway {
	for _, r := range st.Replicas {
		g.Replicas = append(g.Replicas, replicaOf(r))
	}
	g.Connected = st.Connected
	return g
}
