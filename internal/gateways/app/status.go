// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Gateway status reports (G0 M15 D10, D11, HR-410). Every gateway process
// (replica) reports its version, build, start time, the config version it
// serves and each connection's serving state on start, every
// NextReportSeconds and soon after a serving state changes. The org and
// gateway come from the certificate alone; connections the gateway does
// not serve are dropped. A gateway is connected while some replica reported
// in the last ConnectedWithin.
const (
	// NextReportSeconds is when a replica reports next.
	NextReportSeconds = 30
	// ConnectedWithin is how recent a report keeps a gateway connected.
	ConnectedWithin = 90 * time.Second
	// ReplicaRetention is how long a replica that stopped reporting is
	// listed; the prune job deletes it after.
	ReplicaRetention = 24 * time.Hour
)

// ConnectionStatus is one connection's serving state on a replica.
type ConnectionStatus struct {
	Connection     ids.UUID   `json:"connection_id"`
	State          string     `json:"state"`
	LastDriftCheck *time.Time `json:"last_drift_check_time,omitzero"`
}

// ReplicaStatus is one replica's report.
type ReplicaStatus struct {
	Replica, Version, Build string
	StartTime               *time.Time
	ConfigVersion           int64
	Connections             []ConnectionStatus
}

// GatewayStatus is what a gateway's replicas reported.
type GatewayStatus struct {
	Replicas  []dbq.PcGatewayReplica
	Connected bool
}

// ReportStatus records one replica's status for the calling gateway. A
// revoked gateway's certificate fails authentication before it gets here
// (HR-181); the gateway row is checked again in the transaction.
func (s *Service) ReportStatus(ctx context.Context, id Identity, r ReplicaStatus) error {
	return s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.GetGateway(ctx, id.Org, id.Gateway)
		if err != nil || g.State != "ACTIVE" {
			return ErrGatewayCredentials
		}
		served, err := q.ListGatewayServedConnectionIDs(ctx, id.Org, id.Gateway)
		if err != nil {
			return err
		}
		mine := make(map[ids.UUID]bool, len(served))
		for _, c := range served {
			mine[c] = true
		}
		kept := make([]ConnectionStatus, 0, len(r.Connections))
		for _, c := range r.Connections {
			if mine[c.Connection] {
				kept = append(kept, c)
			}
		}
		conns, err := json.Marshal(kept)
		if err != nil {
			return err
		}
		if err := q.UpsertGatewayReplica(ctx, dbq.UpsertGatewayReplicaParams{
			OrgID: id.Org, GatewayID: id.Gateway, ReplicaID: r.Replica, Version: r.Version, Build: r.Build, StartTime: r.StartTime,
			ConfigVersion: r.ConfigVersion, Connections: conns, LastSeen: s.clk.Now(),
		}); err != nil {
			return err
		}
		// The fleet sweep's last report time, never pruned (G0 M18 D167).
		now := s.clk.Now()
		return q.RecordGatewayReport(ctx, id.Org, id.Gateway, &now)
	})
}

// statuses returns the status of each of gateways, keyed by gateway.
func (s *Service) statuses(ctx context.Context, q *dbq.Queries, org ids.OrgID, gateways []ids.UUID) (map[ids.UUID]GatewayStatus, error) {
	out := make(map[ids.UUID]GatewayStatus, len(gateways))
	if len(gateways) == 0 {
		return out, nil
	}
	now := s.clk.Now()
	rows, err := q.ListGatewayReplicas(ctx, org, gateways, now.Add(-ReplicaRetention))
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		st := out[r.GatewayID]
		st.Replicas = append(st.Replicas, r)
		st.Connected = st.Connected || now.Sub(r.LastSeen) < ConnectedWithin
		out[r.GatewayID] = st
	}
	return out, nil
}

// ReplicaConnections decodes a replica row's connection states.
func ReplicaConnections(r dbq.PcGatewayReplica) []ConnectionStatus {
	var out []ConnectionStatus
	_ = json.Unmarshal(r.Connections, &out)
	return out
}

// PruneReplicas deletes one org's replicas not seen for ReplicaRetention.
func (s *Service) PruneReplicas(ctx context.Context, org ids.OrgID) (int64, error) {
	var n int64
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = dbq.New(tx).PruneGatewayReplicas(ctx, org, s.clk.Now().Add(-ReplicaRetention))
		return err
	})
	return n, err
}
