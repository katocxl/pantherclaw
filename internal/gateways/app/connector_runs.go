// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Connector run errors.
var (
	ErrConnectorNotFound = pcerr.New(pcerr.NotFound, "CONNECTOR_NOT_FOUND", "no connector connection of this gateway")
	ErrConnectorRun      = pcerr.New(pcerr.FailedPrecondition, "CONNECTOR_RUN",
		"a connector run moves only forward and runs a spec revision of its connection")
)

// ConnectorRun is one run of a connector's container as its gateway
// reports it (G0 M9 track C, 00094).
type ConnectorRun struct {
	Instance, Connection                                             ids.UUID
	SpecRevision                                                     int32
	State, Container, EngineVersion, APIVersion, Runtime, ErrorClass string
}

// ReportConnectorState records a run of one of the calling gateway's
// connectors. The org and gateway come from the verified certificate
// alone (HR-020): a connection of another gateway, one that is not a
// connector, or any on a PantherClaw-hosted gateway (HR-084) is not found.
// A run moves only forward, and only within its gateway and connection.
func (s *Service) ReportConnectorState(ctx context.Context, id Identity, r ConnectorRun) (dbq.PcConnectorInstance, error) {
	var out dbq.PcConnectorInstance
	err := s.pool.InTenantTx(ctx, id.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.GetGateway(ctx, id.Org, id.Gateway)
		if err != nil || g.State != "ACTIVE" {
			return ErrGatewayCredentials
		}
		conn, err := q.GetConnection(ctx, id.Org, r.Connection)
		if db.IsNoRows(err) || (err == nil && (conn.GatewayID != id.Gateway || conn.Kind != kindMCPContainer || s.hosted[id.Gateway])) {
			return ErrConnectorNotFound
		} else if err != nil {
			return err
		}
		var class *string
		if r.ErrorClass != "" {
			class = &r.ErrorClass
		}
		out, err = q.ReportConnectorInstance(ctx, dbq.ReportConnectorInstanceParams{
			OrgID: id.Org, ID: r.Instance, ConnectionID: r.Connection, SpecRevision: r.SpecRevision, GatewayID: id.Gateway,
			ContainerName: r.Container, State: r.State, EngineVersion: r.EngineVersion, ApiVersion: r.APIVersion, Runtime: r.Runtime,
			LastErrorClass: class,
		})
		if db.IsNoRows(err) || db.IsForeignKeyViolation(err) || db.IsCheckViolation(err) {
			return ErrConnectorRun
		}
		return err
	})
	return out, err
}
