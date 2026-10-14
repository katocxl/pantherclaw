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

// ErrNotServed: the connection is not one the reporting gateway serves.
var ErrNotServed = pcerr.New(pcerr.NotFound, "CONNECTION_NOT_SERVED", "the connection is not one this gateway serves")

// ToolObservation is a tool call an agent SDK ran without a mapping
// (HR-200): recorded OBSERVE_ONLY, the tool's name UNTRUSTED, its input
// kept only as a digest.
type ToolObservation struct {
	Run, Instance, Connection ids.UUID
	Tool                      string
	InputSHA256               []byte
}

// RecordToolObservation records an observation a gateway reports for a
// workload the Authority verified, through a connection that gateway
// serves (ErrNotServed otherwise). It is called by the Authority, never by
// a person: the caller checked the gateway's identity. A call through a
// simulated connection records nothing and returns the zero id (HR-222).
func (s *Service) RecordToolObservation(ctx context.Context, org ids.OrgID, gateway ids.UUID, o ToolObservation) (ids.UUID, error) {
	var id ids.UUID
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, org, o.Connection)
		if err == nil && conn.GatewayID == gateway && conn.Simulated {
			return nil // HR-222: a simulator's tool calls leave no observation
		}
		id, err = q.InsertToolObservation(ctx, dbq.InsertToolObservationParams{
			ID: ids.NewV7(), RunID: o.Run, InstanceID: o.Instance, Tool: o.Tool, InputSha256: o.InputSHA256, OrgID: org,
			ConnectionID: o.Connection, GatewayID: gateway,
		})
		if db.IsNoRows(err) {
			return ErrNotServed
		}
		return err
	})
	return id, err
}
