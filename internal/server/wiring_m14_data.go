// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// wireM14Data registers the postgres kind's configuration store (G0 M14
// D15, D64): with it, postgres connections can be created, and their
// gateways receive the endpoint and manifest.
func wireM14Data(c *m14Core) {
	if c != nil {
		c.kinds.Register(capp.KindPostgres, postgresConfigs{})
	}
}

// postgresConfigs keeps postgres connection configurations in
// pc.postgres_connections (00151).
type postgresConfigs struct{}

var errPostgresConfigType = errors.New("server: a postgres configuration store got another configuration")

// Save stores a validated configuration as its canonical JSON and digest.
// A postgres connection has no base URL.
func (postgresConfigs) Save(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, _ int32, cfg any) (string, error) {
	pc, ok := cfg.(*capp.PostgresConfig)
	if !ok || pc == nil {
		return "", errPostgresConfigType
	}
	raw, err := json.Marshal(pc, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "", dbq.New(tx).UpsertPostgresConnection(ctx, dbq.UpsertPostgresConnectionParams{
		OrgID: org, ConnectionID: connection, Config: raw, Digest: sum[:],
	})
}

// Load returns the configuration as the gateway gets it.
func (postgresConfigs) Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID) (proto.Message, error) {
	row, err := dbq.New(tx).GetPostgresConnection(ctx, org, connection)
	if err != nil {
		return nil, fmt.Errorf("postgres configuration of %s: %w", connection, err)
	}
	var c capp.PostgresConfig
	if err := json.Unmarshal(row.Config, &c, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("postgres configuration of %s: %w", connection, err)
	}
	return postgresProto(c), nil
}

func postgresProto(c capp.PostgresConfig) *pb.PostgresConfig {
	out := &pb.PostgresConfig{
		Host: c.Host, Port: c.Port, Database: c.Database, User: c.User, Sslmode: c.SSLMode, CaPem: c.CAPEM, Internal: c.Internal,
		MaxRows: c.MaxRows, StatementTimeoutMs: c.StatementTimeoutMs, MaxResultBytes: c.MaxResultBytes, MinGroupSize: c.MinGroupSize,
	}
	for _, t := range c.Tables {
		pt := &pb.PostgresTable{Schema: t.Schema, Name: t.Name, ScopeKey: t.ScopeKey, ScopeColumn: t.ScopeColumn, MaxRows: t.MaxRows}
		for _, col := range t.Columns {
			pt.Columns = append(pt.Columns, &pb.PostgresColumn{Name: col.Name, Type: col.Type, Class: col.Class})
		}
		out.Tables = append(out.Tables, pt)
	}
	return out
}
