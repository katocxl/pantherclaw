// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgvectorstore is the vectorstore kind's configuration store (G0
// M30 D922-D925a): pc.vectorstore_connections, written in the transaction
// that creates or changes a vectorstore connection and loaded into the
// gateway's configuration. An internal endpoint, as a postgres
// connection's, never runs on a gateway PantherClaw hosts.
package pgvectorstore

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Store is the vectorstore kind's ports.KindConfig. Hosted reports whether
// PantherClaw hosts a gateway; nil refuses every internal endpoint.
type Store struct {
	Hosted func(gateway ids.UUID) bool
}

var (
	_ ports.KindConfig       = Store{}
	_ ports.KindGatewayCheck = Store{}
)

// ErrInternalHosted: an internal endpoint runs only on a customer-hosted
// gateway, as a postgres connection's.
var ErrInternalHosted = pcerr.New(pcerr.InvalidArgument, "INTERNAL_NOT_ALLOWED",
	"internal is allowed only on a vectorstore connection served by a customer-hosted gateway")

// ErrType: Save was given something other than a vectorstore configuration.
var ErrType = errors.New("pgvectorstore: not a vectorstore configuration")

// Save stores a checked *capp.VectorstoreConfig; a vectorstore connection
// implies no base URL.
func (s Store) Save(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, _ int32, cfg any) (string, error) {
	c, ok := cfg.(*capp.VectorstoreConfig)
	if !ok || c == nil {
		return "", ErrType
	}
	if c.Internal {
		conn, err := dbq.New(tx).GetConnection(ctx, org, connection)
		if err != nil {
			return "", err
		}
		if s.Hosted == nil || s.Hosted(conn.GatewayID) {
			return "", ErrInternalHosted
		}
	}
	return "", capp.SaveVectorstore(ctx, tx, org, connection, c)
}

// Load returns the connection's settings as the gateway gets them.
func (Store) Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID) (proto.Message, error) {
	row, err := dbq.New(tx).GetVectorstoreConnection(ctx, org, connection)
	if err != nil {
		return nil, err
	}
	return ToProto(capp.VectorstoreConfigFromRow(row)), nil
}

// CheckGateway refuses to move an internal vectorstore connection to a
// gateway PantherClaw hosts (ports.KindGatewayCheck, as postgres, D105).
func (s Store) CheckGateway(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection, gateway ids.UUID) error {
	row, err := dbq.New(tx).GetVectorstoreConnection(ctx, org, connection)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	if row.Internal && (s.Hosted == nil || s.Hosted(gateway)) {
		return ErrInternalHosted
	}
	return nil
}

// ToProto is a vectorstore configuration on the wire.
func ToProto(c *capp.VectorstoreConfig) *pb.VectorstoreConfig {
	if c == nil {
		return nil
	}
	out := &pb.VectorstoreConfig{
		Host: c.Host, Port: c.Port, Database: c.Database, User: c.User, Sslmode: c.SSLMode, CaPem: c.CAPEM,
		Internal: c.Internal, SchemaName: c.Schema, TableName: c.Table, Dimensions: c.Dimensions, Distance: c.Distance,
	}
	for _, w := range c.Writers {
		out.WriterAgentIds = append(out.WriterAgentIds, w.String())
	}
	return out
}

// FromProto is a vectorstore configuration from the wire; nil when absent.
// A writer that is not a uuid is refused.
func FromProto(c *pb.VectorstoreConfig) (*capp.VectorstoreConfig, error) {
	if c == nil {
		return nil, nil
	}
	out := &capp.VectorstoreConfig{
		Host: c.GetHost(), Port: c.GetPort(), Database: c.GetDatabase(), User: c.GetUser(), SSLMode: c.GetSslmode(),
		CAPEM: c.GetCaPem(), Internal: c.GetInternal(), Schema: c.GetSchemaName(), Table: c.GetTableName(),
		Dimensions: c.GetDimensions(), Distance: c.GetDistance(),
	}
	for _, w := range c.GetWriterAgentIds() {
		id, err := ids.ParseUUID(w)
		if err != nil {
			return nil, capp.ErrVectorstoreConfig
		}
		out.Writers = append(out.Writers, id)
	}
	return out, nil
}
