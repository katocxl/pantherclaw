// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgmodel is the model kind's configuration store (G0 M29 D811):
// pc.model_connections, written in the transaction that creates or changes a
// model connection and loaded into the gateway's configuration.
package pgmodel

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Store is the model kind's ports.KindConfig.
type Store struct{}

var _ ports.KindConfig = Store{}

// Save stores a checked *capp.ModelConfig; a model connection implies no
// base URL.
func (Store) Save(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, _ int32, cfg any) (string, error) {
	m, ok := cfg.(*capp.ModelConfig)
	if !ok || m == nil {
		return "", errors.New("pgmodel: not a model configuration")
	}
	return "", capp.SaveModel(ctx, tx, org, connection, m)
}

// Load returns the connection's settings as the gateway gets them.
func (Store) Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID) (proto.Message, error) {
	row, err := dbq.New(tx).GetModelConnection(ctx, org, connection)
	if err != nil {
		return nil, err
	}
	return ToProto(capp.ModelConfigFromRow(row)), nil
}

// ToProto is a model configuration on the wire.
func ToProto(m *capp.ModelConfig) *pb.ModelConfig {
	if m == nil {
		return nil
	}
	out := &pb.ModelConfig{MaxOutputTokens: m.MaxOutputTokens, AllowedServerTools: m.AllowedServerTools}
	if p := m.Price; p != nil {
		out.Price = &pb.ModelPrice{
			Currency: p.Currency, InputPerMillion: p.Input, OutputPerMillion: p.Output,
			CacheReadPerMillion: p.CacheRead, CacheWritePerMillion: p.CacheWrite,
		}
	}
	return out
}

// FromProto is a model configuration from the wire; nil when absent.
func FromProto(m *pb.ModelConfig) *capp.ModelConfig {
	if m == nil {
		return nil
	}
	out := &capp.ModelConfig{MaxOutputTokens: m.GetMaxOutputTokens(), AllowedServerTools: m.GetAllowedServerTools()}
	if p := m.GetPrice(); p != nil {
		out.Price = &capp.ModelPrice{
			Currency: p.GetCurrency(), Input: p.GetInputPerMillion(), Output: p.GetOutputPerMillion(),
			CacheRead: p.GetCacheReadPerMillion(), CacheWrite: p.GetCacheWritePerMillion(),
		}
	}
	return out
}
