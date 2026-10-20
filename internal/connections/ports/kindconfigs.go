// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports holds the connection ports other packages implement (G0
// M14 D64): the stores of the configurations that the postgres and a2a
// kinds carry beside the connection row.
package ports

import (
	"context"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// KindConfig stores one kind's configuration (a postgres manifest, an
// a2a card pin) in the transaction that creates or updates the
// connection, and loads it for the gateway's configuration.
type KindConfig interface {
	// Save stores a validated configuration (the connections app's
	// *PostgresConfig or *A2AConfig) at the connection's revision. It may
	// return the base URL the configuration implies (an a2a interface
	// URL), which an update writes with the configuration (G0 M14 D85);
	// empty keeps the connection's.
	Save(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, revision int32, cfg any) (baseURL string, err error)
	// Load returns the connection's current configuration as the gateway
	// gets it (*pb.PostgresConfig or *pb.A2AConfig).
	Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID) (proto.Message, error)
}

// KindConfigs are the registered KindConfig of each kind. A kind without
// one cannot be created: the connections app refuses it with
// KIND_NOT_IMPLEMENTED (D4, D64). The zero value has none.
type KindConfigs struct {
	mu    sync.RWMutex
	m     map[string]KindConfig
	drift map[string]KindDrift
}

// Register sets the store of kind's configurations, at wiring time.
func (k *KindConfigs) Register(kind string, c KindConfig) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]KindConfig{}
	}
	k.m[kind] = c
}

// Get returns the store of kind's configurations; ok is false without one
// (and for a nil KindConfigs).
func (k *KindConfigs) Get(kind string) (KindConfig, bool) {
	if k == nil {
		return nil, false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	c, ok := k.m[kind]
	return c, ok
}

// KindDrift hears a drift report about a connection of its kind in the
// transaction that quarantines it (G0 M14 D86): an a2a card whose digest
// changed. An error refuses the report (for example a stale expected
// digest), and nothing is quarantined.
type KindDrift interface {
	Drift(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection ids.UUID, expected, observed string) error
}

// RegisterDrift sets the drift hook of kind, at wiring time.
func (k *KindConfigs) RegisterDrift(kind string, d KindDrift) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.drift == nil {
		k.drift = map[string]KindDrift{}
	}
	k.drift[kind] = d
}

// Drift returns kind's drift hook; ok is false without one.
func (k *KindConfigs) Drift(kind string) (KindDrift, bool) {
	if k == nil {
		return nil, false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	d, ok := k.drift[kind]
	return d, ok
}

// KindGatewayCheck is an optional part of a KindConfig: it validates the
// connection's configuration for a new gateway (one that must hold the
// postgres credential, or reach the peer agent), in the transaction that
// moves the connection (G0 M14 D105). An error refuses the move.
type KindGatewayCheck interface {
	CheckGateway(ctx context.Context, tx db.TenantTx, org ids.OrgID, connection, gateway ids.UUID) error
}
