// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/adapters/saasrpc"
	saasapp "github.com/katocxl/pantherclaw/internal/saasdiscovery/app"
)

// registerM26SaaS serves SaasDiscoveryService (G0 M26 D407). The procedure
// permissions are in procedures_m26_saas.go.
func registerM26SaaS(rs *connect.Server, d apiDeps) {
	inv := aapp.NewInventory(d.pool, d.billing)
	if d.m5 != nil {
		inv = inv.WithNotify(d.m5.notifications)
	}
	svc := &saasapp.Service{Pool: d.pool, Inventory: inv}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	pantherclawv1connect.RegisterSaasDiscoveryServiceHandler(rs, saasrpc.New(svc))
}

func init() { postureSourceFactories = append(postureSourceFactories, newSaaSPostureSource) }

// newSaaSPostureSource reports external agents nobody owns, and tenants whose
// last run left something unread, to the queue.
func newSaaSPostureSource(pool *db.Pool, ents exapp.Entitlements) ports.Source {
	s := &saasapp.Source{Pool: pool}
	if ents != nil {
		s.Editions = ents
	}
	return s
}
