// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/adapters/catalogrpc"
	catalogapp "github.com/katocxl/pantherclaw/internal/mcpcatalog/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
)

// registerM24Catalog serves McpCatalogService (G0 M24 D222), holds a change
// of mode out of ENFORCE behind the Gate (HR-586) and connects the catalogue
// to the connection lifecycle (D223). The procedure permissions are in
// procedures_m24_catalog.go.
func registerM24Catalog(rs *connect.Server, d apiDeps) {
	var notify rapp.Notifier
	if d.m5 != nil {
		notify = responseNotifier(d.m5)
	}
	svc := &catalogapp.Service{Pool: d.pool, Containment: responseContainment(d.pool, notify, d.billing), Versions: &defspg.Store{Pool: d.pool}}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	svc.RegisterProtect(d.m11protect.gate)
	if d.m6 != nil && d.m6.connections != nil {
		svc.Connections = d.m6.connections
		d.m6.connections.WithCatalog(catalogapp.Gate{})
	}
	pantherclawv1connect.RegisterMcpCatalogServiceHandler(rs, catalogrpc.New(svc))
}

func init() { postureSourceFactories = append(postureSourceFactories, newCatalogPostureSource) }

// newCatalogPostureSource reports unapproved servers to the queue (D226).
func newCatalogPostureSource(pool *db.Pool, ents exapp.Entitlements) ports.Source {
	s := &catalogapp.Source{Pool: pool}
	if ents != nil {
		s.Editions = ents
	}
	return s
}
