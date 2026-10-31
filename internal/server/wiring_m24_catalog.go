// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/adapters/catalogrpc"
	catalogapp "github.com/katocxl/pantherclaw/internal/mcpcatalog/app"
)

// registerM24Catalog serves McpCatalogService (G0 M24 D222). The procedure
// permissions are in procedures_m24_catalog.go.
func registerM24Catalog(rs *connect.Server, d apiDeps) {
	svc := &catalogapp.Service{Pool: d.pool}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	pantherclawv1connect.RegisterMcpCatalogServiceHandler(rs, catalogrpc.New(svc))
}
