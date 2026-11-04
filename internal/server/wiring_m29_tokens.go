// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/modelusage/adapters/modelusagerpc"
	muapp "github.com/katocxl/pantherclaw/internal/modelusage/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// registerModelUsage serves ModelUsageService on the public API (G0 M29
// D825); without an entitlements source the report is refused (D829).
func registerModelUsage(rs *connect.Server, d apiDeps) {
	svc := &muapp.Service{Pool: d.pool}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	pantherclawv1connect.RegisterModelUsageServiceHandler(rs, modelusagerpc.New(svc))
}

// tokenCostReports reports whether usage rows carry a cost estimate: the
// Team edition or above now (G0 M29 D825, D829). Without a licence source,
// or when it cannot be read, none (fail closed).
func tokenCostReports(b *billing.Service) func(context.Context, ids.OrgID) bool {
	if b == nil {
		return nil
	}
	return func(ctx context.Context, _ ids.OrgID) bool {
		e, err := b.Current(ctx)
		return err == nil && e.TokenCostReports()
	}
}
