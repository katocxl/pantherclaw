// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"slices"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/github/adapters/githubrpc"
	githubapp "github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// gatewayFacts is the fact service a gateway reports a connection's facts
// to (G0 M8 decision 5, GatewayService.ReportFacts).
func gatewayFacts(pool *db.Pool) *factsapp.Service {
	return &factsapp.Service{Store: &factspg.Store{Pool: pool}, Packages: packageFacts(pool)}
}

// packageFacts names the facts a connection's pinned package uses, each
// with the target type it is about: every definition's prerequisites, and
// the facts its package's consequence rules require. A gateway provider of
// the connection may declare and report only these (HR-160). The connection
// must be active and served by the gateway.
func packageFacts(pool *db.Pool) factsapp.PackageFacts {
	return func(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID) (map[string][]string, error) {
		out := map[string][]string{}
		add := func(fact, typ string) {
			if !slices.Contains(out[fact], typ) {
				out[fact] = append(out[fact], typ)
			}
		}
		err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			conn, err := q.GetConnection(ctx, org, connection)
			if db.IsNoRows(err) || (err == nil && (conn.GatewayID != gateway || conn.State != "ACTIVE")) {
				return factsapp.ErrConnectionUnknown
			} else if err != nil {
				return err
			}
			pin, err := q.PinnedPackageRaw(ctx, org, conn.Package)
			if db.IsNoRows(err) {
				return factsapp.ErrConnectionUnknown
			} else if err != nil {
				return err
			}
			p, err := manifest.Decode(pin.Raw)
			if err != nil {
				return err
			}
			for _, d := range p.Definitions {
				for _, pr := range d.Prerequisites {
					add(pr.Fact, d.Target.Type)
				}
			}
			for _, c := range p.Consequences {
				if d, ok := p.Definition(c.Operation); ok {
					for _, f := range c.RequiresFacts {
						add(f, d.Target.Type)
					}
				}
			}
			return nil
		}, db.ReadOnly())
		return out, err
	}
}

// registerM8G mounts the M8 track G services people use: the GitHub
// identity links independence compares (HR-207), and organization scans
// (HR-209).
func registerM8G(rs *connect.Server, pool *db.Pool, ents githubapp.Entitlements) {
	pantherclawv1connect.RegisterGitHubServiceHandler(rs, githubrpc.New(&githubapp.Service{Pool: pool}, &githubapp.Scans{Pool: pool, Ents: ents}))
}
