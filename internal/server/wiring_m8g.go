// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/github/adapters/githubhttp"
	"github.com/katocxl/pantherclaw/internal/github/adapters/githubrpc"
	githubapp "github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/platform/config"
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
// the connection may declare only these (HR-160). The connection must be
// served by the gateway.
func packageFacts(pool *db.Pool) factsapp.PackageFacts {
	return func(ctx context.Context, org ids.OrgID, gateway, connection ids.UUID) (map[string]string, error) {
		out := map[string]string{}
		err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			conn, err := q.GetConnection(ctx, org, connection)
			if db.IsNoRows(err) || (err == nil && conn.GatewayID != gateway) {
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
					out[pr.Fact] = d.Target.Type
				}
			}
			for _, c := range p.Consequences {
				if d, ok := p.Definition(c.Operation); ok {
					for _, f := range c.RequiresFacts {
						out[f] = d.Target.Type
					}
				}
			}
			return nil
		}, db.ReadOnly())
		return out, err
	}
}

// registerM8G mounts the M8 track G services people use: the GitHub
// identity links independence compares (HR-207), each change notified and
// each made by GitHub sign-in (P2f), which is off without github.client_id.
// The sign-in App's client secret is read from its file here.
func registerM8G(rs *connect.Server, pool *db.Pool, notify githubapp.Notifier, gh GitHubConfig) error {
	s := &githubapp.Service{Pool: pool, Notify: notify}
	if gh.ClientID != "" {
		secret, err := config.ReadSecretFile(gh.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("github.client_secret_file: %w", err)
		}
		web, api := gh.URLs()
		s.Verifier = &githubhttp.Verifier{APIURL: api, ClientID: gh.ClientID, ClientSecret: secret}
		s.SignIn = githubapp.SignIn{ClientID: gh.ClientID, WebURL: web}
	}
	pantherclawv1connect.RegisterGitHubServiceHandler(rs, githubrpc.New(s))
	return nil
}
