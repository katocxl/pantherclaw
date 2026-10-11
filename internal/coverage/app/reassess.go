// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrHumanOnly reports a caller that is not a person signed in as
// themselves.
var ErrHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")

// Reassessed counts what a reassessment did.
type Reassessed struct {
	Scopes, Snapshots int
}

// reassessScopes reassesses each scope in tx, in order.
func (s *Service) reassessScopes(ctx context.Context, tx db.TenantTx, scopes []domain.Scope, cause *ids.UUID,
	actor evdomain.Actor, pkgs packages,
) (Reassessed, error) {
	var out Reassessed
	for _, sc := range scopes {
		recorded, err := s.reassess(ctx, tx, sc, cause, actor, pkgs)
		if err != nil {
			return out, err
		}
		out.Scopes++
		if recorded {
			out.Snapshots++
		}
	}
	return out, nil
}

// scopesOf lists the scopes known for a connection, optionally one agent's.
func scopesOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, connection ids.UUID, agent *ids.UUID) ([]domain.Scope, error) {
	rows, err := q.CoverageScopesOfConnection(ctx, org, connection, agent)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Scope, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Scope{Agent: r.AgentID, Connection: connection, Operation: r.Operation})
	}
	return out, nil
}

// Reassess recomputes the scopes of one connection now, from evidence,
// after reading new traffic, and records a snapshot for each that changed.
// The caller is a person holding coverage.manage at org scope.
func (s *Service) Reassess(ctx context.Context, connection ids.UUID, agent *ids.UUID) (Reassessed, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Reassessed{}, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return Reassessed{}, ErrHumanOnly
	}
	if err := c.Require(td.PermCoverageManage, td.OrgPath(c.Org)); err != nil {
		return Reassessed{}, err
	}
	var out Reassessed
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.CoverageBinding(ctx, c.Org, connection); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := s.RefreshTraffic(ctx, tx); err != nil {
			return err
		}
		scopes, err := scopesOf(ctx, q, c.Org, connection, agent)
		if err != nil {
			return err
		}
		out, err = s.reassessScopes(ctx, tx, scopes, nil, c.Actor(), packages{})
		return err
	})
	return out, err
}
