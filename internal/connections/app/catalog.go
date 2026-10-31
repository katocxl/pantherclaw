// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// QuarantineCatalogNotApproved is the reason code of a connection the MCP
// server catalogue quarantined on the switch to ENFORCE (G0 M24 D223).
const QuarantineCatalogNotApproved = "catalog_not_approved"

// CatalogTarget is the MCP server a connection reaches: its URL, or a
// connector's image. Other kinds have none.
type CatalogTarget struct {
	BaseURL, Image string
}

// CatalogGate refuses to activate a connection to a server the catalogue
// does not allow (G0 M24 D223). It runs in the change's transaction and on
// the connection's lifecycle only, never on the decision path. An error
// refuses the change.
type CatalogGate interface {
	CheckActivation(ctx context.Context, tx db.TenantTx, t CatalogTarget) error
}

// WithCatalog sets the catalogue's check; nil has none.
func (s *Service) WithCatalog(g CatalogGate) *Service {
	s.catalog = g
	return s
}

// servesMCP reports whether a kind of connection reaches an MCP server.
func servesMCP(kind string) bool { return kind == KindMCP || kind == KindMCPContainer }

func (s *Service) checkCatalog(ctx context.Context, tx db.TenantTx, t *CatalogTarget) error {
	if s.catalog == nil || t == nil {
		return nil
	}
	return s.catalog.CheckActivation(ctx, tx, *t)
}

// createdTarget is the server a connection of kind will reach, or nil when
// the kind reaches none.
func createdTarget(kind string, base *string, spec ConnectorSpec) *CatalogTarget {
	if !servesMCP(kind) {
		return nil
	}
	return &CatalogTarget{BaseURL: deref(base), Image: spec.Image}
}

// currentTarget is the server conn reaches now.
func currentTarget(ctx context.Context, q *dbq.Queries, conn dbq.PcConnection) (*CatalogTarget, error) {
	if !servesMCP(conn.Kind) {
		return nil, nil //nolint:nilnil // a kind with no server has no target
	}
	t := &CatalogTarget{BaseURL: deref(conn.BaseUrl)}
	if conn.Kind == KindMCPContainer {
		spec, err := q.CurrentConnectorSpec(ctx, conn.OrgID, conn.ID)
		if err != nil {
			return nil, err
		}
		t.Image = spec.Image
	}
	return t, nil
}

// QuarantineForCatalogTx quarantines an active connection in the caller's
// transaction, which raises the epoch, bumps its gateway's configuration,
// audits and notifies as any quarantine does; any other state is left as it
// is. It reports whether it quarantined.
//
// Precondition: it checks no permission itself. Its one caller is the
// catalogue's switch to ENFORCE, which has verified, in this same tx, that
// the caller is a person holding catalog.manage with a fresh security-key
// step-up. Exported only for that cross-package caller.
func (s *Service) QuarantineForCatalogTx(ctx context.Context, tx db.TenantTx, caller tenancy.Caller, id ids.UUID) (bool, error) {
	c := actor{Org: caller.Org, By: caller.Principal.String(), Audit: caller.Actor(), Caller: caller}
	conn, err := lock(ctx, dbq.New(tx), c.Org, id)
	if err != nil {
		return false, err
	}
	if conn.State != StateActive {
		return false, nil
	}
	reason := QuarantineCatalogNotApproved
	p := params(c, conn)
	p.State, p.QuarantineReason = StateQuarantined, &reason
	after, err := s.apply(ctx, tx, c, conn, p, []change{{field: "state", from: conn.State, to: StateQuarantined}}, "connection.quarantined",
		map[string]string{"reason_code": reason})
	if err != nil {
		return false, err
	}
	return true, s.notifyQuarantined(ctx, tx, c, after, reason)
}
