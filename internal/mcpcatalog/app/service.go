// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the MCP server catalogue's use cases (G0 M24 D220-D226;
// F872-F879; HR-585, HR-586, HR-587). Nothing here runs on the decision path:
// the catalogue acts on a connection's lifecycle and through the response
// service, and the Authority decides as it always did (D223).
package app

import (
	"context"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrEdition  = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "the MCP server catalogue needs the Team edition or above")
	ErrNotFound = pcerr.New(pcerr.NotFound, "MCP_SERVER_NOT_FOUND", "MCP server not found")
	ErrNameUsed = pcerr.New(pcerr.AlreadyExists, "MCP_SERVER_NAME_TAKEN", "the catalogue already has a server of this name")
	ErrStatus   = pcerr.New(pcerr.FailedPrecondition, "MCP_SERVER_STATUS", "the server is not in a status that allows this")
)

// Editions reports the licence's entitlements. Nil is Community (fail
// closed).
type Editions interface {
	Current(ctx context.Context) (bdomain.Entitlements, error)
}

// Service serves the catalogue.
type Service struct {
	Pool     *db.Pool
	Editions Editions
	// Connections quarantines on the switch to ENFORCE.
	Connections Quarantiner
	// Protect holds a change of mode out of ENFORCE (RegisterProtect, HR-586);
	// nil refuses it.
	Protect *protect.Gate
}

// caller reads who is calling and checks the permission at the org.
func (s *Service) caller(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

// entitled checks the edition (D222).
func (s *Service) entitled(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.MCPCatalog() {
		return ErrEdition
	}
	return nil
}

// use is caller and entitled together, what most of the catalogue needs.
func (s *Service) use(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := s.caller(ctx, p)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, s.entitled(ctx)
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, server ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "mcp_server", ID: server.String()}, Details: details,
	})
	return err
}

// Propose adds a PROPOSED server (catalog.manage). Proposing changes nothing
// a connection may do.
func (s *Service) Propose(ctx context.Context, p domain.Proposal) (dbq.PcMcpServer, error) {
	c, err := s.use(ctx, td.PermCatalogManage)
	if err != nil {
		return dbq.PcMcpServer{}, err
	}
	p, err = p.Check()
	if err != nil {
		return dbq.PcMcpServer{}, err
	}
	var out dbq.PcMcpServer
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).InsertMcpServer(ctx, dbq.InsertMcpServerParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: p.Name, Title: p.Title, Transport: p.Transport, PackageRef: opt(p.Spec.PackageRef),
			UrlHost: opt(p.Spec.Host), UrlPathPrefix: opt(p.Spec.PathPrefix), ImageDigest: opt(p.Spec.ImageDigest), Notes: p.Notes,
		})
		if db.IsUniqueViolation(err) {
			return ErrNameUsed
		} else if err != nil {
			return err
		}
		return record(ctx, tx, c, "mcp.catalog.server_proposed", out.ID, map[string]string{
			"name": out.Name, "transport": out.Transport, "url_host": deref(out.UrlHost), "url_path_prefix": deref(out.UrlPathPrefix),
			"image_digest": deref(out.ImageDigest), "package_ref": deref(out.PackageRef),
		})
	})
	return out, err
}

// Approve moves a PROPOSED or DENIED server to APPROVED (catalog.manage). A
// REVOKED server comes back only through its revoke's restoration.
func (s *Service) Approve(ctx context.Context, id ids.UUID) (dbq.PcMcpServer, error) {
	return s.decide(ctx, id, domain.StatusApproved, "mcp.catalog.server_approved", domain.StatusProposed, domain.StatusDenied)
}

// Deny moves a PROPOSED server to DENIED (catalog.manage). An approved server
// leaves the catalogue through a revoke, which stops what matches it.
func (s *Service) Deny(ctx context.Context, id ids.UUID) (dbq.PcMcpServer, error) {
	return s.decide(ctx, id, domain.StatusDenied, "mcp.catalog.server_denied", domain.StatusProposed)
}

func (s *Service) decide(ctx context.Context, id ids.UUID, to domain.Status, event string, from ...domain.Status) (dbq.PcMcpServer, error) {
	c, err := s.use(ctx, td.PermCatalogManage)
	if err != nil {
		return dbq.PcMcpServer{}, err
	}
	var out dbq.PcMcpServer
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cur, err := q.LockMcpServer(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		known := false
		for _, f := range from {
			known = known || domain.Status(cur.Status) == f
		}
		if !known {
			return ErrStatus
		}
		by := c.Principal.String()
		out, err = q.DecideMcpServer(ctx, dbq.DecideMcpServerParams{
			OrgID: c.Org, ID: id, FromStatus: cur.Status, ToStatus: string(to), DecidedBy: &by,
		})
		if err != nil {
			return err
		}
		return record(ctx, tx, c, event, id, map[string]string{"name": out.Name, "status_old": cur.Status, "status_new": out.Status})
	})
	return out, err
}

// Get reads one server (catalog.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (dbq.PcMcpServer, error) {
	c, err := s.use(ctx, td.PermCatalogRead)
	if err != nil {
		return dbq.PcMcpServer{}, err
	}
	var out dbq.PcMcpServer
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetMcpServer(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		return err
	})
	return out, err
}

// List pages the catalogue (catalog.read).
func (s *Service) List(ctx context.Context, size int32, token string, statuses []string) ([]dbq.PcMcpServer, string, error) {
	c, err := s.use(ctx, td.PermCatalogRead)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	if statuses == nil {
		statuses = []string{}
	}
	var out []dbq.PcMcpServer
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListMcpServers(ctx, dbq.ListMcpServersParams{OrgID: c.Org, Statuses: statuses, AfterID: pr.After, MaxRows: pr.Limit()})
		if err != nil {
			return err
		}
		out, next = page.Finish(pr, rows, func(r dbq.PcMcpServer) ids.UUID { return r.ID })
		return nil
	})
	return out, next, err
}

// GetSettings reads the catalogue's mode (catalog.read).
func (s *Service) GetSettings(ctx context.Context) (dbq.PcMcpCatalogSetting, error) {
	c, err := s.use(ctx, td.PermCatalogRead)
	if err != nil {
		return dbq.PcMcpCatalogSetting{}, err
	}
	var out dbq.PcMcpCatalogSetting
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = settings(ctx, dbq.New(tx), c.Org)
		return err
	})
	return out, err
}

// settings reads the org's row, or the default when it has none yet.
func settings(ctx context.Context, q *dbq.Queries, org ids.OrgID) (dbq.PcMcpCatalogSetting, error) {
	row, err := q.GetMcpCatalogSettings(ctx, org)
	if db.IsNoRows(err) {
		return dbq.PcMcpCatalogSetting{OrgID: org, Mode: string(domain.DefaultMode)}, nil
	}
	return row, err
}
