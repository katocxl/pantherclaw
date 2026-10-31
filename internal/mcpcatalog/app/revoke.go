// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"unicode/utf8"

	ddomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// NotStoppableHere is the state of a local server a scan saw: it runs outside
// any connection, so a revoke can only say so (D224, F877).
const NotStoppableHere = "not_stoppable_here"

// Errors of a revoke.
var (
	// ErrRevoked refuses a connection to a revoked server, in every mode: the
	// modes govern unapproved servers, and a revoke survives WATCH to OFF.
	ErrRevoked = pcerr.New(pcerr.FailedPrecondition, "SERVER_REVOKED", "this connection matches a revoked server")
	// ErrRevocationActive refuses to approve a server while a control of its
	// revocation is live.
	ErrRevocationActive = pcerr.New(pcerr.FailedPrecondition, "SERVER_REVOCATION_ACTIVE",
		"a control of this server's revocation is still live: it is lifted through its restoration first")
	ErrRevokeReason = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 1000 characters is required")
)

// Containment adds a revoke's controls (rapp.Containment).
type Containment interface {
	ContainServerIn(ctx context.Context, tx db.TenantTx, r rapp.ServerRevoke) (rapp.ServerRevoked, error)
}

// Versions moves a package version through its lifecycle in the caller's
// transaction (the definitions store).
type Versions interface {
	TransitionTx(ctx context.Context, tx db.TenantTx, pkg, version string, from, to ddomain.State, ev *audit.Event) error
}

// LocalServer is a local server a scan saw that a revoke cannot stop.
type LocalServer struct {
	Discovery ids.UUID
	// Name is what the scan reported: UNTRUSTED, plain text only.
	Name, DenyListHint string
}

// RevokePreview is what a revoke would do (HR-252).
type RevokePreview struct {
	Server      dbq.PcMcpServer
	Connections []dbq.McpConnectionsRow
	Versions    []dbq.McpPackageVersionsRow
	Locals      []LocalServer
	Digest      []byte
}

// RevokeResult is what RevokeServer did.
type RevokeResult struct {
	Preview RevokePreview
	Action  ids.UUID
	// Controls are one per connection; Plans lift them, for someone else to
	// decide. A lift returns neither the server nor the versions (D224a).
	Controls, Plans []ids.UUID
}

func denyHint(s domain.Spec) string {
	what := s.PackageRef
	if s.Host != "" {
		what = s.Host + s.PathPrefix
	}
	return "add " + what + " to the managed deny list"
}

// previewRevoke computes a revoke's preview in tx. The digest covers the
// server and each connection and version it would stop, so a change to any of
// them makes it stale (HR-252). Local servers are no part of it: nothing
// happens to them, and a scan must not stale a revoke.
func previewRevoke(ctx context.Context, q *dbq.Queries, org ids.OrgID, server dbq.PcMcpServer) (RevokePreview, error) {
	p := RevokePreview{Server: server}
	spec := specOf(server)
	conns, err := q.McpConnections(ctx, org)
	if err != nil {
		return RevokePreview{}, err
	}
	type item struct{ ID, State, Base, Image string }
	type version struct{ Package, Version, State string }
	items, versions := []item{}, []version{}
	for _, c := range conns {
		if spec.Matches(candidate(target(c))) {
			p.Connections = append(p.Connections, c)
			items = append(items, item{c.ID.String(), c.State, deref(c.BaseUrl), c.Image})
		}
	}
	if spec.PackageRef != "" {
		p.Versions, err = q.McpPackageVersions(ctx, org, spec.PackageRef)
		if err != nil {
			return RevokePreview{}, err
		}
		for _, v := range p.Versions {
			versions = append(versions, version{v.Package, v.Version, v.State})
		}
	}
	locals, err := q.McpScanServers(ctx, org)
	if err != nil {
		return RevokePreview{}, err
	}
	for _, l := range locals {
		if spec.Matches(scanCandidate(l)) {
			p.Locals = append(p.Locals, LocalServer{Discovery: l.ID, Name: l.Name, DenyListHint: denyHint(spec)})
		}
	}
	b, err := json.Marshal(struct {
		ID, Status string
		Spec       domain.Spec
		Items      []item
		Versions   []version
	}{server.ID.String(), server.Status, spec, items, versions}, json.Deterministic(true))
	if err != nil {
		return RevokePreview{}, err
	}
	sum := sha256.Sum256(b)
	p.Digest = sum[:]
	return p, nil
}

// revocable reads a server a revoke may act on: any but one already revoked.
// A revoke only stops things, so a server need not be APPROVED first.
func revocable(ctx context.Context, org ids.OrgID, id ids.UUID, read func(context.Context, ids.OrgID, ids.UUID) (dbq.PcMcpServer, error)) (dbq.PcMcpServer, error) {
	s, err := read(ctx, org, id)
	if db.IsNoRows(err) {
		return s, ErrNotFound
	}
	if err == nil && domain.Status(s.Status) == domain.StatusRevoked {
		return s, ErrStatus
	}
	return s, err
}

// PreviewRevoke says what revoking a server would do (catalog.read).
func (s *Service) PreviewRevoke(ctx context.Context, id ids.UUID) (RevokePreview, error) {
	c, err := s.use(ctx, td.PermCatalogRead)
	if err != nil {
		return RevokePreview{}, err
	}
	var out RevokePreview
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		server, err := revocable(ctx, c.Org, id, q.GetMcpServer)
		if err != nil {
			return err
		}
		out, err = previewRevoke(ctx, q, c.Org, server)
		return err
	})
	return out, err
}

// RevokeServer revokes a server against the digest of a current preview: a
// person holding catalog.manage with a fresh step-up (HR-587). In one
// transaction of one org it adds a DENY_ALL control per matching connection
// through the response service, quarantines the package's versions, and sets
// REVOKED. It holds the mode row, so a connection write and a revoke take
// turns and nothing connects between the digest and the commit.
func (s *Service) RevokeServer(ctx context.Context, id ids.UUID, digest []byte, reason string) (RevokeResult, error) {
	if n := utf8.RuneCountInString(reason); n < 1 || n > rdomain.MaxReason || !utf8.ValidString(reason) {
		return RevokeResult{}, ErrRevokeReason
	}
	c, err := s.use(ctx, td.PermCatalogManage)
	if err != nil {
		return RevokeResult{}, err
	}
	if !c.Human() {
		return RevokeResult{}, ErrHuman
	}
	var out RevokeResult
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := rapp.FreshStepUp(ctx, q, c); err != nil {
			return err
		}
		if err := q.EnsureMcpCatalogSettings(ctx, c.Org); err != nil {
			return err
		}
		if _, err := q.LockMcpCatalogSettings(ctx, c.Org); err != nil {
			return err
		}
		server, err := revocable(ctx, c.Org, id, q.LockMcpServer)
		if err != nil {
			return err
		}
		p, err := previewRevoke(ctx, q, c.Org, server)
		if err != nil {
			return err
		}
		if !bytes.Equal(p.Digest, digest) {
			return ErrPreviewStale
		}
		conns := make([]ids.UUID, 0, len(p.Connections))
		for _, conn := range p.Connections {
			conns = append(conns, conn.ID)
		}
		added, err := s.Containment.ContainServerIn(ctx, tx, rapp.ServerRevoke{
			Server: id, Connections: conns, Person: c.Principal.ID, Reason: reason, PreviewDigest: digest,
		})
		if err != nil {
			return err
		}
		for _, v := range p.Versions {
			if err := s.Versions.TransitionTx(ctx, tx, v.Package, v.Version, ddomain.State(v.State), ddomain.StateQuarantined, &audit.Event{
				Name: "package.transitioned", Actor: c.Actor(), Outcome: audit.Success,
				Object:  &audit.Object{Type: "package_version", ID: v.Package + "@" + v.Version},
				Details: map[string]string{"from": v.State, "to": string(ddomain.StateQuarantined), "mcp_server": id.String()},
			}); err != nil {
				return err
			}
		}
		by := c.Principal.String()
		if p.Server, err = q.DecideMcpServer(ctx, dbq.DecideMcpServerParams{
			OrgID: c.Org, ID: id, FromStatus: server.Status, ToStatus: string(domain.StatusRevoked), DecidedBy: &by,
		}); err != nil {
			return err
		}
		out = RevokeResult{Preview: p, Action: added.Action, Controls: added.Controls, Plans: added.Plans}
		return record(ctx, tx, c, "mcp.catalog.server_revoked", id, map[string]string{
			"name": server.Name, "status_old": server.Status, "status_new": string(domain.StatusRevoked), "reason": reason,
		})
	})
	return out, err
}

// reapprove is what approving a REVOKED server needs: every control of its
// revocation lifted, then a person with a fresh step-up (D224a).
func reapprove(ctx context.Context, q *dbq.Queries, c tenancy.Caller, id ids.UUID) error {
	live, err := q.McpRevocationLive(ctx, c.Org, id.String())
	if err != nil {
		return err
	}
	if live {
		return ErrRevocationActive
	}
	if !c.Human() {
		return ErrHuman
	}
	_, err = rapp.FreshStepUp(ctx, q, c)
	return err
}
