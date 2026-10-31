// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"unicode/utf8"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the catalogue's mode and enforcement.
var (
	// ErrNotApproved refuses a connection to a server ENFORCE does not allow.
	ErrNotApproved = pcerr.New(pcerr.FailedPrecondition, "SERVER_NOT_APPROVED",
		"the catalogue is enforcing and no approved server matches this connection exactly")
	ErrPreviewStale = pcerr.New(pcerr.FailedPrecondition, "PREVIEW_STALE",
		"what this would do has changed: preview it again and confirm the new digest")
	ErrReason = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 500 characters is required")
	ErrHuman  = pcerr.New(pcerr.PermissionDenied, "HUMAN_SESSION_REQUIRED", "only a person may do this")
	ErrMode   = pcerr.New(pcerr.InvalidArgument, "MCP_CATALOG_MODE_INVALID", "the mode is OFF, WATCH or ENFORCE")
)

// Quarantiner stops a connection in the caller's transaction.
type Quarantiner interface {
	QuarantineForCatalogTx(ctx context.Context, tx db.TenantTx, caller tenancy.Caller, id ids.UUID) (bool, error)
}

// allowed reports whether c may run under ENFORCE: an APPROVED server matches
// it exactly, and no DENIED or REVOKED server does, so a second entry with
// the same URL never undoes a decision (HR-585).
func allowed(servers []dbq.PcMcpServer, c domain.Candidate) bool {
	ok := false
	for _, s := range servers {
		if !specOf(s).Matches(c) {
			continue
		}
		if domain.Status(s.Status) == domain.StatusDenied || domain.Status(s.Status) == domain.StatusRevoked {
			return false
		}
		ok = ok || domain.Status(s.Status) == domain.StatusApproved
	}
	return ok
}

func specOf(s dbq.PcMcpServer) domain.Spec {
	return domain.Spec{Host: deref(s.UrlHost), PathPrefix: deref(s.UrlPathPrefix), ImageDigest: deref(s.ImageDigest), PackageRef: deref(s.PackageRef)}
}

// candidate is what a connection reaches, as the catalogue compares it.
func candidate(t capp.CatalogTarget) domain.Candidate {
	if t.Image != "" {
		return domain.ImageCandidate(t.Image)
	}
	return domain.URLCandidate(t.BaseURL)
}

// decidedServers reads every server whose status bears on matching.
func decidedServers(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]dbq.PcMcpServer, error) {
	return q.McpServersIn(ctx, org, []string{string(domain.StatusApproved), string(domain.StatusDenied), string(domain.StatusRevoked)})
}

// Gate is the catalogue's check on a connection's lifecycle (D223). It holds
// the mode for its transaction, so a connection change and a switch to
// ENFORCE take turns. It implements capp.CatalogGate.
type Gate struct{}

var _ capp.CatalogGate = Gate{}

// CheckActivation implements capp.CatalogGate.
func (Gate) CheckActivation(ctx context.Context, tx db.TenantTx, t capp.CatalogTarget) error {
	org := tx.OrgID()
	q := dbq.New(tx)
	if err := q.EnsureMcpCatalogSettings(ctx, org); err != nil {
		return err
	}
	mode, err := q.ShareMcpCatalogMode(ctx, org)
	if err != nil {
		return err
	}
	if domain.Mode(mode) != domain.ModeEnforce {
		return nil
	}
	servers, err := decidedServers(ctx, q, org)
	if err != nil {
		return err
	}
	if !allowed(servers, candidate(t)) {
		return ErrNotApproved
	}
	return nil
}

// ModePreview is what a switch of mode would do.
type ModePreview struct {
	From, To domain.Mode
	// Quarantines are the active connections a switch to ENFORCE stops.
	Quarantines []dbq.McpConnectionsRow
	// SecondPerson says leaving ENFORCE waits for a second person.
	SecondPerson bool
	Digest       []byte
}

func target(r dbq.McpConnectionsRow) capp.CatalogTarget {
	return capp.CatalogTarget{BaseURL: deref(r.BaseUrl), Image: r.Image}
}

// previewMode computes a switch's preview in tx. The digest covers each
// connection's identity and state and the decided servers, so a change to
// either makes it stale (HR-252).
func previewMode(ctx context.Context, q *dbq.Queries, org ids.OrgID, from, to domain.Mode) (ModePreview, error) {
	p := ModePreview{From: from, To: to, SecondPerson: from == domain.ModeEnforce && to != domain.ModeEnforce}
	type item struct{ ID, State, Base, Image string }
	type serverItem struct{ ID, Status string }
	var items []item
	var serverItems []serverItem
	if to == domain.ModeEnforce && from != domain.ModeEnforce {
		conns, err := q.McpConnections(ctx, org)
		if err != nil {
			return ModePreview{}, err
		}
		servers, err := decidedServers(ctx, q, org)
		if err != nil {
			return ModePreview{}, err
		}
		for _, s := range servers {
			serverItems = append(serverItems, serverItem{s.ID.String(), s.Status})
		}
		for _, c := range conns {
			if c.State == capp.StateActive && !allowed(servers, candidate(target(c))) {
				p.Quarantines = append(p.Quarantines, c)
				items = append(items, item{c.ID.String(), c.State, deref(c.BaseUrl), c.Image})
			}
		}
	}
	b, err := json.Marshal(struct {
		From, To string
		Items    []item
		Servers  []serverItem
	}{string(from), string(to), items, serverItems}, json.Deterministic(true))
	if err != nil {
		return ModePreview{}, err
	}
	sum := sha256.Sum256(b)
	p.Digest = sum[:]
	return p, nil
}

// PreviewMode says what switching to a mode would do (catalog.read).
func (s *Service) PreviewMode(ctx context.Context, to domain.Mode) (ModePreview, error) {
	if !to.Valid() {
		return ModePreview{}, ErrMode
	}
	c, err := s.use(ctx, td.PermCatalogRead)
	if err != nil {
		return ModePreview{}, err
	}
	var out ModePreview
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := settings(ctx, q, c.Org)
		if err != nil {
			return err
		}
		out, err = previewMode(ctx, q, c.Org, domain.Mode(row.Mode), to)
		return err
	})
	return out, err
}

// ModeResult is what SetMode did.
type ModeResult struct {
	Settings    dbq.PcMcpCatalogSetting
	Quarantined []ids.UUID
	// Held is the protected change a weakening filed: Settings are unchanged.
	Held *protect.PendingError
}

// modePayload is a held change of mode.
type modePayload struct {
	To     domain.Mode `json:"to"`
	Reason string      `json:"reason"`
}

// modeSubject is the subject of the mode's changes.
var modeSubject = protect.SubjectID(protect.SurfaceCatalogMode, "mcp_catalog_mode")

// RegisterProtect sets the Gate's applier for the catalogue's mode.
func (s *Service) RegisterProtect(g *protect.Gate) {
	s.Protect = g
	if g != nil {
		g.Register(protect.SurfaceCatalogMode, s.ApplyMode, s.modeState)
	}
}

// SetMode changes the mode: a person holding catalog.manage with a fresh
// step-up (D222). A switch to ENFORCE confirms the digest of a current
// preview and quarantines what it listed, in one transaction. Leaving ENFORCE
// always waits for a second person (HR-586) and changes nothing until one
// confirms it. Weakening needs no edition, so a lapsed org is not stuck.
func (s *Service) SetMode(ctx context.Context, to domain.Mode, digest []byte, reason string) (ModeResult, error) {
	if !to.Valid() {
		return ModeResult{}, ErrMode
	}
	if n := utf8.RuneCountInString(reason); n < 1 || n > 500 || !utf8.ValidString(reason) {
		return ModeResult{}, ErrReason
	}
	c, err := s.caller(ctx, td.PermCatalogManage)
	if err != nil {
		return ModeResult{}, err
	}
	if !c.Human() {
		return ModeResult{}, ErrHuman
	}
	if to == domain.ModeEnforce {
		if err := s.entitled(ctx); err != nil {
			return ModeResult{}, err
		}
	}
	var out ModeResult
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := rapp.FreshStepUp(ctx, q, c); err != nil {
			return err
		}
		if err := q.EnsureMcpCatalogSettings(ctx, c.Org); err != nil {
			return err
		}
		row, err := q.LockMcpCatalogSettings(ctx, c.Org)
		if err != nil {
			return err
		}
		from := domain.Mode(row.Mode)
		out.Settings = row
		switch {
		case from == to:
			return nil
		case from == domain.ModeEnforce:
			out.Held, err = s.hold(ctx, tx, c, from, to, reason)
			return err
		case to == domain.ModeEnforce:
			p, err := previewMode(ctx, q, c.Org, from, to)
			if err != nil {
				return err
			}
			if !bytes.Equal(p.Digest, digest) {
				return ErrPreviewStale
			}
			for _, conn := range p.Quarantines {
				done, err := s.Connections.QuarantineForCatalogTx(ctx, tx, c, conn.ID)
				if err != nil {
					return err
				}
				if done {
					out.Quarantined = append(out.Quarantined, conn.ID)
				}
			}
		}
		out.Settings, err = write(ctx, tx, c, from, to, reason)
		return err
	})
	return out, err
}

// hold files the weakening. The surface is always protected, so the Gate
// never runs the apply it is given here (HR-586).
func (s *Service) hold(ctx context.Context, tx db.TenantTx, c tenancy.Caller, from, to domain.Mode, reason string) (*protect.PendingError, error) {
	held, err := s.Protect.Hold(ctx, tx, c, protect.Change{
		Category: protect.ToolMeaning, Surface: protect.SurfaceCatalogMode, Subject: modeSubject.String(), SubjectID: modeSubject,
		Summary:  map[string]string{"mode_old": string(from), "mode_new": string(to), "reason": reason},
		Widening: []string{"catalog_mode"}, Payload: modePayload{To: to, Reason: reason},
	}, func(context.Context) error { return protect.ErrUnavailable })
	if err != nil {
		return nil, err
	}
	if held == nil {
		return nil, protect.ErrUnavailable // leaving ENFORCE never applies at once
	}
	return held, nil
}

// write stores the mode and records it. The epoch stays: a mode decides
// nothing on the path, and quarantines raise it themselves.
func write(ctx context.Context, tx db.TenantTx, c tenancy.Caller, from, to domain.Mode, reason string) (dbq.PcMcpCatalogSetting, error) {
	by := c.Principal.String()
	row, err := dbq.New(tx).SetMcpCatalogMode(ctx, string(to), &by, tx.OrgID())
	if err != nil {
		return row, err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "mcp.catalog.mode_changed", Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "mcp_catalog", ID: tx.OrgID().String()},
		Details: map[string]string{"mode_old": string(from), "mode_new": string(to), "reason": reason},
	})
	return row, err
}

// ApplyMode is the confirmed re-run of a held change of mode (a
// protect.Applier).
func (s *Service) ApplyMode(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p modePayload
	if err := json.Unmarshal(payload, &p); err != nil || !p.To.Valid() {
		return protect.ErrInvalid
	}
	if err := author.Require(td.PermCatalogManage, td.OrgPath(author.Org)); err != nil {
		return err
	}
	q := dbq.New(tx)
	row, err := q.LockMcpCatalogSettings(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	_, err = write(ctx, tx, author, domain.Mode(row.Mode), p.To, p.Reason)
	return err
}

// modeState is what a confirmed re-run must still find: the mode as filed.
func (s *Service) modeState(ctx context.Context, tx db.TenantTx, _ []byte) ([]byte, error) {
	row, err := settings(ctx, dbq.New(tx), tx.OrgID())
	if err != nil {
		return nil, err
	}
	return []byte(row.Mode), nil
}
