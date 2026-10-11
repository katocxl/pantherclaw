// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Evidence packs (G0 M7 design decision 15, HR-196, F525–F532, Team
// edition). A person holding evidence.export asks for a pack; a worker job
// builds it from that person's permissions at that moment (evidence.read
// where each transaction's agent lives), so what the scope holds beyond
// them is left out and counted as a gap. A pack's metadata and signed
// manifest are visible to its creator and to holders of evidence.read at
// org scope (they could read all of it); its content only to its creator,
// or to a holder of evidence.export and evidence.read at org scope.
// Creation and every download are audited, the download before any byte
// leaves.

// Pack limits.
const (
	// MaxPackTransactions bounds a scope named by its transactions.
	MaxPackTransactions = 1000
	// MaxPackRange bounds a time range.
	MaxPackRange = 366 * 24 * time.Hour
	// DownloadChunk is the size of one streamed message.
	DownloadChunk = 1 << 20
)

// Pack errors.
var (
	ErrPacksEdition  = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "evidence packs need a Team licence or higher")
	ErrPackNotFound  = pcerr.New(pcerr.NotFound, "PACK_NOT_FOUND", "evidence pack not found")
	ErrPackNotReady  = pcerr.New(pcerr.FailedPrecondition, "PACK_NOT_READY", "the evidence pack is not ready")
	ErrPackExpired   = pcerr.New(pcerr.FailedPrecondition, "PACK_EXPIRED", "the evidence pack expired: create a new one")
	ErrBadPackScope  = pcerr.New(pcerr.InvalidArgument, "INVALID_SCOPE", "name 1 to 1,000 transactions, a run, an agent, or a time range of at most 366 days")
	ErrRunNotFound   = pcerr.New(pcerr.NotFound, "RUN_NOT_FOUND", "run not found")
	ErrAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrPacksUnwired  = pcerr.New(pcerr.Unavailable, "PACKS_UNAVAILABLE", "evidence packs are not available on this server")
	errPackNoContent = errors.New("app: a ready pack without content")
)

// PackEnqueuer enqueues a pack's build job in the creating transaction.
type PackEnqueuer func(ctx context.Context, tx db.TenantTx, org ids.OrgID, pack ids.UUID) error

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// WithPacks adds evidence packs to the service.
func (s *Service) WithPacks(enqueue PackEnqueuer, editions Editions) *Service {
	s.enqueuePack, s.editions = enqueue, editions
	return s
}

// PackRequest is what a pack covers and holds.
type PackRequest struct {
	Kind         string // pack.ScopeTransactions, ScopeRun, ScopeAgent, ScopeTimeRange
	Transactions []ids.UUID
	Run, Agent   ids.UUID
	// From and To bound a time range, or narrow a run or an agent.
	From, To *time.Time
	Include  pack.Include
}

// Pack is a pack's metadata and, when ready, its signed manifest.
type Pack struct {
	ID            ids.UUID
	State         string
	Scope         pack.Scope
	ScopeJSON     []byte
	Include       pack.Include
	CreatedBy     ids.UUID
	Created       time.Time
	Ready         time.Time
	Expires       time.Time
	Items         int
	ContentSize   int64
	ContentSHA256 []byte
	Manifest      string
	ErrorCode     string
}

func (r PackRequest) scope() (pack.Scope, error) {
	sc := pack.Scope{Kind: r.Kind}
	if r.From != nil {
		sc.From = r.From.UTC().Format(time.RFC3339Nano)
	}
	if r.To != nil {
		sc.To = r.To.UTC().Format(time.RFC3339Nano)
	}
	if (r.From == nil) != (r.To == nil) || (r.From != nil && (!r.To.After(*r.From) || r.To.Sub(*r.From) > MaxPackRange)) {
		return sc, ErrBadPackScope
	}
	switch r.Kind {
	case pack.ScopeTransactions:
		if len(r.Transactions) == 0 || len(r.Transactions) > MaxPackTransactions || r.From != nil {
			return sc, ErrBadPackScope
		}
		for _, id := range r.Transactions {
			sc.Transactions = append(sc.Transactions, id.String())
		}
		slices.Sort(sc.Transactions)
		sc.Transactions = slices.Compact(sc.Transactions)
	case pack.ScopeRun:
		if r.Run.IsZero() {
			return sc, ErrBadPackScope
		}
		sc.Run = r.Run.String()
	case pack.ScopeAgent:
		if r.Agent.IsZero() {
			return sc, ErrBadPackScope
		}
		sc.Agent = r.Agent.String()
	case pack.ScopeTimeRange:
		if r.From == nil {
			return sc, ErrBadPackScope
		}
	default:
		return sc, ErrBadPackScope
	}
	return sc, nil
}

// CreateEvidencePack records a pack of req for the calling person and
// enqueues its build, in one transaction with the audit event. It needs
// evidence.export (human only) and a Team licence; a run or an agent of
// another org is not found (T-037). What the pack then holds is decided by
// the creator's evidence.read when it is built.
func (s *Service) CreateEvidencePack(ctx context.Context, req PackRequest) (Pack, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Pack{}, err
	}
	if !c.CanAnywhere(td.PermEvidenceExport) {
		return Pack{}, td.ErrPermissionDenied(td.PermEvidenceExport)
	}
	if s.enqueuePack == nil || s.editions == nil {
		return Pack{}, ErrPacksUnwired
	}
	ents, err := s.editions.Current(ctx)
	if err != nil {
		return Pack{}, err
	}
	if !ents.Edition.Paid() {
		return Pack{}, ErrPacksEdition
	}
	sc, err := req.scope()
	if err != nil {
		return Pack{}, err
	}
	scopeJSON, err := pack.Canonical(sc)
	if err != nil {
		return Pack{}, err
	}
	includeJSON, err := pack.Canonical(req.Include)
	if err != nil {
		return Pack{}, err
	}
	id := ids.NewV7()
	var out Pack
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		switch req.Kind {
		case pack.ScopeRun:
			if _, err := q.GetRun(ctx, c.Org, req.Run); db.IsNoRows(err) {
				return ErrRunNotFound
			} else if err != nil {
				return err
			}
		case pack.ScopeAgent:
			if _, err := q.GetAgent(ctx, c.Org, req.Agent); db.IsNoRows(err) {
				return ErrAgentNotFound
			} else if err != nil {
				return err
			}
		}
		if err := q.InsertEvidencePack(ctx, dbq.InsertEvidencePackParams{
			OrgID: c.Org, ID: id, CreatedBy: c.Principal.ID, ScopeKind: req.Kind, Scope: scopeJSON, Include: includeJSON,
		}); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.pack_created", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "evidence_pack", ID: id.String()},
			Details: map[string]string{"scope": req.Kind, "include": includeList(req.Include)},
		}); err != nil {
			return err
		}
		if err := s.enqueuePack(ctx, tx, c.Org, id); err != nil {
			return err
		}
		row, err := q.GetEvidencePack(ctx, c.Org, id)
		if err != nil {
			return err
		}
		out, err = packOf(row)
		return err
	})
	return out, err
}

func includeList(in pack.Include) string {
	var out []string
	for name, on := range map[string]bool{
		"receipts": in.Receipts, "versions": in.Versions, "approvals": in.Approvals, "containment": in.Containment, "captures": in.Captures,
	} {
		if on {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}

func packOf(r dbq.GetEvidencePackRow) (Pack, error) {
	p := Pack{
		ID: r.ID, State: r.State, ScopeJSON: r.Scope, CreatedBy: r.CreatedBy, Created: r.CreatedAt, ContentSHA256: r.ContentSha256,
	}
	if err := json.Unmarshal(r.Scope, &p.Scope); err != nil {
		return Pack{}, err
	}
	if err := json.Unmarshal(r.Include, &p.Include); err != nil {
		return Pack{}, err
	}
	if r.ErrorCode != nil {
		p.ErrorCode = *r.ErrorCode
	}
	if r.Manifest != nil {
		p.Manifest = *r.Manifest
	}
	if r.ContentSize.Valid {
		p.ContentSize = r.ContentSize.Int64
	}
	if r.Items != nil {
		p.Items = int(*r.Items)
	}
	if r.ReadyAt != nil {
		p.Ready = *r.ReadyAt
	}
	if r.ExpiresAt != nil {
		p.Expires = *r.ExpiresAt
	}
	return p, nil
}

// orgReader reports whether c reads evidence across the org.
func orgReader(c tenancy.Caller) bool { return c.Can(td.PermEvidenceRead, td.OrgPath(c.Org)) }

// GetEvidencePack returns a pack its creator, or an org-wide evidence
// reader, may see; any other is not found.
func (s *Service) GetEvidencePack(ctx context.Context, id ids.UUID) (Pack, error) {
	c, err := reader(ctx)
	if err != nil {
		return Pack{}, err
	}
	var out Pack
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetEvidencePack(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrPackNotFound
		} else if err != nil {
			return err
		}
		if r.CreatedBy != c.Principal.ID && !orgReader(c) {
			return ErrPackNotFound
		}
		out, err = packOf(r)
		return err
	}, db.ReadOnly())
	return out, err
}

// PackPage is one page of packs, newest first.
type PackPage struct {
	Items []Pack
	Next  string
}

// ListEvidencePacks lists the packs the caller may see: every pack for an
// org-wide evidence reader, otherwise their own.
func (s *Service) ListEvidencePacks(ctx context.Context, pr page.Request) (PackPage, error) {
	c, err := reader(ctx)
	if err != nil {
		return PackPage{}, err
	}
	var by *ids.UUID
	if !orgReader(c) {
		by = &c.Principal.ID
	}
	var out PackPage
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListEvidencePacks(ctx, dbq.ListEvidencePacksParams{
			OrgID: c.Org, CreatedBy: by, Before: pr.After, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListEvidencePacksRow) ids.UUID { return r.ID })
		for _, r := range rows {
			p, err := packOf(dbq.GetEvidencePackRow(r))
			if err != nil {
				return err
			}
			out.Items = append(out.Items, p)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Download is a ready pack's content.
type Download struct {
	Content []byte
	SHA256  []byte
}

// DownloadEvidencePack returns a ready pack's content to its creator, or to
// a holder of evidence.export and evidence.read at org scope, after
// recording evidence.pack_downloaded in the org's audit ledger.
func (s *Service) DownloadEvidencePack(ctx context.Context, id ids.UUID) (Download, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Download{}, err
	}
	if !c.CanAnywhere(td.PermEvidenceExport) {
		return Download{}, td.ErrPermissionDenied(td.PermEvidenceExport)
	}
	var out Download
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetEvidencePackContent(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrPackNotFound
		} else if err != nil {
			return err
		}
		org := td.OrgPath(c.Org)
		orgExporter := c.Can(td.PermEvidenceExport, org) && c.Can(td.PermEvidenceRead, org)
		if r.CreatedBy != c.Principal.ID && !orgExporter {
			return ErrPackNotFound
		}
		switch {
		case r.State == "EXPIRED" || (r.State == "READY" && r.ExpiresAt != nil && !r.ExpiresAt.After(time.Now())):
			return ErrPackExpired
		case r.State != "READY":
			return ErrPackNotReady
		case r.Content == nil:
			return errPackNoContent
		}
		sum := sha256.Sum256(r.Content)
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.pack_downloaded", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "evidence_pack", ID: id.String()},
		}); err != nil {
			return err
		}
		out = Download{Content: r.Content, SHA256: sum[:]}
		return nil
	})
	return out, err
}
