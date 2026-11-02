// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the content signal settings (G0 M27 D505, D507, D512;
// F936; HR-647, HR-650, HR-652). Nothing here runs on the decision path.
package app

import (
	"context"
	"encoding/json/v2"
	"unicode/utf8"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrEdition     = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "content signals need the Business edition or above")
	ErrMode        = pcerr.New(pcerr.InvalidArgument, "CONTENT_MODE_INVALID", "the mode is not one of OFF, WATCHING, ACTIVE")
	ErrReason      = pcerr.New(pcerr.InvalidArgument, "CONTENT_REASON_INVALID", "a reason of 1 to 500 characters is required")
	ErrHuman       = pcerr.New(pcerr.PermissionDenied, "CONTENT_HUMAN_ONLY", "only a person may change the content signal mode")
	ErrWatchFirst  = pcerr.New(pcerr.FailedPrecondition, "CONTENT_WATCH_FIRST", "content signals reach ACTIVE only from WATCHING")
	errUnavailable = protect.ErrUnavailable
)

// Editions reports the licence's entitlements. Nil is Community (fail
// closed).
type Editions interface {
	Current(ctx context.Context) (bdomain.Entitlements, error)
}

// Service serves the settings.
type Service struct {
	Pool     *db.Pool
	Editions Editions
	// Protect holds a change of mode out of ACTIVE (RegisterProtect, D512);
	// nil refuses it.
	Protect *protect.Gate
}

// Settings are the org's settings and what WATCHING would have held.
type Settings struct {
	Row       dbq.PcContentSignalSetting
	WouldHold []dbq.PcContentSignalWouldHold
}

// Mode is the row's mode; a missing row is OFF.
func (s Settings) Mode() domain.Mode {
	if s.Row.Mode == "" {
		return domain.ModeOff
	}
	return domain.Mode(s.Row.Mode)
}

// Result is what SetMode did.
type Result struct {
	Settings Settings
	// Held is the protected change leaving ACTIVE filed: Settings are
	// unchanged.
	Held *protect.PendingError
}

// modePayload is a held change of mode.
type modePayload struct {
	To     domain.Mode `json:"to"`
	Reason string      `json:"reason"`
}

// modeSubject is the subject of the mode's changes.
var modeSubject = protect.SubjectID(protect.SurfaceContentSignalMode, "content_signal_mode")

// RegisterProtect sets the Gate's applier for the mode.
func (s *Service) RegisterProtect(g *protect.Gate) {
	s.Protect = g
	if g != nil {
		g.Register(protect.SurfaceContentSignalMode, s.ApplyMode, s.modeState)
	}
}

func (s *Service) caller(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

func (s *Service) entitled(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.ContentSignals() {
		return ErrEdition
	}
	return nil
}

// Get reads the settings on every plan state: a lapsed org still sees that a
// signal is on (HR-652).
func (s *Service) Get(ctx context.Context) (Settings, error) {
	c, err := s.caller(ctx, td.PermContentRead)
	if err != nil {
		return Settings{}, err
	}
	var out Settings
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = read(ctx, dbq.New(tx), c.Org)
		return err
	})
	return out, err
}

func read(ctx context.Context, q *dbq.Queries, org ids.OrgID) (Settings, error) {
	var out Settings
	row, err := q.GetContentSignalSettings(ctx, org)
	switch {
	case db.IsNoRows(err):
		row.Mode = string(domain.ModeOff)
	case err != nil:
		return out, err
	}
	out.Row = row
	out.WouldHold, err = q.ContentWouldHolds(ctx, org)
	return out, err
}

// SetMode changes the mode, a person holding content.manage. The way up is
// OFF, WATCHING, ACTIVE, and ACTIVE takes a fresh security-key step-up and
// the Business edition (HR-647). Leaving ACTIVE always waits for a second
// person (D512) and changes nothing until one confirms it; it needs no
// edition, so a lapsed org can still turn a signal off, and a lapse alone
// never does (HR-652).
func (s *Service) SetMode(ctx context.Context, to domain.Mode, reason string) (Result, error) {
	if !to.Valid() {
		return Result{}, ErrMode
	}
	if n := utf8.RuneCountInString(reason); n < 1 || n > 500 || !utf8.ValidString(reason) {
		return Result{}, ErrReason
	}
	c, err := s.caller(ctx, td.PermContentManage)
	if err != nil {
		return Result{}, err
	}
	if !c.Human() {
		return Result{}, ErrHuman
	}
	// Read before the transaction: the licence read is not part of it.
	var up error
	if to != domain.ModeOff {
		up = s.entitled(ctx)
	}
	var out Result
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.EnsureContentSignalSettings(ctx, c.Org); err != nil {
			return err
		}
		row, err := q.LockContentSignalSettings(ctx, c.Org)
		if err != nil {
			return err
		}
		from := domain.Mode(row.Mode)
		switch {
		case from == to:
		case from == domain.ModeActive:
			if out.Held, err = s.hold(ctx, tx, c, from, to, reason); err != nil {
				return err
			}
		case to == domain.ModeActive && from != domain.ModeWatching:
			return ErrWatchFirst
		default:
			if up != nil {
				return up
			}
			if to == domain.ModeActive {
				if _, err := rapp.FreshStepUp(ctx, q, c); err != nil {
					return err
				}
			}
			if err := write(ctx, tx, c, from, to, reason); err != nil {
				return err
			}
		}
		out.Settings, err = read(ctx, q, c.Org)
		return err
	})
	return out, err
}

// hold files the weakening. The surface is always protected, so the Gate
// never runs the apply it is given here (D512).
func (s *Service) hold(ctx context.Context, tx db.TenantTx, c tenancy.Caller, from, to domain.Mode, reason string) (*protect.PendingError, error) {
	held, err := s.Protect.Hold(ctx, tx, c, protect.Change{
		Category: protect.ToolMeaning, Surface: protect.SurfaceContentSignalMode, Subject: modeSubject.String(), SubjectID: modeSubject,
		Summary:  map[string]string{"mode_old": string(from), "mode_new": string(to), "reason": reason},
		Widening: []string{"content_signal_mode"}, Payload: modePayload{To: to, Reason: reason},
	}, func(context.Context) error { return errUnavailable })
	if err != nil {
		return nil, err
	}
	if held == nil {
		return nil, errUnavailable // leaving ACTIVE never applies at once
	}
	return held, nil
}

// write stores the mode and records it.
func write(ctx context.Context, tx db.TenantTx, c tenancy.Caller, from, to domain.Mode, reason string) error {
	by := c.Principal.String()
	q := dbq.New(tx)
	if _, err := q.SetContentSignalMode(ctx, string(to), &by, tx.OrgID()); err != nil {
		return err
	}
	// Gateways learn the mode from their configuration; the Authority reads
	// it for itself.
	if err := q.BumpOrgGateways(ctx, tx.OrgID()); err != nil {
		return err
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "content.signals.mode_changed", Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "content_signals", ID: tx.OrgID().String()},
		Details: map[string]string{"mode_old": string(from), "mode_new": string(to), "reason": reason},
	})
	return err
}

// ApplyMode is the confirmed re-run of a held change of mode (a
// protect.Applier).
func (s *Service) ApplyMode(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p modePayload
	if err := json.Unmarshal(payload, &p); err != nil || !p.To.Valid() {
		return protect.ErrInvalid
	}
	if err := author.Require(td.PermContentManage, td.OrgPath(author.Org)); err != nil {
		return err
	}
	row, err := dbq.New(tx).LockContentSignalSettings(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	return write(ctx, tx, author, domain.Mode(row.Mode), p.To, p.Reason)
}

// modeState is what a confirmed re-run must still find: the mode as filed.
func (s *Service) modeState(ctx context.Context, tx db.TenantTx, _ []byte) ([]byte, error) {
	cur, err := read(ctx, dbq.New(tx), tx.OrgID())
	if err != nil {
		return nil, err
	}
	return []byte(cur.Mode()), nil
}
