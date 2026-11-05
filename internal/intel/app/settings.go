// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Changing the settings (G0 M38 D1104a; HR-820). Only a person holding
// intel.manage changes them. A tightening of the consume mode (OFF to
// ALERT_ONLY or HOLD, ALERT_ONLY to HOLD) applies at once; a loosening
// (HOLD to ALERT_ONLY, either to OFF) is filed with the protect Gate and
// waits for a second person, whatever the TOOL_MEANING mode. The share
// switch applies at once either way.

// ErrManageHuman refuses a settings change by anything but a person.
var ErrManageHuman = pcerr.New(pcerr.PermissionDenied, "INTEL_HUMAN_ONLY", "only a person may change the intel settings")

// errGateUnavailable: a loosening could not be filed.
var errGateUnavailable = protect.ErrUnavailable

// consumeSubject is the subject of the consume mode's changes.
var consumeSubject = protect.SubjectID(protect.SurfaceIntelConsume, "intel_consume")

// strength orders the consume modes from loosest to tightest.
func strength(m domain.Mode) int {
	switch m {
	case domain.ModeHold:
		return 2
	case domain.ModeAlertOnly:
		return 1
	}
	return 0
}

// Loosens reports whether going from one mode to another loosens matching.
func Loosens(from, to domain.Mode) bool { return strength(to) < strength(from) }

// SetResult is what Set did.
type SetResult struct {
	// Settings are the settings as they now stand: a filed loosening has
	// not changed the consume mode.
	Settings Settings
	// Held is the filed loosening, or nil.
	Held *protect.PendingError
}

// consumePayload is a held loosening.
type consumePayload struct {
	To domain.Mode `json:"to"`
}

// RegisterProtect sets the Gate's applier for the consume mode.
func (s *Service) RegisterProtect(g *protect.Gate) {
	s.Protect = g
	if g != nil {
		g.Register(protect.SurfaceIntelConsume, s.ApplyConsume, s.consumeState)
	}
}

// Set changes the consume mode and the share switch. A tightening into a
// consuming mode needs the Business edition or above; a loosening needs no
// edition, so a lapsed org can still stop consuming. The org's gateways get
// a new configuration when the mode changes. Audited.
func (s *Service) Set(ctx context.Context, consume domain.Mode, share bool) (SetResult, error) {
	if !consume.Valid() {
		return SetResult{}, ErrMode
	}
	c, err := caller(ctx, td.PermIntelManage)
	if err != nil {
		return SetResult{}, err
	}
	if !c.Human() {
		return SetResult{}, ErrManageHuman
	}
	// Read before the transaction: the licence read is not part of it.
	var up error
	if consume.Consumes() {
		ok, err := s.consumeAvailable(ctx)
		switch {
		case err != nil:
			up = err
		case !ok:
			up = ErrEdition
		}
	}
	var out SetResult
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.EnsureIntelSettings(ctx, c.Org, by(c)); err != nil {
			return err
		}
		row, err := q.LockIntelSettings(ctx, c.Org)
		if err != nil {
			return err
		}
		from := Settings{Consume: domain.Mode(row.Consume), Share: row.Share}
		to := consume
		switch {
		case Loosens(from.Consume, consume):
			if out.Held, err = s.hold(ctx, tx, c, from.Consume, consume); err != nil {
				return err
			}
			to = from.Consume // unchanged until a second person confirms
		case from.Consume != consume && up != nil:
			return up
		}
		if to != from.Consume || share != from.Share {
			if err := write(ctx, tx, c, from, Settings{Consume: to, Share: share}); err != nil {
				return err
			}
		}
		out.Settings, err = ReadSettings(ctx, q, c.Org)
		return err
	})
	return out, err
}

func by(c tenancy.Caller) string { return c.Actor().Type + ":" + c.Actor().ID }

// hold files a loosening. The surface is always protected, so the Gate
// never runs the apply it is given here.
func (s *Service) hold(ctx context.Context, tx db.TenantTx, c tenancy.Caller, from, to domain.Mode) (*protect.PendingError, error) {
	held, err := s.Protect.Hold(ctx, tx, c, protect.Change{
		Category: protect.ToolMeaning, Surface: protect.SurfaceIntelConsume, Subject: consumeSubject.String(), SubjectID: consumeSubject,
		Summary:  map[string]string{"consume_old": string(from), "consume_new": string(to)},
		Widening: []string{"intel_consume"}, Payload: consumePayload{To: to},
	}, func(context.Context) error { return errGateUnavailable })
	if err != nil {
		return nil, err
	}
	if held == nil {
		return nil, errGateUnavailable // a loosening never applies at once
	}
	return held, nil
}

// write stores the settings and records the change.
func write(ctx context.Context, tx db.TenantTx, c tenancy.Caller, from, to Settings) error {
	q := dbq.New(tx)
	if _, err := q.UpsertIntelSettings(ctx, dbq.UpsertIntelSettingsParams{
		OrgID: tx.OrgID(), Consume: string(to.Consume), Share: to.Share, UpdatedBy: by(c),
	}); err != nil {
		return err
	}
	// Gateways learn the mode from their configuration, so their content
	// scan starts or stops matching.
	if from.Consume != to.Consume {
		if err := q.BumpOrgGateways(ctx, tx.OrgID()); err != nil {
			return err
		}
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: auditkind.IntelSettingsChanged, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "intel_settings", ID: tx.OrgID().String()},
		Details: map[string]string{
			"from_consume": string(from.Consume), "to_consume": string(to.Consume),
			"from_share": strconv.FormatBool(from.Share), "to_share": strconv.FormatBool(to.Share),
		},
	})
	return err
}

// ApplyConsume is the confirmed re-run of a held loosening (a
// protect.Applier). The share switch is left as it stands.
func (s *Service) ApplyConsume(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p consumePayload
	if err := json.Unmarshal(payload, &p); err != nil || !p.To.Valid() {
		return protect.ErrInvalid
	}
	if err := author.Require(td.PermIntelManage, td.OrgPath(author.Org)); err != nil {
		return err
	}
	q := dbq.New(tx)
	if err := q.EnsureIntelSettings(ctx, tx.OrgID(), by(author)); err != nil {
		return err
	}
	row, err := q.LockIntelSettings(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	from := Settings{Consume: domain.Mode(row.Consume), Share: row.Share}
	return write(ctx, tx, author, from, Settings{Consume: p.To, Share: row.Share})
}

// consumeState is what a confirmed re-run must still find: the mode as filed.
func (s *Service) consumeState(ctx context.Context, tx db.TenantTx, _ []byte) ([]byte, error) {
	cur, err := ReadSettings(ctx, dbq.New(tx), tx.OrgID())
	if err != nil {
		return nil, err
	}
	return []byte(cur.Consume), nil
}
