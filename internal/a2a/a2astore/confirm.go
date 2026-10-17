// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2astore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of confirming a pin (D85).
var (
	ErrHuman = pcerr.New(pcerr.PermissionDenied, "HUMAN_REQUIRED",
		"only a person confirms an a2a pin")
	ErrNoProposal = pcerr.New(pcerr.FailedPrecondition, "A2A_PIN_NOT_PROPOSED",
		"the connection has no proposed pin, or another one replaced it")
	ErrCardChanged = pcerr.New(pcerr.FailedPrecondition, "A2A_CARD_CHANGED",
		"the agent card changed since it was proposed; propose it again")
)

// Pins are the confirm page's use cases: an a2a connection's ACTIVE pin
// and its proposal, and confirming the proposal (D85).
type Pins struct {
	Pool   *db.Pool
	Pinner *Pinner
}

// Proposal is what the page shows of a connection: its name, the pin that
// serves and the one proposed.
type Proposal struct {
	Connection ids.UUID
	Name       string
	Active     *Pin
	Proposed   *Pin
}

// Digest is a pin's card digest in hex.
func (p Pin) Digest() string { return hex.EncodeToString(p.Config.GetCardDigest()) }

// Get returns a connection's pins, for a caller who may read connections.
func (s *Pins) Get(ctx context.Context, conn ids.UUID) (Proposal, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Proposal{}, err
	}
	if err := c.Require(td.PermConnectionRead, td.OrgPath(c.Org)); err != nil {
		return Proposal{}, err
	}
	var out Proposal
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out = Proposal{Connection: conn}
		q := dbq.New(tx)
		w, err := q.GetA2AConnectionWriter(ctx, c.Org, conn)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out.Name = w.Name
		for _, st := range []string{StateActive, StateProposed} {
			p, err := Get(ctx, q, c.Org, conn, st)
			if errors.Is(err, ErrNotFound) {
				continue
			} else if err != nil {
				return err
			}
			if st == StateActive {
				out.Active = &p
			} else {
				out.Proposed = &p
			}
		}
		return nil
	})
	return out, err
}

// Confirm makes a connection's proposal, pin, its ACTIVE pin. It needs a
// person holding connection.manage with a fresh step-up of one of their
// own keys (su is nil over the API, which refuses). The card is read
// again and must still be the one proposed, so the person confirms
// exactly what the page showed; the connection's gateway then gets it.
func (s *Pins) Confirm(ctx context.Context, conn, pin ids.UUID, su *stepup.StepUp) (Pin, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Pin{}, err
	}
	if err := c.Require(td.PermConnectionManage, td.OrgPath(c.Org)); err != nil {
		return Pin{}, err
	}
	if !c.Human() {
		return Pin{}, ErrHuman
	}
	if su == nil {
		return Pin{}, stepup.ErrStepUp
	}
	var out Pin
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		w, err := q.GetA2AConnectionWriter(ctx, c.Org, conn)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		proposed, err := Get(ctx, q, c.Org, conn, StateProposed)
		if errors.Is(err, ErrNotFound) || (err == nil && proposed.ID != pin) {
			return ErrNoProposal
		} else if err != nil {
			return err
		}
		again, err := s.Pinner.Pin(ctx, proposed.Config, w.Simulated)
		if err != nil {
			return err
		}
		if !bytes.Equal(again.GetCardDigest(), proposed.Config.GetCardDigest()) {
			return ErrCardChanged
		}
		var previous string
		if p, err := Get(ctx, q, c.Org, conn, StateActive); err == nil {
			previous = p.Digest()
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		out, err = Activate(ctx, q, c.Org, conn, pin, c.Principal.ID, su.Credential)
		if errors.Is(err, ErrNotFound) {
			return ErrNoProposal
		} else if err != nil {
			return err
		}
		if _, err := q.BumpGatewayConfig(ctx, c.Org, w.GatewayID); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "connection.a2a_pin_confirmed", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "connection", ID: conn.String()},
			Details: map[string]string{
				"pin_id": pin.String(), "card_digest": out.Digest(), "previous_card_digest": previous,
				"interface_url": out.Config.GetInterface().GetUrl(), "skills": strings.Join(out.Config.GetSkills(), ","),
				"peer_agent_id": out.Config.GetPeerAgentId(), "security_key": su.Credential.String(),
			},
		})
		return err
	})
	return out, err
}
