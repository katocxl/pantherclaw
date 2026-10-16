// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Identity is an automation in the agent inventory (D15, F025, HR-274).
type Identity struct {
	Automation, ServiceAccount, Owner, EnabledVersion ids.UUID
	Name                                              string
	State                                             autodomain.State
	Rollout                                           autodomain.Rollout
	CeilingAgents, ActiveGrants                       int
	ReviewBy                                          *time.Time
}

// NoteNoPermission explains automations left out of an inventory.
const NoteNoPermission = "automations are not listed: that needs automation.read"

// Identities lists the org's automations as execution identities for the
// agent inventory. Without automation.read it returns none and a note.
func (s *Service) Identities(ctx context.Context) ([]Identity, string, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	if !c.Can(td.PermAutomationRead, td.OrgPath(c.Org)) {
		return nil, NoteNoPermission, nil
	}
	var out []Identity
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListAutomationIdentities(ctx, c.Org, 1000)
		if err != nil {
			return err
		}
		for _, r := range rows {
			x := Identity{
				Automation: r.ID, ServiceAccount: r.ServiceAccountID, Owner: r.OwnerUserID, Name: r.Name,
				State: autodomain.State(r.State), EnabledVersion: deref(r.EnabledVersionID), ActiveGrants: int(r.ActiveGrants),
				ReviewBy: r.CeilingReviewBy,
			}
			if r.Rollout != nil {
				x.Rollout = autodomain.Rollout(*r.Rollout)
			}
			if r.EnabledVersionID != nil {
				if v, err := loadVersion(ctx, q, c.Org, *r.EnabledVersionID, false); err == nil {
					if d, err := definitionOf(v); err == nil {
						x.CeilingAgents = len(d.CeilingAgents())
					}
				}
			}
			out = append(out, x)
		}
		return nil
	}, db.ReadOnly())
	return out, "", err
}
