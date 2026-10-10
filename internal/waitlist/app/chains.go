// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Errors of escalation chains.
var (
	ErrChainInvalid = pcerr.New(pcerr.InvalidArgument, "ESCALATION_CHAIN_INVALID",
		"a chain has 1 to 5 steps that start at 0%, come later each time, stay below 100% and never narrow")
	ErrChainChanged = pcerr.New(pcerr.Aborted, "REVISION_CHANGED", "the chain changed; read it again")
	ErrTeamNotFound = pcerr.New(pcerr.NotFound, "TEAM_NOT_FOUND", "team not found")
)

// GetEscalationChain returns the chain in effect for a team (nil: the
// org): the team's own, else the org's, else decision 8's default
// (revision 0). It needs waitlist.read; a chain holds no subject data.
func (rd *Reader) GetEscalationChain(ctx context.Context, team *ids.UUID) (Chain, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Chain{}, err
	}
	if !c.CanAnywhere(td.PermWaitlistRead) {
		return Chain{}, td.ErrPermissionDenied(td.PermWaitlistRead)
	}
	var out Chain
	err = rd.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if team != nil {
			if _, err := q.GetTeam(ctx, c.Org, *team); db.IsNoRows(err) {
				return ErrTeamNotFound
			} else if err != nil {
				return err
			}
			if own, err := storedChain(ctx, q, c.Org, team); err != nil || own != nil {
				if own != nil {
					out = *own
				}
				return err
			}
		}
		org, err := storedChain(ctx, q, c.Org, nil)
		switch {
		case err != nil:
			return err
		case org != nil:
			out = *org
		default:
			out = Chain{Steps: wdomain.DefaultChain}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// SetEscalationChain replaces a team's (nil: the org's) chain with a new
// revision (decision 8). The caller must hold waitlist.manage at org
// scope; revision is the one being replaced (0 when none is set), and a
// stale one is refused. The change is audited.
func (w *Writer) SetEscalationChain(ctx context.Context, team *ids.UUID, steps []wdomain.Step, revision int) (Chain, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Chain{}, err
	}
	if err := c.Require(td.PermWaitlistManage, td.OrgPath(c.Org)); err != nil {
		return Chain{}, err
	}
	if err := wdomain.ValidateChain(steps); err != nil {
		return Chain{}, ErrChainInvalid
	}
	raw, err := json.Marshal(steps)
	if err != nil {
		return Chain{}, err
	}
	var out Chain
	err = w.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cur, err := storedChain(ctx, q, c.Org, team)
		if err != nil {
			return err
		}
		if (cur == nil && revision != 0) || (cur != nil && cur.Revision != revision) {
			return ErrChainChanged
		}
		if err := q.InsertChain(ctx, dbq.InsertChainParams{
			OrgID: c.Org, ID: ids.NewV7(), TeamID: team, Revision: int32(revision + 1), Steps: raw, //nolint:gosec // small
			CreatedBy: c.Principal.String(),
		}); err != nil {
			return err
		}
		details := map[string]string{"revision": strconv.Itoa(revision + 1), "steps": strconv.Itoa(len(steps))}
		object := &audit.Object{Type: "org", ID: c.Org.String()}
		if team != nil {
			object = &audit.Object{Type: "team", ID: team.String()}
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "waitlist.escalation_chain_set", Actor: c.Actor(), Outcome: audit.Success, Object: object, Details: details,
		}); err != nil {
			return err
		}
		set, err := storedChain(ctx, q, c.Org, team)
		if err == nil {
			out = *set
		}
		return err
	})
	switch {
	case db.IsUniqueViolation(err):
		return Chain{}, ErrChainChanged
	case db.IsForeignKeyViolation(err):
		return Chain{}, ErrTeamNotFound
	}
	return out, err
}
