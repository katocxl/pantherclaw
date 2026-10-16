// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Automation exposure (G0 M11 D37a): an automation's execution reach (the
// effective rights of grants it issued) is Team, like the rest of breach
// radius; its issuance ceiling is Business. Both need automation.read
// besides exposure.read; without it automation ids are left off rights and
// automations are never listed.

// ErrCeilingEdition refuses the issuance-ceiling view below Business.
var ErrCeilingEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"the issuance-ceiling view needs the Business edition or above")

// Notes on automations a read left out.
const (
	NoteAutomationPermission = "automations are left out: they need automation.read"
	NoteCeilingEdition       = "automations are not ranked by their issuance ceiling: that needs the Business edition"
)

// CeilingEntitled reports whether the edition offers the issuance-ceiling
// view; without entitlements wired the answer is no (fail closed).
func CeilingEntitled(ctx context.Context, e Entitlements) (bool, error) {
	if e == nil {
		return false, nil
	}
	ent, err := e.Current(ctx)
	if err != nil {
		return false, err
	}
	return ent.AutomationLatentExposure(), nil
}

// automationRead reports whether the caller holds automation.read anywhere.
func (r *reader) automationRead() bool { return r.c.CanAnywhere(td.PermAutomationRead) }

// automationFilter checks what a filter asks of automations: an automation
// or the ceiling view needs automation.read, the ceiling view Business.
func (r *reader) automationFilter(ctx context.Context, ents Entitlements, f domain.Filter) error {
	ceiling := f.View.Potential() || f.WithCeiling
	if (f.Automation != nil || ceiling) && !r.automationRead() {
		return td.ErrPermissionDenied(td.PermAutomationRead)
	}
	if ceiling {
		ok, err := CeilingEntitled(ctx, ents)
		if err != nil {
			return err
		}
		if !ok {
			return ErrCeilingEdition
		}
	}
	return nil
}

// RankedAutomations is the automation half of a ranking.
type RankedAutomations struct {
	Automations []domain.RankedAutomation
	// ByCeiling is false below Business: the list then carries execution
	// reach only, in automation order.
	ByCeiling bool
	Note      string
}

// rankAutomations ranks the automations behind the visible rights, by
// their ceiling where the edition offers it (F754: never by activity).
func (r *reader) rankAutomations(ctx context.Context, ents Entitlements, rights []domain.Right, limit int) (RankedAutomations, error) {
	if !r.automationRead() {
		return RankedAutomations{Note: NoteAutomationPermission}, nil
	}
	ceiling, err := CeilingEntitled(ctx, ents)
	if err != nil {
		return RankedAutomations{}, err
	}
	in := rights
	out := RankedAutomations{ByCeiling: ceiling}
	if !ceiling {
		in = domain.HeldReach(rights)
		out.Note = NoteCeilingEdition
	}
	issued, err := r.issued(ctx)
	if err != nil {
		return RankedAutomations{}, err
	}
	now, err := r.q.DBNow(ctx)
	if err != nil {
		return RankedAutomations{}, err
	}
	out.Automations = domain.RankAutomations(in, issued, now)
	if limit > 0 && len(out.Automations) > limit {
		out.Automations = out.Automations[:limit]
	}
	return out, nil
}

// issued lists the active automation-issued grants of agents the caller
// may see (D73 A6: nothing outside the viewer's scope reaches a count).
func (r *reader) issued(ctx context.Context) ([]domain.IssuedGrant, error) {
	rows, err := r.q.ExposureIssuedGrants(ctx, r.c.Org)
	if err != nil {
		return nil, err
	}
	out := make([]domain.IssuedGrant, 0, len(rows))
	for _, g := range rows {
		ok, err := r.view.Agent(ctx, g.AgentID)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, domain.IssuedGrant{Automation: g.AutomationID, Grant: g.ID, Agent: g.AgentID, ExpiresAt: g.ExpiresAt})
		}
	}
	return out, nil
}
