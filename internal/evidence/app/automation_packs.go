// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// MaxAutomationPackAgents bounds the agents an automation's pack declares.
const MaxAutomationPackAgents = 50

// AutomationPack is a digest step's pack (G0 M11 part 2 D85).
type AutomationPack struct {
	Org        ids.OrgID
	Automation ids.UUID
	Execution  ids.UUID
	// ServiceAccount is the automation's execution identity, the pack's
	// creator.
	ServiceAccount ids.UUID
	// Agents are the agents the version declared; nil means all of the
	// org's. The pack never holds evidence of another agent.
	Agents []ids.UUID
	// Request is what the pack covers (time_range or transactions).
	Request PackRequest
}

// CreateForAutomationTx records an automation's pack and enqueues its
// build in the caller's transaction (D85). It checks no caller: the
// automation's step calls it as the automation, and its confirmers'
// evidence.read and evidence.export at the declared scope are revalidated
// with the ceiling before every effectful step (HR-273). It needs a Team
// licence. The pack is created by the automation's execution identity and
// built with evidence.read only, within the declared agents; RPC
// CreateEvidencePack stays human-only. The audit actor is the automation.
func (s *Service) CreateForAutomationTx(ctx context.Context, tx pgx.Tx, in AutomationPack) (ids.UUID, error) {
	if s.enqueuePack == nil || s.editions == nil {
		return ids.UUID{}, ErrPacksUnwired
	}
	ents, err := s.editions.Current(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if !ents.Edition.Paid() {
		return ids.UUID{}, ErrPacksEdition
	}
	switch in.Request.Kind {
	case pack.ScopeTimeRange, pack.ScopeTransactions:
	default:
		return ids.UUID{}, ErrBadPackScope
	}
	if in.Agents != nil && (len(in.Agents) == 0 || len(in.Agents) > MaxAutomationPackAgents) {
		return ids.UUID{}, ErrBadPackScope
	}
	sc, err := in.Request.scope()
	if err != nil {
		return ids.UUID{}, err
	}
	scopeJSON, err := pack.Canonical(sc)
	if err != nil {
		return ids.UUID{}, err
	}
	includeJSON, err := pack.Canonical(in.Request.Include)
	if err != nil {
		return ids.UUID{}, err
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, in.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	var agents []ids.UUID
	if in.Agents != nil {
		agents = slices.Clone(in.Agents)
		slices.SortFunc(agents, func(a, b ids.UUID) int { return bytes.Compare(a[:], b[:]) })
		agents = slices.Compact(agents)
	}
	id := ids.NewV7()
	auto := in.Automation
	if err := dbq.New(ttx).InsertAutomationEvidencePack(ctx, dbq.InsertAutomationEvidencePackParams{
		OrgID: in.Org, ID: id, CreatedBy: in.ServiceAccount, ScopeKind: in.Request.Kind, Scope: scopeJSON, Include: includeJSON,
		AutomationID: &auto, AutomationAgents: agents,
	}); err != nil {
		return ids.UUID{}, err
	}
	scope := "all"
	if agents != nil {
		scope = strconv.Itoa(len(agents)) + " agents"
	}
	if _, err := audit.Record(ctx, ttx, audit.Event{
		Name: "evidence.pack_created", Actor: evdomain.Actor{Type: "automation", ID: in.Automation.String()}, Outcome: audit.Success,
		Object: &audit.Object{Type: "evidence_pack", ID: id.String()},
		Details: map[string]string{
			"scope": in.Request.Kind, "include": includeList(in.Request.Include), "automation": in.Automation.String(),
			"execution": in.Execution.String(), "created_by": "service_account:" + in.ServiceAccount.String(), "agents": scope,
		},
	}); err != nil {
		return ids.UUID{}, err
	}
	if err := s.enqueuePack(ctx, ttx, in.Org, id); err != nil {
		return ids.UUID{}, err
	}
	return id, nil
}
