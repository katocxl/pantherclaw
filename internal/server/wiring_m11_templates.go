// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/automations/templates/templatesrpc"
	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
)

// The M11 templates stream (G0 M11 part 2 D31–D33): the security-work
// steps, the built-in templates and the proposals automations make.
// The runner agent is pclaw's (`pclaw automation runner`), not the
// server's: the server never calls a tool (F3, HR-279).

// registerAutomationTemplates serves TemplateService and ProposalService.
// Creating from a template creates the automation, its version and its
// baseline tests in one transaction (D96, D103 T1).
func registerAutomationTemplates(rs *connect.Server, d apiDeps, core *automationsCore) {
	pantherclawv1connect.RegisterTemplateServiceHandler(rs, templateHandler(d, core))
	pantherclawv1connect.RegisterProposalServiceHandler(rs, &templatesrpc.ProposalHandler{Pool: d.pool})
}

// templateHandler creates through core's CreateDraftTx and assurance's
// test store (automationTestStore, set by the assurance wiring, D34);
// until both are set CreateFromTemplate answers UNAVAILABLE.
func templateHandler(d apiDeps, core *automationsCore) *templatesrpc.TemplateHandler {
	h := &templatesrpc.TemplateHandler{Pool: d.pool, Tests: automationTestStore(d)}
	if core != nil && core.svc != nil {
		h.Drafts = automationDrafts{svc: core.svc}
	}
	return h
}

var automationTestStore = func(apiDeps) templatesrpc.TestStore { return nil }

// automationDrafts is the Drafts port over core's CreateDraftTx.
type automationDrafts struct{ svc *autoapp.Service }

func (a automationDrafts) CreateDraftTx(ctx context.Context, tx db.TenantTx, d templatesrpc.Draft) (automation, version ids.UUID, err error) {
	auto, v, err := a.svc.CreateDraftTx(ctx, tx, autoapp.Draft{
		Name: d.Name, Purpose: d.Purpose, Kind: autodomain.WorkKind(d.Kind), Owner: d.Owner, Definition: d.Definition,
	})
	return auto.ID, v.ID, err
}

// templateSteps are the security-work step kinds (D31) the engine's
// registry merges with its generic kinds (D11). core pauses automations
// (pause_launches). The grants port (contain REVOKE_GRANT) is the
// engine's issuance wiring and resuming only what a step paused is not
// core's yet; while nil, their kinds refuse with UNSUPPORTED_CAPABILITY
// rather than pretend.
func templateSteps(d apiDeps, core *automationsCore) autoports.StepRegistry { //nolint:unused // merged by the engine wiring (D11)
	deps := securitysteps.Deps{
		Actions:  securitysteps.Actions{},
		Cases:    m10CaseOpener(d.billing),
		Failures: edgesFailures(),
		Coverage: routeCoverage{svc: &covapp.Service{Pool: d.pool, Freshness: d.freshness, Verifier: covapp.ConnectionTests{}}},
		Owners:   securitysteps.StoreOwners{},
	}
	if core != nil && core.svc != nil {
		deps.Pauser = core.svc
	}
	var notify rapp.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	deps.Container = m10Container(d.pool, d.billing, notify)
	if d.m5p2 != nil && d.m5p2.router != nil {
		deps.Approvals = securitysteps.StoreApprovals{Nudger: d.m5p2.router}
	}
	templateStepDeps(d, &deps)
	return securitysteps.All(deps)
}

// templateStepDeps fills the intake and review kinds' ties: definitions
// and scenario tests as the M11.1 gate reads them, policy drafts and
// simulations in the driver's transaction, and evidence packs enqueued
// like EvidenceService's. Fleet cohorts (COHORT_BASELINE) are govern's.
func templateStepDeps(d apiDeps, deps *securitysteps.Deps) { //nolint:unused // with templateSteps
	defs := &defspg.Store{Pool: d.pool}
	facts := &factspg.Store{Pool: d.pool}
	reads := securitysteps.NewIntakeReads(defs)
	deps.Intake = securitysteps.IntakeDeps{
		Agents: reads, Candidates: reads, Routes: reads, Operations: reads,
		Tests: securitysteps.NewScenarioTests(scenario.New(defs, facts, d.cel, policyapp.DefaultBudget)),
	}
	deps.Review = securitysteps.ReviewDeps{
		Unused: securitysteps.NewUnusedGrants(), Drafts: securitysteps.NewPolicyDrafts(facts, defs, d.cel),
		Digests: securitysteps.NewDigestCounts(),
	}
	if d.billing == nil {
		return // Community: no simulations or packs
	}
	insert, err := jobs.NewClient(d.pool, nil, jobs.Config{Logger: d.log}) // insert-only: enqueue in the step's transaction
	if err != nil {
		return // the kinds that need it refuse with UNSUPPORTED_CAPABILITY
	}
	deps.Review.Simulations = securitysteps.NewPolicySimulations(insert, d.billing)
	// Digest packs are the automation's own, within its declared agents
	// (D85).
	deps.Review.Packs = securitysteps.NewDigestPacks(evapp.New(d.pool, d.logOrigin).WithPacks(
		func(ctx context.Context, tx db.TenantTx, org ids.OrgID, pack ids.UUID) error {
			args, err := packbuild.NewBuildArgs(org, pack)
			if err != nil {
				return err
			}
			return jobs.InsertTx(ctx, insert, tx, args, nil)
		}, d.billing))
}

// routeCoverage is wait_coverage's view of coverage (D31): the trigger's
// own route, read without a viewer.
type routeCoverage struct{ svc *covapp.Service } //nolint:unused // with templateSteps

//nolint:unused // with templateSteps
func (c routeCoverage) RouteState(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, connection ids.UUID, operation string) (string, ids.UUID, error) {
	return c.svc.RouteStateForAutomationTx(ctx, tx, org, agent, connection, operation)
}
