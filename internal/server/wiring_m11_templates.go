// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
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
	wapp "github.com/katocxl/pantherclaw/internal/waitlist/app"
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
// SetTestCasesTx (D34) in one transaction; without core
// CreateFromTemplate answers UNAVAILABLE.
func templateHandler(d apiDeps, core *automationsCore) *templatesrpc.TemplateHandler {
	h := &templatesrpc.TemplateHandler{Pool: d.pool, Tests: automationTests{svc: assuranceService(d.pool, d.billing)}}
	if core != nil && core.svc != nil {
		h.Drafts = automationDrafts{svc: core.svc}
	}
	return h
}

// automationTests is the TestStore port over assurance's SetTestCasesTx.
// A template's case becomes an assurance case: trigger parameters as text,
// stubbed results with their state, effect, reason and output, and
// evidence when the template's result carries refs. Assurance cases carry
// no trigger subjects; the stubs stand for the steps that read them.
type automationTests struct{ svc *assurance.Service }

func (a automationTests) SetTestCasesTx(ctx context.Context, tx db.TenantTx, version ids.UUID, cases []templates.TestCase) (int, error) {
	ac := assuranceCases(cases)
	if _, err := a.svc.SetTestCasesTx(ctx, tx, version, ac); err != nil {
		return 0, err
	}
	return len(ac), nil
}

func assuranceCases(cases []templates.TestCase) []assurance.Case {
	out := make([]assurance.Case, 0, len(cases))
	for _, tc := range cases {
		c := assurance.Case{
			Name: tc.Name, Kind: assurance.CaseKind(tc.Kind),
			Expect: assurance.Expect{State: string(tc.Expect.State), Reason: tc.Expect.Reason},
		}
		if len(tc.Trigger.Params) > 0 {
			c.Trigger.Params = make(map[string]string, len(tc.Trigger.Params))
			for k, v := range tc.Trigger.Params {
				c.Trigger.Params[k] = v.Text()
			}
		}
		if len(tc.Expect.Steps) > 0 {
			c.Expect.Steps = make(map[string]string, len(tc.Expect.Steps))
			for k, v := range tc.Expect.Steps {
				c.Expect.Steps[k] = string(v)
			}
		}
		if len(tc.Stubs) > 0 {
			c.Stubs = make(map[string][]assurance.StubResult, len(tc.Stubs))
			for step, rs := range tc.Stubs {
				for _, r := range rs {
					c.Stubs[step] = append(c.Stubs[step], assurance.StubResult{
						State: string(r.State), Effect: string(r.Effect), Reason: r.Reason, Output: r.Output, Evidence: len(r.Refs) > 0,
					})
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// automationDrafts is the Drafts port over core's CreateDraftTx.
type automationDrafts struct{ svc *autoapp.Service }

func (a automationDrafts) CreateDraftTx(ctx context.Context, tx db.TenantTx, d templatesrpc.Draft) (automation, version ids.UUID, err error) {
	auto, v, err := a.svc.CreateDraftTx(ctx, tx, autoapp.Draft{
		Name: d.Name, Purpose: d.Purpose, Kind: autodomain.WorkKind(d.Kind), Owner: d.Owner, Definition: d.Definition,
	})
	return auto.ID, v.ID, err
}

func init() { automationSecuritySteps = securitySteps }

// securitySteps are the security-work step kinds (D31) the engine's
// registry merges with its generic kinds (D11), built from the same
// inputs in the API and the worker (D108).
func securitySteps(in securityStepDeps) autoports.StepRegistry {
	return securitysteps.All(securityPorts(in))
}

// securityPorts ties each step to its port. A step whose port could not
// be built here fails DEPENDENCY_UNAVAILABLE and never acts in part
// (D108, HR-284): contain needs its escalation's failure sink and case
// opener, remind and escalate need the approvals router, simulations and
// digest packs a licence and the job queue.
func securityPorts(in securityStepDeps) securitysteps.Deps {
	deps := securitysteps.Deps{
		Grants:   in.Steps.Grants,
		Actions:  securitysteps.Actions{},
		Cases:    m10CaseOpener(in.Bill),
		Failures: edgesFailures(),
		Coverage: routeCoverage{svc: &covapp.Service{Pool: in.Pool, Freshness: in.Freshness, Verifier: covapp.ConnectionTests{}}},
		Owners:   securitysteps.StoreOwners{},
	}
	if in.Core != nil && in.Core.svc != nil {
		deps.Pauser, deps.Resumer = in.Core.svc, in.Core.svc
	}
	var notify rapp.Notifier
	if in.Notify != nil {
		notify = in.Notify
		deps.Approvals = securitysteps.StoreApprovals{Nudger: &wapp.Router{Pool: in.Pool, Notify: in.Notify}}
	}
	deps.Container = m10Container(in.Pool, in.Bill, notify)

	defs := &defspg.Store{Pool: in.Pool}
	facts := &factspg.Store{Pool: in.Pool}
	reads := securitysteps.NewIntakeReads(defs)
	deps.Intake = securitysteps.IntakeDeps{
		Agents: reads, Candidates: reads, Routes: reads, Operations: reads,
		Tests:     securitysteps.NewScenarioTests(scenario.New(defs, facts, in.CEL, policyapp.DefaultBudget)),
		Proposals: securitysteps.TableProposals{},
	}
	deps.Review = securitysteps.ReviewDeps{
		Unused: securitysteps.NewUnusedGrants(), Drafts: securitysteps.NewPolicyDrafts(facts, defs, in.CEL),
		Digests: securitysteps.NewDigestCounts(), Proposals: securitysteps.TableProposals{},
	}
	if in.Bill == nil {
		return deps // Community: no simulations or packs
	}
	insert, err := jobs.NewClient(in.Pool, nil, jobs.Config{Logger: in.Log}) // insert-only: enqueue in the step's transaction
	if err != nil {
		// A licensed server without its job queue is misconfigured: it does
		// not start (D115 R3), as the engine does not start without its
		// guard environment.
		panic(fmt.Errorf("automation security steps: job client: %w", err))
	}
	deps.Review.Simulations = securitysteps.NewPolicySimulations(insert, in.Bill)
	// Digest packs are the automation's own, within its declared agents
	// (D85).
	deps.Review.Packs = securitysteps.NewDigestPacks(evapp.New(in.Pool, in.LogOrigin).WithPacks(
		func(ctx context.Context, tx db.TenantTx, org ids.OrgID, pack ids.UUID) error {
			args, err := packbuild.NewBuildArgs(org, pack)
			if err != nil {
				return err
			}
			return jobs.InsertTx(ctx, insert, tx, args, nil)
		}, in.Bill))
	return deps
}

// routeCoverage is wait_coverage's view of coverage (D31): the trigger's
// own route, read without a viewer.
type routeCoverage struct{ svc *covapp.Service }

func (c routeCoverage) RouteState(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, connection ids.UUID, operation string) (string, ids.UUID, error) {
	return c.svc.RouteStateForAutomationTx(ctx, tx, org, agent, connection, operation)
}
