// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package securitysteps

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// propFixture is an org with an automation whose executions propose.
type propFixture struct {
	f *triggerstest.Fixture
	a triggerstest.Automation
}

func newPropFixture(t *testing.T) *propFixture {
	t.Helper()
	f := triggerstest.New(t)
	a := f.Automation(t, triggerstest.Slug(t), f.Definition(triggerstest.Slug(t), `"manual":{}`, ""), autodomain.RolloutFull)
	return &propFixture{f: f, a: a}
}

// execution inserts an execution of the automation (and its trigger) and
// returns the context of its step.
func (p *propFixture) execution(t *testing.T, step string) autodomain.StepContext {
	t.Helper()
	trig, exec := ids.NewV7(), ids.NewV7()
	p.f.Exec(t, `INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref, authenticity,
		root_trigger_id, state, occurred_at) VALUES ($1, $2, $3, $4, 'MANUAL', 'SHADOW', 'test', 'USER_SESSION', $2, 'SHADOW', now())`,
		p.f.Org, trig, p.a.ID, p.a.Version)
	p.f.Exec(t, `INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode, service_account_id,
		principal_sa_id, trigger_kind, occurred_at, root_trigger_id, deadline_at)
		VALUES ($1, $2, $3, $4, $5, 'SHADOW', $6, $6, 'MANUAL', now(), $5, now() + interval '1 hour')`,
		p.f.Org, exec, p.a.ID, p.a.Version, trig, p.a.ServiceAccount)
	return autodomain.StepContext{
		Org: p.f.Org, Spec: autodomain.StepSpec{ID: step},
		Execution: autodomain.ExecutionView{ID: exec, Automation: p.a.ID, Owner: p.f.User, ServiceAccount: p.a.ServiceAccount},
		Now:       time.Now(),
	}
}

func (p *propFixture) propose(t *testing.T, sc autodomain.StepContext, kind, about string, subject ids.UUID, body any) ids.UUID {
	t.Helper()
	var id ids.UUID
	p.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = propose(ctx, tx.Pgx(), sc, kind, about, subject, body)
		return err
	})
	return id
}

func (p *propFixture) proposal(t *testing.T, id ids.UUID) dbq.PcAutomationProposal {
	t.Helper()
	var row dbq.PcAutomationProposal
	p.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).GetAutomationProposal(ctx, p.f.Org, id)
		return err
	})
	return row
}

// TestPropose_OncePerExecutionStepAndSubject: a repeat of the step finds
// the first proposal; its body never changes.
func TestPropose_OncePerExecutionStepAndSubject(t *testing.T) {
	p := newPropFixture(t)
	sc := p.execution(t, "owner")
	agent := ids.NewV7()
	first := p.propose(t, sc, ProposalOwner, ProposalAboutAgent, agent, map[string]string{"n": "1"})
	again := p.propose(t, sc, ProposalOwner, ProposalAboutAgent, agent, map[string]string{"n": "2"})
	if first != again {
		t.Fatalf("a repeat proposed again: %s, %s", first, again)
	}
	if n := p.f.Count(t, "SELECT count(*) FROM pc.automation_proposals WHERE org_id = $1"); n != 1 {
		t.Fatalf("proposals: %d", n)
	}
	if row := p.proposal(t, first); !strings.Contains(string(row.Body), `"1"`) || row.State != "PROPOSED" {
		t.Fatalf("row: %+v %s", row, row.Body)
	}
	// Another subject of the same step is another proposal.
	if other := p.propose(t, sc, ProposalOwner, ProposalAboutAgent, ids.NewV7(), map[string]string{}); other == first {
		t.Fatal("another subject reused the proposal")
	}
	// A body over 16 KiB (as jsonb renders it) is refused before the insert.
	big := map[string]string{"x": strings.Repeat("a", MaxProposalBody)}
	bigSC := p.execution(t, "big")
	if err := p.f.Pool.InTenantTx(context.Background(), p.f.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := propose(ctx, tx.Pgx(), bigSC, ProposalOwner, ProposalAboutAgent, agent, big)
		return err
	}); !errors.Is(err, ErrProposalBody) {
		t.Fatalf("big body: %v", err)
	}
}

// TestPropose_SupersedesOlderOpenProposals: a newer proposal of the same
// kind about the same subject supersedes the open one; other kinds and
// subjects stay open.
func TestPropose_SupersedesOlderOpenProposals(t *testing.T) {
	p := newPropFixture(t)
	agent, other := ids.NewV7(), ids.NewV7()
	e1 := p.execution(t, "owner")
	old := p.propose(t, e1, ProposalOwner, ProposalAboutAgent, agent, map[string]string{})
	base := p.propose(t, autodomain.StepContext{Org: e1.Org, Execution: e1.Execution, Spec: autodomain.StepSpec{ID: "baseline"}},
		ProposalBaseline, ProposalAboutAgent, agent, map[string]string{})
	elsewhere := p.propose(t, e1, ProposalOwner, ProposalAboutAgent, other, map[string]string{})
	e2 := p.execution(t, "owner")
	latest := p.propose(t, e2, ProposalOwner, ProposalAboutAgent, agent, map[string]string{})
	if r := p.proposal(t, old); r.State != "SUPERSEDED" || r.DecidedAt == nil || r.DecidedBy != nil {
		t.Fatalf("older proposal: %+v", r)
	}
	for _, id := range []ids.UUID{latest, base, elsewhere} {
		if r := p.proposal(t, id); r.State != "PROPOSED" {
			t.Fatalf("proposal %s: %s", id, r.State)
		}
	}
}

// TestHR286_ProposalDecisionIsFinalAndBodyFixed: a person's decision only
// records it, once; the database refuses a second decision, a changed body
// and a proposal inserted already decided.
func TestHR286_ProposalDecisionIsFinalAndBodyFixed(t *testing.T) {
	p := newPropFixture(t)
	sc := p.execution(t, "owner")
	id := p.propose(t, sc, ProposalOwner, ProposalAboutAgent, ids.NewV7(), map[string]string{"a": "b"})
	open := p.propose(t, sc, ProposalOwner, ProposalAboutAgent, ids.NewV7(), map[string]string{"a": "b"})
	ctx := context.Background()
	decide := func(state string) error {
		return p.f.Pool.InTenantTx(ctx, p.f.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).DecideAutomationProposal(ctx, dbq.DecideAutomationProposalParams{
				State: state, DecidedBy: &p.f.User, OrgID: p.f.Org, ID: id,
			})
			return err
		})
	}
	if err := decide("ACCEPTED"); err != nil {
		t.Fatal(err)
	}
	if err := decide("DECLINED"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second decision: %v", err)
	}
	exec := func(sql string, args ...any) error {
		return p.f.Pool.InTenantTx(ctx, p.f.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, append([]any{p.f.Org}, args...)...)
			return err
		})
	}
	if err := exec("UPDATE pc.automation_proposals SET state = 'DECLINED', decided_at = now() WHERE org_id = $1 AND id = $2", id); err == nil {
		t.Fatal("a decided proposal was decided again")
	}
	if err := exec(`UPDATE pc.automation_proposals SET body = '{"a":"c"}' WHERE org_id = $1 AND id = $2`, open); err == nil {
		t.Fatal("a proposal's body changed")
	}
	if err := exec(`INSERT INTO pc.automation_proposals (org_id, id, execution_id, step_id, kind, subject_type, subject_id, body, state,
		decided_by, decided_at) VALUES ($1, $2, $3, 'x', 'OWNER', 'agent', $2, '{}', 'ACCEPTED', $4, now())`,
		ids.NewV7(), sc.Execution.ID, p.f.User); err == nil {
		t.Fatal("a proposal was inserted decided")
	}
	if r := p.proposal(t, id); r.State != "ACCEPTED" || r.DecidedBy == nil || *r.DecidedBy != p.f.User {
		t.Fatalf("decided: %+v", r)
	}
}

// emptyFacts and noDefinitions are an org with no facts or packages.
type emptyFacts struct{}

func (emptyFacts) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return map[string]fdomain.Type{}, nil
}

type noDefinitions struct{}

func (noDefinitions) ActiveDefinitionsInTx(context.Context, db.TenantTx, ids.OrgID) ([]*defs.Definition, error) {
	return nil, nil
}

// TestHR286_PolicyDraftStaysADraft: the draft store writes a DRAFT
// version authored by the automation, audited, and nothing is published.
func TestHR286_PolicyDraftStaysADraft(t *testing.T) {
	p := newPropFixture(t)
	store := NewPolicyDrafts(emptyFacts{}, noDefinitions{}, celenv.Limits{MaxExpressionBytes: 2048, MaxCost: 5000, MaxComprehensionNesting: 1, EstimatedCollectionSize: 256})
	agent := ids.NewV7()
	b := RestrictionDraft(nil, map[ids.UUID][]string{agent: {"repo.*"}}, 30)
	author := evdomain.Actor{Type: "automation", ID: p.a.ID.String()}
	var id ids.UUID
	var n int
	p.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		pub, _, err := store.Published(ctx, tx.Pgx(), p.f.Org)
		if err != nil || pub != nil {
			t.Fatalf("published before: %v, %v", pub, err)
		}
		id, n, err = store.CreateDraft(ctx, tx.Pgx(), p.f.Org, b, author)
		return err
	})
	if n != 1 {
		t.Fatalf("version %d", n)
	}
	p.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		v, err := dbq.New(tx).GetPolicyVersion(ctx, p.f.Org, id)
		if err != nil {
			return err
		}
		if v.State != "DRAFT" || v.PublishedAt != nil || v.CreatedBy != "automation:"+p.a.ID.String() || v.BundleID != DraftBundleID {
			t.Fatalf("version: %+v", v)
		}
		if _, err := dbq.New(tx).GetPublishedPolicy(ctx, p.f.Org); !db.IsNoRows(err) {
			t.Fatalf("published after: %v", err)
		}
		return nil
	})
	if c := p.f.Count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.policy.version_created'"); c != 1 {
		t.Fatalf("audit events: %d", c)
	}
	// A bundle that does not validate is refused with a stable reason.
	bad := *b
	bad.Rules = []pdomain.Rule{{ID: "BAD", Kind: pdomain.Forbid}}
	err := p.f.Pool.InTenantTx(context.Background(), p.f.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, _, err := store.CreateDraft(ctx, tx.Pgx(), p.f.Org, &bad, author)
		return err
	})
	if r, ok := refusal(err); !ok || r != "POLICY_INVALID" {
		t.Fatalf("invalid draft: %v", err)
	}
}

// TestReview_PacksAndCountsReadTheDatabase: the digest counts run on every
// section for all agents and for declared ones, and the unused-grant and
// intake reads run.
func TestReview_PacksAndCountsReadTheDatabase(t *testing.T) {
	p := newPropFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	p.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		for _, agents := range [][]ids.UUID{nil, {ids.NewV7(), ids.NewV7()}} {
			for _, sec := range digestSections {
				if _, err := (DigestCounts{}).Counts(ctx, tx.Pgx(), p.f.Org, sec, now.Add(-time.Hour), now, agents); err != nil {
					t.Fatalf("section %s (%v): %v", sec, agents, err)
				}
			}
		}
		unused, err := NewUnusedGrants().Unused(ctx, tx.Pgx(), p.f.Org, now.Add(-7*24*time.Hour), 10)
		if err != nil || len(unused) != 0 {
			t.Fatalf("unused: %v, %v", unused, err)
		}
		return nil
	})

	// The intake reads of a discovered agent.
	agent := ids.NewV7()
	reads := NewIntakeReads(noDefinitions{})
	p.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := dbq.New(tx).InsertDiscoveredAgent(ctx, dbq.InsertDiscoveredAgentParams{
			OrgID: p.f.Org, ID: agent, Name: "found", CreatedBy: "user:" + p.f.User.String(),
		}); err != nil {
			return err
		}
		a, err := reads.Agent(ctx, tx.Pgx(), p.f.Org, agent)
		if err != nil || a.Claimed() || a.State != "DISCOVERED" {
			t.Fatalf("agent: %+v, %v", a, err)
		}
		if _, err := reads.Agent(ctx, tx.Pgx(), p.f.Org, ids.NewV7()); !errors.Is(err, ErrTriggerAgentNotFound) {
			t.Fatalf("unknown agent: %v", err)
		}
		cands, disc, err := reads.Candidates(ctx, tx.Pgx(), p.f.Org, agent)
		if err != nil || disc != nil || len(cands) != 1 || cands[0].User != p.f.User || cands[0].Why[0] != WhyDiscovered {
			t.Fatalf("candidates: %+v, %+v, %v", cands, disc, err)
		}
		sum, err := reads.Summary(ctx, tx.Pgx(), p.f.Org, agent)
		if err != nil || sum.Routes != 0 || sum.Scopes != 0 {
			t.Fatalf("summary: %+v, %v", sum, err)
		}
		ops, err := reads.ReadOperations(ctx, tx.Pgx(), p.f.Org, agent)
		if err != nil || len(ops) != 0 {
			t.Fatalf("operations: %v, %v", ops, err)
		}
		return nil
	})
}

// TestHR286_DigestPackIsTheAutomations: a build_digest step's pack is
// created by the automation's service account for the automation, within
// the declared agents, and audited with the automation as actor; a
// person's pack is unchanged (created by the person, no automation) (D85).
func TestHR286_DigestPackIsTheAutomations(t *testing.T) {
	p := newPropFixture(t)
	var enqueued []ids.UUID
	svc := evapp.New(p.f.Pool, "https://log.test").WithPacks(func(_ context.Context, _ db.TenantTx, _ ids.OrgID, id ids.UUID) error {
		enqueued = append(enqueued, id)
		return nil
	}, triggerstest.Team)
	agents := []ids.UUID{ids.NewV7(), ids.NewV7()}
	reg := reviewSteps(Deps{Review: ReviewDeps{Digests: NewDigestCounts(), Packs: NewDigestPacks(svc)}})
	step := reg[autodomain.KindBuildDigest].(*buildDigest)
	step.scope = func(*autodomain.BuildDigestWith) ([]ids.UUID, bool, bool) { return agents, false, true }
	sc := p.execution(t, "digest")
	sc.Def = &autodomain.Definition{Authority: autodomain.Authority{Platform: []autodomain.PlatformScope{
		{Step: autodomain.KindBuildDigest, Scopes: []string{autodomain.ScopeTimeRange}},
	}}}
	sc.With = &autodomain.BuildDigestWith{Scope: autodomain.ScopeTimeRange, Days: 7, Sections: digestSections}
	var r autodomain.StepResult
	p.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		r, err = step.Run(ctx, tx.Pgx(), sc)
		return err
	})
	if r.State != autodomain.StepDone || r.Output[OutPack] == "" || r.Output[OutPack] == OutPackNone {
		t.Fatalf("digest: %+v", r)
	}
	pack, _ := ids.ParseUUID(r.Output[OutPack])
	if len(enqueued) != 1 || enqueued[0] != pack {
		t.Fatalf("enqueued %v, pack %s", enqueued, pack)
	}
	if n := p.f.Count(t, `SELECT count(*) FROM pc.evidence_packs WHERE org_id = $1 AND id = $2 AND created_by = $3 AND automation_id = $4
		AND automation_agents @> $5::uuid[] AND cardinality(automation_agents) = 2 AND state = 'BUILDING' AND scope_kind = 'time_range'`,
		pack, p.a.ServiceAccount, p.a.ID, agents); n != 1 {
		t.Fatal("the automation's pack is not recorded as the automation's")
	}
	if n := p.f.Count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.pack_created' AND actor_type = 'automation' AND actor_id = $2",
		p.a.ID.String()); n != 1 {
		t.Fatalf("audit events: %d", n)
	}

	// A person's pack: created by the person, no automation.
	from, to := time.Now().Add(-time.Hour), time.Now()
	mine, err := svc.CreateEvidencePack(p.f.As(td.KindUser, td.RoleAuditor), evapp.PackRequest{Kind: "time_range", From: &from, To: &to})
	if err != nil {
		t.Fatal(err)
	}
	if n := p.f.Count(t, "SELECT count(*) FROM pc.evidence_packs WHERE org_id = $1 AND id = $2 AND created_by = $3 AND automation_id IS NULL AND automation_agents IS NULL",
		mine.ID, p.f.User); n != 1 {
		t.Fatal("a person's pack changed")
	}
}
