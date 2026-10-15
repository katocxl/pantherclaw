// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// edition is a fixed edition.
type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Edition(e)
	return x, nil
}

type fixture struct {
	d                 *dbtest.DB
	p                 *db.Pool
	org               ids.OrgID
	teamA, teamB      ids.UUID
	agentA, agentB    ids.UUID
	runA, runB        ids.UUID
	txnA, txnB        ids.UUID
	alice, bob, carol ids.UUID
	svc               *capp.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		d: d, p: d.AppPool(t), org: ids.New[ids.Org](), teamA: ids.NewV7(), teamB: ids.NewV7(),
		agentA: ids.NewV7(), agentB: ids.NewV7(), runA: ids.NewV7(), runB: ids.NewV7(), txnA: ids.NewV7(), txnB: ids.NewV7(),
		alice: ids.NewV7(), bob: ids.NewV7(), carol: ids.NewV7(),
	}
	f.svc = &capp.Service{Pool: f.p, Editions: edition(billing.Team)}
	envA, envB := ids.NewV7(), ids.NewV7()
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'cases')", f.org)
	f.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'a', 'A'), ($1, $3, 'b', 'B')", f.org, f.teamA, f.teamB)
	f.exec(t, `INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind)
		VALUES ($1, $2, $3, 'a', 'A', 'DEVELOPMENT'), ($1, $4, $5, 'b', 'B', 'DEVELOPMENT')`, f.org, envA, f.teamA, envB, f.teamB)
	for i, u := range []ids.UUID{f.alice, f.bob, f.carol} {
		f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)",
			f.org, u, []string{"alice", "bob", "carol"}[i])
	}
	for _, x := range []struct{ agent, team, env, run, txn ids.UUID }{
		{f.agentA, f.teamA, envA, f.runA, f.txnA}, {f.agentB, f.teamB, envB, f.runB, f.txnB},
	} {
		f.exec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by, team_id, environment_id, owner_user_id, execution_context, claimed_at)
			VALUES ($1, $2, $5, 'VERIFIED', 'test', $3, $4, $6, 'service', now())`, f.org, x.agent, x.team, x.env, "bot-"+x.agent.String()[30:], f.bob)
		f.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
			VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '1 hour')`, f.org, x.run, x.agent, x.env, f.bob)
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id)
			VALUES ($1, $2, $3, $4, $5, 'repo.contents.write', 'ALLOW', 'OK', 'gw')`, f.org, x.txn, x.run, ids.NewV7(), make([]byte, 32))
	}
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// as is the caller user with role at scope (the org when team is nil).
func (f *fixture) as(user ids.UUID, role td.RoleName, team *ids.UUID) context.Context {
	s := td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}
	if team != nil {
		s = td.Scope{Type: td.ScopeTeam, ID: *team}
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
			Bindings: []td.Binding{{Role: role, Scope: s}},
		},
	})
}

func subject(t reflexdomain.SubjectType, id ids.UUID) reflexdomain.Subject {
	return reflexdomain.Subject{Type: t, ID: id.String()}
}

func (f *fixture) fact(txn ids.UUID) domain.Draft {
	return domain.Draft{
		Kind: domain.KindFact, Text: "It wrote to the repository.", Basis: domain.BasisObserved,
		Evidence: []domain.EvidenceRef{{Kind: domain.EvidenceTransaction, ID: txn}},
	}
}

// TestHR247_CaseReadsApplyTheViewersScope: a case is read and changed only
// over every agent it is about (or the whole org); other cases look like
// none and are never listed or counted; lenses keep to the case; export
// needs evidence.export and is audited.
func TestHR247_CaseReadsApplyTheViewersScope(t *testing.T) {
	f := newFixture(t)
	bob := f.as(f.bob, td.RoleResponder, nil)
	alice := f.as(f.alice, td.RoleResponder, &f.teamA)
	carol := f.as(f.carol, td.RoleAuditor, nil)

	onlyA, err := f.svc.Open(bob, capp.OpenRequest{
		Title: "A only", Subjects: []reflexdomain.Subject{subject(reflexdomain.SubjectRun, f.runA)},
		Questions: []string{"What did it touch?"},
	})
	if err != nil {
		t.Fatal(err)
	}
	both, err := f.svc.Open(bob, capp.OpenRequest{Title: "A and B", Subjects: []reflexdomain.Subject{
		subject(reflexdomain.SubjectTransaction, f.txnA), subject(reflexdomain.SubjectAgent, f.agentB),
	}})
	if err != nil {
		t.Fatal(err)
	}

	p, err := f.svc.List(alice, 50, "", capp.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 1 || p.Items[0].ID != onlyA.ID {
		t.Fatalf("alice lists %+v", p.Items)
	}
	if p, err = f.svc.List(bob, 50, "", capp.Filter{}); err != nil || len(p.Items) != 2 {
		t.Fatalf("bob lists %d, %v", len(p.Items), err)
	}
	if _, err := f.svc.Get(alice, both.ID, 0, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("alice reads a case about B: %v", err)
	}
	if _, err := f.svc.GetLens(alice, capp.LensRequest{Case: both.ID, Lens: capp.LensSequence}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("alice's lens on a case about B: %v", err)
	}
	if _, err := f.svc.Append(alice, both.ID, f.fact(f.txnA)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("alice changes a case about B: %v", err)
	}
	// A person may not widen a case past what they may manage.
	if _, err := f.svc.Append(alice, onlyA.ID, domain.Draft{
		Kind: domain.KindLink,
		Ref:  &domain.Ref{Kind: "agent", ID: f.agentB.String()},
	}); !errors.Is(err, capp.ErrForbidden) {
		t.Fatalf("alice links agent B: %v", err)
	}
	if _, err := f.svc.Open(alice, capp.OpenRequest{Title: "B", Subjects: []reflexdomain.Subject{
		subject(reflexdomain.SubjectRun, f.runB),
	}}); !errors.Is(err, capp.ErrForbidden) {
		t.Fatalf("alice opens a case about B: %v", err)
	}
	// A case about no agent needs the organization.
	if _, err := f.svc.Open(alice, capp.OpenRequest{Title: "nothing"}); !errors.Is(err, capp.ErrForbidden) {
		t.Fatalf("alice opens an org-wide case: %v", err)
	}

	if _, err := f.svc.Append(alice, onlyA.ID, f.fact(f.txnA)); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.Get(alice, onlyA.ID, 0, 0)
	if err != nil || v.OpenQuestions != 1 || len(v.Entries) != 3 {
		t.Fatalf("alice's view: %+v, %v", v, err)
	}
	l, err := f.svc.GetLens(alice, capp.LensRequest{Case: onlyA.ID, Lens: capp.LensSequence})
	if err != nil || len(l.Items) != 1 || !l.ScopeLimited {
		t.Fatalf("sequence lens: %+v, %v", l, err)
	}
	sel := subject(reflexdomain.SubjectRun, f.runB)
	if _, err := f.svc.GetLens(alice, capp.LensRequest{Case: onlyA.ID, Lens: capp.LensSequence, Selection: &sel}); !errors.Is(err, capp.ErrSelection) {
		t.Fatalf("selection outside the case: %v", err)
	}
	for _, name := range []string{capp.LensReach, capp.LensResponse} {
		l, err := f.svc.GetLens(alice, capp.LensRequest{Case: onlyA.ID, Lens: name})
		if err != nil || l.Available || l.Note != capp.NoteNotAvailable {
			t.Fatalf("%s lens: %+v, %v", name, l, err)
		}
	}
	// related: bob sees the other case about A; alice does not.
	if l, err := f.svc.GetLens(bob, capp.LensRequest{Case: onlyA.ID, Lens: capp.LensRelated}); err != nil {
		t.Fatal(err)
	} else if len(l.Items) != 0 {
		// The two cases link different subjects (run A vs transaction A).
		t.Fatalf("related: %+v", l.Items)
	}

	if _, err := f.svc.Export(alice, onlyA.ID); !errors.Is(err, capp.ErrForbidden) {
		t.Fatalf("export without evidence.export: %v", err)
	}
	x, err := f.svc.Export(carol, onlyA.ID)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Format  string `json:"format"`
		Entries []struct {
			Hash string `json:"entry_hash"`
		} `json:"entries"`
		Evidence []struct{ Kind, ID string } `json:"evidence"`
	}
	if err := json.Unmarshal(x.Document, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Format != capp.ExportFormat || len(doc.Entries) != 3 || len(doc.Evidence) != 1 || doc.Entries[2].Hash == "" {
		t.Fatalf("export: %s", x.Document)
	}
	var kind string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT kind FROM pc.ledger_entries WHERE id = $1", x.AuditEntry).Scan(&kind)
	}); err != nil || kind != "audit.case.exported" {
		t.Fatalf("audit entry %q, %v", kind, err)
	}

	// Cases need Team; changes need a person.
	f.svc.Editions = edition(billing.Community)
	if _, err := f.svc.Get(bob, onlyA.ID, 0, 0); !errors.Is(err, capp.ErrEdition) {
		t.Fatalf("community: %v", err)
	}
	f.svc.Editions = edition(billing.Team)
	sa := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org:       f.org,
		Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings:  []td.Binding{{Role: td.RoleResponder, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}})
	if _, err := f.svc.Append(sa, onlyA.ID, domain.Draft{Kind: domain.KindNote, Text: "n"}); !errors.Is(err, capp.ErrHumanOnly) {
		t.Fatalf("service account: %v", err)
	}
}

// TestT107_CaseTamperingIsRefusedOrDetected: entries cannot be changed
// through the application role, and an entry changed behind the triggers'
// back breaks the chain, so the case is not exported.
func TestT107_CaseTamperingIsRefusedOrDetected(t *testing.T) {
	f := newFixture(t)
	bob := f.as(f.bob, td.RoleResponder, nil)
	carol := f.as(f.carol, td.RoleAuditor, nil)
	k, err := f.svc.Open(bob, capp.OpenRequest{Title: "t", Subjects: []reflexdomain.Subject{subject(reflexdomain.SubjectRun, f.runA)}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.svc.Append(bob, k.ID, f.fact(f.txnA))
	if err != nil {
		t.Fatal(err)
	}
	err = f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.case_entries SET body = $2 WHERE id = $1", e.ID, []byte(`{"v":1}`))
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Fatalf("app role edits an entry: %v", err)
	}
	if _, err := f.svc.Export(carol, k.ID); err != nil {
		t.Fatal(err)
	}
	// Behind the triggers (an operator with table rights): the chain breaks.
	f.d.AdminExec(t, "ALTER TABLE pc.case_entries DISABLE TRIGGER USER")
	f.d.AdminExec(t, `UPDATE pc.case_entries SET body = convert_to(replace(convert_from(body, 'UTF8'), 'repository', 'wiki'), 'UTF8')
		WHERE id = $1`, e.ID)
	f.d.AdminExec(t, "ALTER TABLE pc.case_entries ENABLE TRIGGER USER")
	if _, err := f.svc.Export(carol, k.ID); !errors.Is(err, capp.ErrChainBroken) {
		t.Fatalf("export of a tampered case: %v", err)
	}
}

// TestCaseOpenerSeedsLinksAndQuestions: the product opens a case in its own
// transaction with links and open questions and never a fact; below Team
// it opens nothing.
func TestCaseOpenerSeedsLinksAndQuestions(t *testing.T) {
	f := newFixture(t)
	alert := ids.NewV7()
	seed := reflexdomain.CaseSeed{
		Org: f.org, Title: "Self-issued grant", Source: reflexdomain.SourceDetection,
		Subjects:  []reflexdomain.Subject{subject(reflexdomain.SubjectAgent, f.agentA)},
		Evidence:  []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceTransaction, ID: f.txnA}},
		Questions: []string{"Who approved it?"}, AlertID: &alert,
		Opener: reflexdomain.Subject{Type: "rule", ID: "pc.authority.self_issue"},
	}
	var id ids.UUID
	o := &capp.Opener{Editions: edition(billing.Community)}
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := o.Open(ctx, tx.Pgx(), seed)
		return err
	})
	if !errors.Is(err, capp.ErrEdition) {
		t.Fatalf("community opener: %v", err)
	}
	o.Editions = edition(billing.Team)
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = o.Open(ctx, tx.Pgx(), seed)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.Get(f.as(f.bob, td.RoleResponder, nil), id, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[domain.Kind]int{}
	for _, e := range v.Entries {
		kinds[e.Kind]++
		if e.Author.Type != "rule" {
			t.Errorf("author %+v", e.Author)
		}
	}
	if kinds[domain.KindLink] != 3 || kinds[domain.KindQuestion] != 1 || kinds[domain.KindFact] != 0 || v.Case.Alert == nil {
		t.Fatalf("seeded %v, case %+v", kinds, v.Case)
	}
	// Another org's transaction is refused.
	err = f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		s := seed
		s.Org = ids.New[ids.Org]()
		_, err := o.Open(ctx, tx.Pgx(), s)
		return err
	})
	if !errors.Is(err, db.ErrTenantMismatch) {
		t.Fatalf("opener across orgs: %v", err)
	}
}
