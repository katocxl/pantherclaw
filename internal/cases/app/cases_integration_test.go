// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
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

	// A link given in upper case is the same subject: it widens the case's
	// read scope just as the check that allowed it saw it (D70).
	mixed, err := f.svc.Open(bob, capp.OpenRequest{Title: "A, then B", Subjects: []reflexdomain.Subject{subject(reflexdomain.SubjectRun, f.runA)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Append(bob, mixed.ID, domain.Draft{
		Kind: domain.KindLink,
		Ref:  &domain.Ref{Kind: "agent", ID: strings.ToUpper(f.agentB.String())},
	}); err != nil {
		t.Fatalf("link agent B in upper case: %v", err)
	}
	if _, err := f.svc.Get(alice, mixed.ID, 0, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("alice reads a case that links agent B in upper case: %v", err)
	}
	// Hidden cases never crowd a scoped caller's page out (D60): with newer
	// cases about B, alice's first one-item page is still her case about A.
	for range 3 {
		if _, err := f.svc.Open(bob, capp.OpenRequest{Title: "B only", Subjects: []reflexdomain.Subject{
			subject(reflexdomain.SubjectRun, f.runB),
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := f.svc.List(alice, 1, "", capp.Filter{}); err != nil || len(p.Items) != 1 || p.Items[0].ID != onlyA.ID || p.Next != "" {
		t.Fatalf("alice's first page: %+v, %v", p, err)
	}
	// A ledger entry names no agent a scope could check: only an
	// organization-wide author cites one (D62).
	var entry ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT ledger_entry_id FROM pc.case_entries WHERE case_id = $1 ORDER BY seq LIMIT 1", onlyA.ID).Scan(&entry)
	}); err != nil {
		t.Fatal(err)
	}
	ledgerFact := domain.Draft{
		Kind: domain.KindFact, Text: "Recorded.", Basis: domain.BasisObserved,
		Evidence: []domain.EvidenceRef{{Kind: domain.EvidenceLedger, ID: entry}},
	}
	if _, err := f.svc.Append(alice, onlyA.ID, ledgerFact); !errors.Is(err, capp.ErrForbidden) {
		t.Fatalf("a scoped author cites a ledger entry: %v", err)
	}
	if _, err := f.svc.Append(bob, onlyA.ID, ledgerFact); err != nil {
		t.Fatalf("an organization-wide author cites a ledger entry: %v", err)
	}
	// A fact may not cite another team's action (D62).
	if _, err := f.svc.Append(alice, onlyA.ID, f.fact(f.txnB)); !errors.Is(err, capp.ErrForbidden) {
		t.Fatalf("alice cites a transaction of agent B: %v", err)
	}
	if _, err := f.svc.Append(alice, onlyA.ID, f.fact(f.txnA)); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.Get(alice, onlyA.ID, 0, 0)
	if err != nil || v.OpenQuestions != 1 || len(v.Entries) != 4 {
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
	// related: the case that also links run A (and agent B) is related;
	// bob sees it, alice does not.
	if l, err := f.svc.GetLens(bob, capp.LensRequest{Case: onlyA.ID, Lens: capp.LensRelated}); err != nil {
		t.Fatal(err)
	} else if len(l.Items) != 1 || l.Items[0].Subjects[0].ID != mixed.ID.String() {
		t.Fatalf("related as bob: %+v", l.Items)
	}
	if l, err := f.svc.GetLens(alice, capp.LensRequest{Case: onlyA.ID, Lens: capp.LensRelated}); err != nil || len(l.Items) != 0 {
		t.Fatalf("related as alice: %+v %v", l.Items, err)
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
	if doc.Format != capp.ExportFormat || len(doc.Entries) != 4 || len(doc.Evidence) != 2 || doc.Entries[3].Hash == "" {
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
	// The seeded question is open and unowned until a person takes it on (D66).
	if v.OpenQuestions != 1 || len(v.Unowned) != 1 {
		t.Fatalf("seeded question: open %d, unowned %v", v.OpenQuestions, v.Unowned)
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

// reach is a fake exposure read port; it also answers for an agent it was
// not asked about, which the lens must drop.
type reach struct{ asked []ids.UUID }

func (r *reach) AgentReach(_ context.Context, _ ids.OrgID, agents []ids.UUID) ([]capp.ReachAgent, error) {
	r.asked = agents
	out := []capp.ReachAgent{{Agent: ids.NewV7(), Reach: reflexdomain.Reach{Resources: 99}}}
	for _, a := range agents {
		out = append(out, capp.ReachAgent{Agent: a, Reach: reflexdomain.Reach{Resources: 3, Usable: 2, Uncertain: 1}, Stale: true})
	}
	return out, nil
}

// response is a fake response read port.
// response is a fake response read port; besides an action on a subject it
// was asked about, it returns one that only names the case and scopes a
// hidden run, which the lens must drop for a scoped viewer.
type response struct {
	asked  []reflexdomain.Subject
	hidden reflexdomain.Subject
}

func (r *response) CaseActions(_ context.Context, _ ids.OrgID, _ ids.UUID, subjects []reflexdomain.Subject) ([]capp.ResponseAction, error) {
	r.asked = subjects
	return []capp.ResponseAction{{
		ID: ids.NewV7(), Scope: subjects[0], Control: reflexdomain.ControlDenyAll, Status: "PARTIAL",
		Paths: []capp.ResponsePath{{Kind: "gateway", Status: "CONFIRMED"}, {Kind: "route", Status: "UNRESOLVED"}},
	}, {ID: ids.NewV7(), Scope: r.hidden, Control: reflexdomain.ControlDenyAll, Status: "CONFIRMED"}}, nil
}

// TestHR247_ReachAndResponseLensesGoThroughPorts: the lenses ask their
// ports only about the case's subjects the viewer may read, and keep only
// rows about them.
func TestHR247_ReachAndResponseLensesGoThroughPorts(t *testing.T) {
	f := newFixture(t)
	rp, xp := &reach{}, &response{hidden: subject(reflexdomain.SubjectRun, f.runB)}
	f.svc.Reach, f.svc.Response = rp, xp
	alice := f.as(f.alice, td.RoleResponder, &f.teamA)
	k, err := f.svc.Open(alice, capp.OpenRequest{Title: "A", Subjects: []reflexdomain.Subject{subject(reflexdomain.SubjectRun, f.runA)}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := f.svc.GetLens(alice, capp.LensRequest{Case: k.ID, Lens: capp.LensReach})
	if err != nil {
		t.Fatal(err)
	}
	if len(rp.asked) != 1 || rp.asked[0] != f.agentA || len(l.Items) != 1 || !l.Available ||
		l.Items[0].Detail != "resources=3 usable=2 conditional=0 uncertain=1 stale" {
		t.Fatalf("reach asked %v, lens %+v", rp.asked, l)
	}
	l, err = f.svc.GetLens(alice, capp.LensRequest{Case: k.ID, Lens: capp.LensResponse})
	if err != nil {
		t.Fatal(err)
	}
	want := []reflexdomain.Subject{subject(reflexdomain.SubjectAgent, f.agentA), subject(reflexdomain.SubjectRun, f.runA)}
	if len(xp.asked) != 2 || xp.asked[0] != want[0] || xp.asked[1] != want[1] || len(l.Items) != 1 ||
		l.Items[0].Detail != "PARTIAL (1 of 2 paths unresolved)" {
		t.Fatalf("response asked %v, lens %+v", xp.asked, l)
	}
}
