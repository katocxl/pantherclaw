// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/cases/store"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type fixture struct {
	p               *db.Pool
	org             ids.OrgID
	alice, bob      ids.UUID
	agent, run, txn ids.UUID
	author          domain.Author
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		p: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), bob: ids.NewV7(),
		agent: ids.NewV7(), run: ids.NewV7(), txn: ids.NewV7(),
	}
	f.author = domain.Author{Type: "user", ID: f.alice.String()}
	team, env := ids.NewV7(), ids.NewV7()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'cases')", []any{f.org}},
		{
			"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice'), ($1, $3, 'https://idp.test', 'bob')",
			[]any{f.org, f.alice, f.bob},
		},
		{"INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", []any{f.org, team}},
		{
			"INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')",
			[]any{f.org, env, team},
		},
		{"INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'bot', 'DISCOVERED', 'test')", []any{f.org, f.agent}},
		{`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
			VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '1 hour')`, []any{f.org, f.run, f.agent, env, f.alice}},
		{
			`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id)
			VALUES ($1, $2, $3, $4, $5, 'repo.contents.write', 'ALLOW', 'OK', 'gw')`,
			[]any{f.org, f.txn, f.run, ids.NewV7(), make([]byte, 32)},
		},
	} {
		f.exec(t, s.sql, s.args...)
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

func (f *fixture) open(t *testing.T) domain.Case {
	t.Helper()
	var c domain.Case
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		c, err = store.Open(ctx, tx, domain.NewCase{Title: "Self-issued grant", Source: "manual", OpenedBy: f.author})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) append(c ids.UUID, d domain.Draft) (domain.Entry, error) {
	var e domain.Entry
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		e, err = store.Append(ctx, tx, c, f.author, d)
		return err
	})
	return e, err
}

func (f *fixture) must(t *testing.T, c ids.UUID, d domain.Draft) domain.Entry {
	t.Helper()
	e, err := f.append(c, d)
	if err != nil {
		t.Fatalf("append %s: %v", d.Kind, err)
	}
	return e
}

func (f *fixture) get(t *testing.T, c ids.UUID) domain.Case {
	t.Helper()
	var k domain.Case
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		k, err = store.Get(ctx, tx, c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return k
}

func (f *fixture) fact() domain.Draft {
	return domain.Draft{
		Kind: domain.KindFact, Text: "The agent issued itself a grant.", Basis: domain.BasisObserved,
		Evidence: []domain.EvidenceRef{{Kind: domain.EvidenceTransaction, ID: f.txn}},
	}
}

func TestCaseEntriesChainAndRecordInLedger(t *testing.T) {
	f := newFixture(t)
	c := f.open(t)
	if c.State != domain.StateOpen || c.HeadSeq != 0 || string(c.HeadHash) != string(domain.GenesisHash(c.ID)) {
		t.Fatalf("new case = %+v", c)
	}
	fact := f.must(t, c.ID, f.fact())
	q := f.must(t, c.ID, domain.Draft{Kind: domain.KindQuestion, Text: "Was anything read first?", Owner: &f.bob})
	f.must(t, c.ID, domain.Draft{
		Kind: domain.KindHypothesis, Text: "Prompt injection.", Basis: domain.BasisHypothesis,
		Confidence: domain.ConfidenceLow, Alternatives: []string{"A misconfigured template."},
	})
	f.must(t, c.ID, domain.Draft{Kind: domain.KindAnswer, Text: "Not yet known.", Question: &q.ID, Unresolved: true})
	f.must(t, c.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "run", ID: f.run.String()}})
	if fact.Seq != 1 || q.Seq != 2 {
		t.Fatalf("seqs %d %d", fact.Seq, q.Seq)
	}
	k := f.get(t, c.ID)
	if k.HeadSeq != 5 {
		t.Fatalf("head %d", k.HeadSeq)
	}
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		if err := store.VerifyChain(ctx, tx, c.ID); err != nil {
			return err
		}
		n, err := store.OpenQuestions(ctx, tx, c.ID)
		if err != nil || n != 1 {
			t.Fatalf("open questions = %d, %v", n, err)
		}
		var body []byte
		var kind string
		if err := tx.QueryRow(ctx, "SELECT kind, body FROM pc.ledger_entries WHERE id = $1", fact.LedgerEntry).Scan(&kind, &body); err != nil {
			return err
		}
		if kind != domain.LedgerKind || string(body) != string(fact.Body) {
			t.Fatalf("ledger entry %s %s", kind, body)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCaseEntriesRefuseWhatCanNeverStand(t *testing.T) {
	f := newFixture(t)
	c := f.open(t)
	ghost := f.fact()
	ghost.Evidence = []domain.EvidenceRef{{Kind: domain.EvidenceTransaction, ID: ids.NewV7()}}
	if _, err := f.append(c.ID, ghost); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("fact with unknown evidence: %v", err)
	}
	noEvidence := f.fact()
	noEvidence.Evidence = nil
	if _, err := f.append(c.ID, noEvidence); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("fact without evidence: %v", err)
	}
	other := f.open(t)
	q := f.must(t, other.ID, domain.Draft{Kind: domain.KindQuestion, Text: "Elsewhere?"})
	if _, err := f.append(c.ID, domain.Draft{Kind: domain.KindAnswer, Text: "x", Question: &q.ID}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("answer to another case's question: %v", err)
	}
	fact := f.must(t, c.ID, f.fact())
	note := f.must(t, c.ID, domain.Draft{Kind: domain.KindNote, Text: "n"})
	if _, err := f.append(c.ID, domain.Draft{Kind: domain.KindNote, Text: "n2", Supersedes: &fact.ID}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("supersede across kinds: %v", err)
	}
	f.must(t, c.ID, domain.Draft{Kind: domain.KindNote, Text: "n2", Supersedes: &note.ID})
	if _, err := f.append(c.ID, domain.Draft{Kind: domain.KindNote, Text: "n3", Supersedes: &note.ID}); !errors.Is(err, store.ErrSuperseded) {
		t.Fatalf("supersede twice: %v", err)
	}
}

func TestCaseEntriesAreAppendOnly(t *testing.T) {
	f := newFixture(t)
	c := f.open(t)
	e := f.must(t, c.ID, f.fact())
	for _, sql := range []string{
		"UPDATE pc.case_entries SET text = 'edited' WHERE id = $1",
		"DELETE FROM pc.case_entries WHERE id = $1",
	} {
		err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, e.ID)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	for _, sql := range []string{
		"UPDATE pc.cases SET state = 'CLOSED', disposition = 'BENIGN', impact = 'NONE_FOUND' WHERE id = $1",
		"UPDATE pc.cases SET head_seq = head_seq + 1 WHERE id = $1",
		"UPDATE pc.cases SET owner_id = NULL WHERE id = $1",
	} {
		err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, c.ID)
			return err
		})
		if !db.IsCheckViolation(err) {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// An entry must be in the ledger with the same body.
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		id := ids.NewV7()
		body, err := domain.Draft{Kind: domain.KindNote, Text: "forged"}.Body(c.ID, id, 2, f.author)
		if err != nil {
			return err
		}
		le, err := ledger.Append(ctx, tx, "audit.case.forged", evdomain.Actor{Type: f.author.Type, ID: f.author.ID}, body)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO pc.case_entries (org_id, case_id, id, body, ledger_entry_id) VALUES ($1, $2, $3, $4, $5)",
			f.org, c.ID, id, body, le.ID)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Fatalf("entry without its reflex.case ledger entry: %v", err)
	}
}

func TestCaseClosureRules(t *testing.T) {
	f := newFixture(t)
	c := f.open(t)
	contain := domain.Draft{Kind: domain.KindState, State: domain.StateContained}
	if _, err := f.append(c.ID, contain); !errors.Is(err, store.ErrNotContained) {
		t.Fatalf("contain without actions or reason: %v", err)
	}
	// A linked action that is unknown is not confirmed.
	f.must(t, c.ID, domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: domain.RefResponseAction, ID: ids.NewV7().String()}})
	if _, err := f.append(c.ID, contain); !errors.Is(err, store.ErrNotContained) {
		t.Fatalf("contain with an unknown linked action: %v", err)
	}
	contain.NoContainmentNeeded, contain.Reason = true, "The grant expired before any use."
	f.must(t, c.ID, contain)
	if k := f.get(t, c.ID); k.State != domain.StateContained || k.OperationalClosed == nil {
		t.Fatalf("contained = %+v", k)
	}

	closing := domain.Draft{
		Kind: domain.KindState, State: domain.StateClosed, Disposition: domain.DispositionTruePositive,
		CaseImpact: domain.ImpactExplicitlyUnresolved,
	}
	if _, err := f.append(c.ID, closing); !errors.Is(err, store.ErrClosureRules) {
		t.Fatalf("close without a fact: %v", err)
	}
	fact := f.must(t, c.ID, f.fact())
	q := f.must(t, c.ID, domain.Draft{Kind: domain.KindQuestion, Text: "What did it read?"})
	if _, err := f.append(c.ID, closing); !errors.Is(err, store.ErrClosureRules) {
		t.Fatalf("close with an open question and no follow-up owner: %v", err)
	}
	// Superseding a fact leaves its replacement standing.
	replacement := f.fact()
	replacement.Supersedes = &fact.ID
	f.must(t, c.ID, replacement)
	f.must(t, c.ID, domain.Draft{Kind: domain.KindOwner, OwnerRole: domain.RoleFollowUp, Owner: &f.bob})
	f.must(t, c.ID, closing)
	k := f.get(t, c.ID)
	if k.State != domain.StateClosed || k.Closed == nil || k.FollowUpOwner == nil || *k.FollowUpOwner != f.bob {
		t.Fatalf("closed = %+v", k)
	}
	// The question stays open and owned; a closed case still takes its answer.
	f.must(t, c.ID, domain.Draft{Kind: domain.KindAnswer, Text: "Two files.", Question: &q.ID})
	if _, err := f.append(c.ID, domain.Draft{
		Kind: domain.KindHypothesis, Text: "h", Basis: domain.BasisHypothesis,
		Confidence: domain.ConfidenceHigh,
	}); !errors.Is(err, store.ErrTransition) {
		t.Fatalf("hypothesis on a closed case: %v", err)
	}
	if _, err := f.append(c.ID, domain.Draft{Kind: domain.KindState, State: domain.StateOpen}); !errors.Is(err, store.ErrTransition) {
		t.Fatalf("reopen a closed case: %v", err)
	}
}
