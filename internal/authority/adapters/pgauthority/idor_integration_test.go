// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// idrWorldOn builds a second org on a's database the way newWorld builds
// the first: the mock-payments package imported and active, the fact
// provider, an agent with an admitted instance, a gateway and its
// enforce-mode connection. It shares a's Authority and services, which act
// in the request's or the caller's org.
func idrWorldOn(a *world) *world {
	t := a.t
	t.Helper()
	ctx := context.Background()
	p := a.pool
	w := &world{
		t: t, db: a.db, pool: p, org: ids.New[ids.Org](), alice: ids.NewV7(), billing: ids.NewV7(), agent: ids.NewV7(),
		instance: ids.NewV7(), env: ids.NewV7(), grants: a.grants, facts: a.facts, mapper: a.mapper, auth: a.auth,
	}
	team := ids.NewV7()
	exec(t, p, w.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'globex')", w.org)
	if err := p.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error { return dbq.New(tx).InsertContainment(ctx, w.org) }); err != nil {
		t.Fatal(err)
	}
	exec(t, p, w.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", w.org, team)
	exec(t, p, w.org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')", w.org, w.env, team)
	exec(t, p, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.alice)
	exec(t, p, w.org, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'test')", w.org, w.billing)
	exec(t, p, w.org, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'refund-bot', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, w.org, w.agent, team, w.env, w.alice)
	exec(t, p, w.org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, w.instance, w.agent, fmt.Sprintf("%043d", time.Now().UnixNano()%1e12))
	w.human = tapp.WithCaller(ctx, tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: w.alice}}})

	raw, err := os.ReadFile("../../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := jws.NewSigner(kid, priv)
	sum := sha256.Sum256(raw)
	doc, err := trust.Sign(trust.Targets{Version: 1, Expires: "2027-04-08T00:00:00Z", Targets: map[string]trust.Target{
		trust.Key("pc.mock-payments", "1.0.0"): {Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
	}}, signer)
	if err != nil {
		t.Fatal(err)
	}
	im := &defapp.Importer{Roots: trust.Roots{kid: signer.Public()}, Repo: &defpg.Store{Pool: p}, Clock: clock.NewFake(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))}
	if _, err := im.Import(ctx, w.org, "pc.mock-payments", "1.0.0", doc, raw, nil); err != nil {
		t.Fatal(err)
	}
	if err := im.Transition(ctx, w.org, "pc.mock-payments", "1.0.0", defdomain.StateActive, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.facts.RegisterProvider(w.human, "billing.system", w.billing, []fdomain.Declaration{
		{Name: "payments.charge.refundable", Type: fdomain.TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
	}); err != nil {
		t.Fatal(err)
	}
	gw := ids.NewV7()
	exec(t, p, w.org, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, gw)
	w.gw, w.gwID = finalize.Gateway{ID: gw.String(), Org: w.org}, gw
	w.conn = w.withConnection("enforce")
	return w
}

// idrPerson is a person of w's org holding, at org scope, every role that
// reads evidence or reconciles.
func idrPerson(w *world) context.Context {
	id := ids.NewV7()
	exec(w.t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'idr')", w.org, id)
	var bs []tdomain.Binding
	for _, r := range []tdomain.RoleName{tdomain.RoleReconciler, tdomain.RoleSecurityAdmin, tdomain.RoleAuditor} {
		bs = append(bs, tdomain.Binding{Role: r, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}})
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: id}, Bindings: bs},
		Credential: tapp.CredAccessToken,
	})
}

// idrRecords is everything w's org keeps about txn: its receipts,
// reservations, dedupe claim, verifications, reconciliations, waitlist
// entries and links, the transaction's own state and the org's ledger.
func idrRecords(w *world, txn ids.UUID) string {
	w.t.Helper()
	return w.str(`SELECT concat_ws(' | ',
		(SELECT string_agg(receipt_jws, ',' ORDER BY evaluation) FROM pc.decision_receipts WHERE transaction_id = $1),
		(SELECT string_agg(receipt_jws, ',') FROM pc.execution_receipts WHERE transaction_id = $1),
		(SELECT string_agg(seq::text || state || receipt_jws, ',' ORDER BY seq) FROM pc.effect_receipts WHERE transaction_id = $1),
		(SELECT string_agg(state || amount::text, ',' ORDER BY id) FROM pc.reservations WHERE transaction_id = $1),
		(SELECT string_agg(state, ',') FROM pc.dedupe_claims WHERE transaction_id = $1),
		(SELECT string_agg(id::text || state || attempts::text || next_at::text, ',' ORDER BY id) FROM pc.verifications WHERE transaction_id = $1),
		(SELECT string_agg(id::text || state || coalesce(resolved_via, '') || coalesce(user_id::text, '') || coalesce(basis, ''), ',' ORDER BY id)
			FROM pc.reconciliation_tasks WHERE transaction_id = $1),
		(SELECT string_agg(id::text || state, ',' ORDER BY id) FROM pc.waitlist_entries WHERE subject_type = 'transaction' AND subject_id = $1),
		(SELECT count(*)::text FROM pc.transaction_links WHERE $1 IN (from_transaction_id, to_transaction_id)),
		(SELECT state || ' ' || coalesce(effect_state, '-') FROM pc.transactions WHERE id = $1),
		(SELECT count(*)::text FROM pc.ledger_entries WHERE org_id = $2))`, txn, w.org)
}

// TestT037_TransactionsOfAnotherOrgAreNotFound: T-037 — a person holding
// every evidence-reading role at org scope asks TransactionService for
// another org's real transactions (an unknown outcome, an accepted refund
// and a blocked one): their evidence is NotFound exactly as for an unknown
// id, no list shows them, even filtered by that org's run, agent or
// connection, and nothing about them changes. The same person reads its
// own org's transaction. TestExplorer_ListsByExecutionStateAndScope covers
// who may read inside an org.
func TestT037_TransactionsOfAnotherOrgAreNotFound(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	other := idrWorldOn(w)
	w.refundable("ch_1")
	other.refundable("ch_1", "ch_2", "ch_3")
	mine := w.recorded(w.run(w.grant("500").ID, ids.UUID{}), "ch_1", "30.00", finalize.Accepted, "re_1")
	run := other.run(other.grant("500").ID, ids.UUID{})
	blocked := other.authorize(other.request(run, ids.NewV7(), "ch_3", "150.00"))
	if blocked.Permit != "" {
		t.Fatalf("over the bound: %s", blocked.Decision)
	}
	theirs := []ids.UUID{
		other.recorded(run, "ch_1", "30.00", finalize.Unknown, "").TransactionID,
		other.recorded(run, "ch_2", "20.00", finalize.Accepted, "re_2").TransactionID,
		blocked.TransactionID,
	}
	before := map[ids.UUID]string{}
	for _, id := range theirs {
		before[id] = idrRecords(other, id)
	}

	person := idrPerson(w)
	e := &txapp.Explorer{Pool: w.pool}
	if ev, err := e.TransactionEvidence(person, mine.TransactionID); err != nil || ev.Transaction.ID != mine.TransactionID {
		t.Fatalf("its own transaction: %+v %v", ev.Transaction, err)
	}
	for _, id := range append(theirs, ids.NewV7()) {
		if _, err := e.TransactionEvidence(person, id); !errors.Is(err, txapp.ErrTransactionNotFound) {
			t.Errorf("evidence of %s: %v", id, err)
		}
	}
	for name, c := range map[string]struct {
		f    txapp.Filter
		want int
	}{
		"all":              {txapp.Filter{}, 1},
		"their run":        {txapp.Filter{Run: &run}, 0},
		"their agent":      {txapp.Filter{Agent: &other.agent}, 0},
		"their connection": {txapp.Filter{Connection: &other.conn}, 0},
	} {
		p, err := e.ListTransactions(person, page.Request{Size: page.Max}, c.f)
		if err != nil || len(p.Items) != c.want {
			t.Errorf("list %s: %d %v", name, len(p.Items), err)
		}
		for _, s := range p.Items {
			if s.ID != mine.TransactionID {
				t.Errorf("list %s shows %s", name, s.ID)
			}
		}
	}
	for _, id := range theirs {
		if got := idrRecords(other, id); got != before[id] {
			t.Errorf("%s changed:\n%s\nwas\n%s", id, got, before[id])
		}
	}
}

// TestT037_ReconciliationsOfAnotherOrgAreNotFound: T-037 — a person holding
// transaction.reconcile and every evidence-reading role at org scope gets,
// lists and resolves another org's real open reconciliation, requests a
// verification of its transaction, and links that transaction to one of
// its own, as the later and as the earlier end: each is NotFound exactly as
// for an unknown id, and the other transaction's receipts, budget,
// reconciliation, verification, waitlist entry, links and ledger are
// unchanged. The same person does each of these in its own org.
// TestHR192_*, TestRequestVerification_ReadsAgainNow and TestHR193_* cover
// the checks inside an org.
func TestT037_ReconciliationsOfAnotherOrgAreNotFound(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	other := idrWorldOn(w)
	w.refundable("ch_1", "ch_2", "ch_3")
	other.refundable("ch_1")
	mine := w.run(w.grant("500").ID, ids.UUID{})
	earlier := w.recorded(mine, "ch_1", "30.00", finalize.Accepted, "re_1")
	theirs := other.recorded(other.run(other.grant("500").ID, ids.UUID{}), "ch_1", "30.00", finalize.Unknown, "").TransactionID
	later := w.recorded(mine, "ch_2", "10.00", finalize.Accepted, "re_2")
	own := w.recorded(mine, "ch_3", "5.00", finalize.Unknown, "")
	task, err := ids.ParseUUID(other.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1", theirs))
	if err != nil {
		t.Fatal(err)
	}
	ownTask, err := ids.ParseUUID(w.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1", own.TransactionID))
	if err != nil {
		t.Fatal(err)
	}
	before := idrRecords(other, theirs)

	person := idrPerson(w)
	e := &txapp.Explorer{Pool: w.pool}
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: w.verifier()}
	basis := "The refund is in the processor's dashboard as re_7731."
	for name, c := range map[string]struct {
		call   func(ids.UUID) error
		theirs ids.UUID
		want   error
	}{
		"get": {func(id ids.UUID) error { _, _, err := e.Reconciliation(person, id); return err }, task, txapp.ErrReconciliationNotFound},
		"resolve occurred": {func(id ids.UUID) error {
			_, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: id, Basis: basis})
			return err
		}, task, txapp.ErrReconciliationNotFound},
		"request verification": {func(id ids.UUID) error { _, err := rec.RequestVerification(person, id); return err }, theirs, txapp.ErrTransactionNotFound},
		"link from theirs": {func(id ids.UUID) error {
			_, err := rec.Link(person, txapp.LinkRequest{From: id, To: earlier.TransactionID, Kind: txdomain.LinkCompensates})
			return err
		}, theirs, txapp.ErrTransactionNotFound},
		"link to theirs": {func(id ids.UUID) error {
			_, err := rec.Link(person, txapp.LinkRequest{From: later.TransactionID, To: id, Kind: txdomain.LinkCompensates})
			return err
		}, theirs, txapp.ErrTransactionNotFound},
	} {
		for what, id := range map[string]ids.UUID{"theirs": c.theirs, "unknown": ids.NewV7()} {
			if err := c.call(id); !errors.Is(err, c.want) {
				t.Errorf("%s, %s id: %v, want %v", name, what, err, c.want)
			}
		}
	}
	for name, c := range map[string]struct {
		f    txapp.ReconciliationFilter
		want int
	}{
		"all":               {txapp.ReconciliationFilter{}, 1},
		"their transaction": {txapp.ReconciliationFilter{Transaction: &theirs}, 0},
	} {
		p, err := e.ListReconciliations(person, page.Request{Size: page.Max}, c.f)
		if err != nil || len(p.Items) != c.want {
			t.Errorf("list %s: %d %v", name, len(p.Items), err)
		}
		for _, k := range p.Items {
			if k.ID != ownTask {
				t.Errorf("list %s shows %s", name, k.ID)
			}
		}
	}
	if got := idrRecords(other, theirs); got != before {
		t.Errorf("their transaction changed:\n%s\nwas\n%s", got, before)
	}
	if n := w.count("SELECT count(*) FROM pc.transaction_links"); n != 0 {
		t.Errorf("%d links in its own org", n)
	}

	if _, _, err := e.Reconciliation(person, ownTask); err != nil {
		t.Fatalf("get its own: %v", err)
	}
	if _, err := rec.RequestVerification(person, own.TransactionID); err != nil {
		t.Fatalf("request a verification of its own: %v", err)
	}
	if _, err := rec.Link(person, txapp.LinkRequest{From: later.TransactionID, To: earlier.TransactionID, Kind: txdomain.LinkCompensates}); err != nil {
		t.Fatalf("link its own: %v", err)
	}
	if k, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: ownTask, Basis: basis}); err != nil || k.State != txdomain.TaskOccurred {
		t.Fatalf("resolve its own: %+v %v", k, err)
	}
}
