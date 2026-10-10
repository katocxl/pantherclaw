// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factapp "github.com/katocxl/pantherclaw/internal/facts/app"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type allow struct{}

func (allow) Require(tapp.Caller, tdomain.Permission, tdomain.Path) error { return nil }

type world struct {
	t        testing.TB
	db       *dbtest.DB
	pool     *db.Pool
	org      ids.OrgID
	alice    ids.UUID
	billing  ids.UUID
	agent    ids.UUID
	instance ids.UUID
	env      ids.UUID
	grants   *gapp.Service
	facts    *factapp.Service
	mapper   *mapping.Mapper
	auth     *finalize.Authority
	gw       finalize.Gateway
	human    context.Context
	// gwID is the gateway's id, and conn the connection requests go
	// through by default.
	gwID, conn ids.UUID
}

func exec(t testing.TB, p *db.Pool, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// newWorld builds an org with the mock-payments package imported and
// active, a fact provider, an agent with an admitted instance, and an
// Authority over PostgreSQL.
func newWorld(t testing.TB) *world {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	w := &world{t: t, db: d, pool: p, org: ids.New[ids.Org](), alice: ids.NewV7(), billing: ids.NewV7(), agent: ids.NewV7(), instance: ids.NewV7(), env: ids.NewV7()}
	team := ids.NewV7()
	exec(t, p, w.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
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

	// The package, signed with a test root, imported and activated.
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
	defs := &defpg.Store{Pool: p}
	im := &defapp.Importer{Roots: trust.Roots{kid: signer.Public()}, Repo: defs, Clock: clock.NewFake(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))}
	if _, err := im.Import(ctx, w.org, "pc.mock-payments", "1.0.0", doc, raw, nil); err != nil {
		t.Fatal(err)
	}
	if err := im.Transition(ctx, w.org, "pc.mock-payments", "1.0.0", defdomain.StateActive, nil); err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if w.mapper, err = mapping.New(pkg, celenv.DefaultLimits); err != nil {
		t.Fatal(err)
	}

	facts := &factpg.Store{Pool: p}
	w.facts = &factapp.Service{Store: facts, Authz: allow{}}
	if _, err := w.facts.RegisterProvider(w.human, "billing.system", w.billing, []fdomain.Declaration{
		{Name: "payments.charge.refundable", Type: fdomain.TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
	}); err != nil {
		t.Fatal(err)
	}
	gs := &gpg.Store{Pool: p}
	w.grants = &gapp.Service{Repo: gs, Subjects: gs, Defs: defs, Authz: allow{}, Clock: clock.System{}}

	reg := keys.NewRegistry()
	for _, purpose := range []keys.Purpose{keys.PurposePermits, keys.PurposeReceipts} {
		k, _ := keys.GenerateSigningKey(purpose)
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	receipts, _ := reg.Signer(keys.PurposeReceipts)
	permits, _ := reg.Signer(keys.PurposePermits)
	reader := &pgauthority.Reader{Pool: p, Definitions: defs, Policies: &polpg.Store{Pool: p}, FactStore: facts, Grants: gs, Limits: celenv.DefaultLimits}
	w.auth = &finalize.Authority{Pipeline: &pipeline.Pipeline{Reader: reader}, Store: &pgauthority.Store{Pool: p}, Receipts: receipts, Permits: permits}
	// One gateway, and the enforce-mode connection every request goes
	// through unless a test names another (PAP-1 §6).
	gw := ids.NewV7()
	exec(t, p, w.org, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, gw)
	w.gw, w.gwID = finalize.Gateway{ID: gw.String(), Org: w.org}, gw
	w.conn = w.withConnection("enforce")
	return w
}

// refundable pushes "refundable" facts for charges, as the provider.
func (w *world) refundable(charges ...string) {
	w.t.Helper()
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing}}})
	for len(charges) > 0 {
		n := min(len(charges), factapp.MaxObservations)
		var obs []fdomain.Observation
		for _, c := range charges[:n] {
			obs = append(obs, fdomain.Observation{
				Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: c,
				Value: jsontext.Value(`{"bool": true}`), ObservedAt: time.Now().Add(-time.Second),
			})
		}
		res, err := w.facts.PutFacts(ctx, obs)
		if err != nil {
			w.t.Fatal(err)
		}
		for _, r := range res {
			if r.Err != nil {
				w.t.Fatalf("fact %s: %v", r.SubjectID, r.Err)
			}
		}
		charges = charges[n:]
	}
}

func (w *world) grant(limit string) gdomain.Grant {
	w.t.Helper()
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create", "payments.refund.get"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	lim, _ := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"], "currency": "USD", "limit": "` + limit + `", "period": "none"}]}`))
	g, err := w.grants.Issue(w.human, gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Limits: lim, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

func (w *world) run(grant gdomain.GrantID, parent ids.UUID) ids.UUID {
	id := ids.NewV7()
	if parent.IsZero() {
		exec(w.t, w.pool, w.org, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id,
			principal_source, grant_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', $7, now() + interval '8 hours')`,
			w.org, id, w.agent, w.instance, w.env, w.alice, grant.UUID())
		return id
	}
	exec(w.t, w.pool, w.org, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_instance_id, principal_user_id,
		principal_source, parent_run_id, depth, expires_at) VALUES ($1, $2, $3, $4, $5, $4, $6, 'parent_run', $7, 1, now() + interval '4 hours')`,
		w.org, id, w.agent, w.instance, w.env, w.alice, parent)
	return id
}

func (w *world) request(run, action ids.UUID, charge, amount string) pipeline.Request {
	w.t.Helper()
	p, err := w.mapper.MCP(context.Background(), mapping.Context{
		Org: w.org.String(), Env: w.env.String(), RunID: run.String(), ActionID: action.String(), AgentInstance: w.instance.String(),
		Connection: w.conn.String(),
	}, "create_refund", []byte(`{"charge":"`+charge+`","amount":"`+amount+`","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		w.t.Fatal(err)
	}
	return pipeline.Request{Org: w.org, Action: p, Identity: pipeline.Identity{InstanceID: w.instance, AgentID: w.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}}
}

func (w *world) authorize(req pipeline.Request) finalize.Result {
	w.t.Helper()
	r, err := w.auth.Authorize(context.Background(), w.gw, req)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func decisive(r finalize.Result) string {
	for _, x := range r.Reasons {
		if x.Decisive {
			return x.Code
		}
	}
	return ""
}

func TestIntAuthorizeThroughPostgres(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.refundable("ch_1", "ch_2")
	g := w.grant("500")
	run := w.run(g.ID, ids.UUID{})

	act := ids.NewV7()
	ok := w.authorize(w.request(run, act, "ch_1", "30.00"))
	if ok.Decision != adomain.Allow || ok.Permit == "" || ok.Receipt == "" || decisive(ok) != pipeline.ReasonGrantCovers {
		t.Fatalf("allow: %+v", ok)
	}
	if again := w.authorize(w.request(run, act, "ch_1", "30.00")); !again.Repeat || again.Permit != "" || again.Receipt != ok.Receipt {
		t.Fatalf("a repeat returns the stored decision (HR-005): %+v", again)
	}
	if r := w.authorize(w.request(run, act, "ch_1", "31.00")); decisive(r) != adomain.ReasonActionTampered {
		t.Fatalf("tampered (HR-006): %s", decisive(r))
	}
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00")); decisive(r) != pipeline.ReasonReconciliation {
		t.Fatalf("an identical refund while the first is issued (HR-007): %s", decisive(r))
	}
	if _, err := w.auth.BeginDispatch(ctx, w.gw, ok.PermitID, ok.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: ok.PermitID, Outcome: finalize.Accepted, DispatchMS: -1}); err != nil {
		t.Fatal(err)
	}
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00")); decisive(r) != pipeline.ReasonReconciliation {
		t.Fatalf("an identical refund after success, inside the window: %s", decisive(r))
	}
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_2", "125.00")); r.Decision != adomain.Deny || decisive(r) != gdomain.ReasonGrantLimitExceeded {
		t.Fatalf("over the grant: %s %s", r.Decision, decisive(r))
	}

	// Missing evidence, then the fact arrives: the same action is decided again.
	act = ids.NewV7()
	missing := w.authorize(w.request(run, act, "ch_3", "10.00"))
	if missing.Decision != adomain.CannotAuthorize || decisive(missing) != fdomain.ReasonFactMissing {
		t.Fatalf("missing fact: %s %s", missing.Decision, decisive(missing))
	}
	w.refundable("ch_3")
	retried := w.authorize(w.request(run, act, "ch_3", "10.00"))
	if retried.Decision != adomain.Allow || retried.Evaluation != 2 || retried.TransactionID != missing.TransactionID {
		t.Fatalf("re-evaluated: %+v", retried)
	}

	// Revoking the grant: the in-flight permit can no longer dispatch, and
	// new actions are denied.
	if _, err := w.grants.Revoke(w.human, g.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.auth.BeginDispatch(ctx, w.gw, retried.PermitID, retried.Epoch, finalize.Outbound{}); err == nil {
		t.Fatal("a permit issued before the revocation was dispatched")
	}
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_2", "5.00")); decisive(r) != gdomain.ReasonGrantRevoked {
		t.Fatalf("after revocation: %s", decisive(r))
	}
}

// TestHR048_NoOverspendUnder1000ConcurrentAuthorizations is the M4 exit
// race: 1,000 parallel refunds of 1 USD from a parent run and two child runs
// whose delegated grants have their own 300 USD budgets under the parent's
// shared 500 USD. The first child sends 700 of them, so both caps bind:
// exactly 500 are permitted, no child gets more than 300, and every other
// answer is a decision, never an error.
func TestHR048_NoOverspendUnder1000ConcurrentAuthorizations(t *testing.T) {
	w := newWorld(t)
	charges := make([]string, 1000)
	for i := range charges {
		charges[i] = fmt.Sprintf("ch_%d", i)
	}
	w.refundable(charges...)
	g := w.grant("500")
	rootRun := w.run(g.ID, ids.UUID{})
	runs := []ids.UUID{rootRun}
	lim, _ := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "child", "grouping": "task", "operations": ["payments.refund.create"], "currency": "USD", "limit": "300", "period": "none"}]}`))
	for range 2 {
		child := w.run(gdomain.GrantID{}, rootRun)
		if _, err := w.grants.Delegate(context.Background(), gapp.Workload{Org: w.org, InstanceID: w.instance, RunID: rootRun},
			gapp.DelegateRequest{ChildRunID: child, Limits: lim}); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, child)
	}
	var mu sync.Mutex
	permits := map[int]int{}
	errs := 0
	var wg sync.WaitGroup
	for i := range 1000 {
		r := 1 // 700 from the first child, 200 from the second, 100 from the parent
		switch i % 10 {
		case 7, 8:
			r = 2
		case 9:
			r = 0
		}
		req := w.request(runs[r], ids.NewV7(), charges[i], "1.00")
		wg.Go(func() {
			res, err := w.auth.Authorize(context.Background(), w.gw, req)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				errs++
				t.Logf("authorize: %v", err)
			case res.Permit != "":
				permits[r]++
			case res.Decision.Permits():
				t.Errorf("an ALLOW without a permit")
			}
		})
	}
	wg.Wait()
	total := permits[0] + permits[1] + permits[2]
	if errs > 0 {
		t.Fatalf("%d calls failed instead of deciding", errs)
	}
	if total != 500 || permits[1] > 300 || permits[2] > 300 {
		t.Fatalf("permits %v (total %d), want 500 in total and at most 300 per child", permits, total)
	}
}

// budget returns the reserved and spent totals of the org's accounts as
// settled: an outcome recorded but not yet applied to its row by the sweep
// counts as spent or released (ADR-0015), as the budget views show it.
func (w *world) budget() (reserved, spent string) {
	w.t.Helper()
	return w.totals(`SELECT
		((SELECT coalesce(sum(reserved), 0) FROM pc.budget_accounts)
		 - (SELECT coalesce(sum(amount), 0) FROM pc.reservations WHERE pending AND account_id IS NOT NULL))::text,
		((SELECT coalesce(sum(spent), 0) FROM pc.budget_accounts)
		 + (SELECT coalesce(sum(amount), 0) FROM pc.reservations WHERE pending AND state = 'COMMITTED' AND account_id IS NOT NULL))::text`)
}

// rows returns the reserved and spent totals of the account rows
// themselves, which an outcome reaches only when the sweep applies it.
func (w *world) rows() (reserved, spent string) {
	w.t.Helper()
	return w.totals("SELECT coalesce(sum(reserved), 0)::text, coalesce(sum(spent), 0)::text FROM pc.budget_accounts")
}

func (w *world) totals(sql string) (reserved, spent string) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql).Scan(&reserved, &spent)
	}); err != nil {
		w.t.Fatal(err)
	}
	return money.MustParse(reserved).String(), money.MustParse(spent).String()
}

// settle applies the outcomes recorded so far to the budget rows, as the
// sweep job does (ADR-0015), and checks that none is left pending and the
// rows now equal the settled totals.
func (w *world) settle() {
	w.t.Helper()
	if _, err := w.auth.Store.ApplySettlements(context.Background(), w.org); err != nil {
		w.t.Fatal(err)
	}
	if n := w.count("SELECT count(*) FROM pc.reservations WHERE pending"); n != 0 {
		w.t.Fatalf("%d reservations still pending after the settlement", n)
	}
	r1, s1 := w.rows()
	if r2, s2 := w.budget(); r1 != r2 || s1 != s2 {
		w.t.Fatalf("after the settlement the rows show reserved %s spent %s, the settled totals %s and %s", r1, s1, r2, s2)
	}
}

// waitExpired waits until the database clock, which BeginDispatch and the
// sweep use, is past the permit's expiry.
func (w *world) waitExpired(permit ids.UUID) {
	w.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var expired bool
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT expires_at < now() FROM pc.permits WHERE id = $1", permit).Scan(&expired)
		}); err != nil {
			w.t.Fatal(err)
		}
		if expired {
			return
		}
		if time.Now().After(deadline) {
			w.t.Fatal("the permit did not expire")
		}
	}
}

// reconciliation checks that a transaction with an unknown outcome has one
// open, urgent RECONCILIATION entry (HR-003, HR-177).
func (w *world) reconciliation(txn ids.UUID) {
	w.t.Helper()
	var n, priority int
	w.db.AdminQueryRow(w.t, `SELECT count(*), coalesce(min(priority), 0) FROM pc.waitlist_entries
		WHERE org_id = $1 AND kind = 'RECONCILIATION' AND subject_id = $2 AND transaction_id = $2 AND state = 'OPEN'`,
		[]any{w.org, txn}, &n, &priority)
	if n != 1 || priority != 1 {
		w.t.Fatalf("transaction %s: %d open RECONCILIATION entries, priority %d", txn, n, priority)
	}
}

// TestINV07_SettlementOnPostgres: a decision reserves, only an accepted
// outcome spends; a failed one or an expired permit releases the budget
// and the refund's dedupe claim, and an unknown one holds both (HR-003).
func TestINV07_SettlementOnPostgres(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	// The permits this test dispatches outlive it, so a slow run never
	// expires one before its dispatch; only the one meant to expire gets a
	// short lifetime.
	const long = time.Hour
	w.auth.PermitTTL = long
	w.refundable("ch_1", "ch_2", "ch_3")
	run := w.run(w.grant("500").ID, ids.UUID{})
	dispatch := func(r finalize.Result, o finalize.Outcome) {
		t.Helper()
		if r.Permit == "" {
			t.Fatalf("no permit: %s %s", r.Decision, decisive(r))
		}
		if _, err := w.auth.BeginDispatch(ctx, w.gw, r.PermitID, r.Epoch, finalize.Outbound{}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: r.PermitID, Outcome: o, DispatchMS: -1}); err != nil {
			t.Fatal(err)
		}
	}

	first := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
	if res, sp := w.budget(); res != "30" || sp != "0" {
		t.Fatalf("an ALLOW reserves and spends nothing: reserved %s spent %s", res, sp)
	}
	dispatch(first, finalize.Failed)
	// The outcome reaches the budget row with the settlement (ADR-0015);
	// until then the row still counts it reserved, never less, while the
	// settled totals already show it released.
	if res, sp := w.rows(); res != "30" || sp != "0" {
		t.Fatalf("before the settlement the row: reserved %s spent %s, want the release still counted", res, sp)
	}
	if res, sp := w.budget(); res != "0" || sp != "0" {
		t.Fatalf("before the settlement the settled totals: reserved %s spent %s", res, sp)
	}
	w.settle()
	if res, sp := w.budget(); res != "0" || sp != "0" {
		t.Fatalf("a failed outcome releases: reserved %s spent %s", res, sp)
	}

	second := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
	if second.Decision != adomain.Allow {
		t.Fatalf("after a failure the same refund may be tried again: %s %s", second.Decision, decisive(second))
	}
	dispatch(second, finalize.Unknown)
	w.settle()
	if res, sp := w.budget(); res != "30" || sp != "0" {
		t.Fatalf("an unknown outcome holds the reservation: reserved %s spent %s", res, sp)
	}
	if r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00")); decisive(r) != pipeline.ReasonReconciliation {
		t.Fatalf("an unknown outcome holds the claim: %s", decisive(r))
	}
	// The unknown outcome waits for reconciliation (G0 M5 part 2).
	w.reconciliation(second.TransactionID)

	// An issued permit that expires is released by the sweep, and a permit
	// stuck in DISPATCHING becomes UNKNOWN, even once it has expired too.
	stuck := w.authorize(w.request(run, ids.NewV7(), "ch_3", "5.00"))
	if _, err := w.auth.BeginDispatch(ctx, w.gw, stuck.PermitID, stuck.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	w.db.AdminExec(t, "UPDATE pc.permits SET expires_at = now() - interval '1 second' WHERE id = $1", stuck.PermitID)
	w.auth.PermitTTL = time.Millisecond
	expiring := w.authorize(w.request(run, ids.NewV7(), "ch_2", "20.00"))
	w.auth.PermitTTL = long
	w.waitExpired(expiring.PermitID)
	released, unknown, err := w.auth.Sweep(ctx, w.org, time.Nanosecond)
	if err != nil || released != 1 || unknown != 1 {
		t.Fatalf("sweep: released %d unknown %d: %v", released, unknown, err)
	}
	if _, err := w.auth.BeginDispatch(ctx, w.gw, expiring.PermitID, expiring.Epoch, finalize.Outbound{}); err == nil {
		t.Fatal("a released permit was dispatched")
	}
	w.reconciliation(stuck.TransactionID)
	w.settle()
	if res, sp := w.budget(); res != "35" || sp != "0" {
		t.Fatalf("after the sweep: reserved %s spent %s, want the unknown 30 and 5 held", res, sp)
	}
	again := w.authorize(w.request(run, ids.NewV7(), "ch_2", "20.00"))
	dispatch(again, finalize.Accepted)
	w.settle()
	if res, sp := w.budget(); res != "35" || sp != "20" {
		t.Fatalf("an accepted outcome spends: reserved %s spent %s", res, sp)
	}
}
