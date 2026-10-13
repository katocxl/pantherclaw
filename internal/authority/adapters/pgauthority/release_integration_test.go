// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// onPage is a person signed in on the reconciliation page: a user bound to
// role at the org, with a browser session and a security key (G0 M7 slice
// A11). The assertions in these tests are the parts the page keeps after
// authn's VerifyBinding checked them; the end-to-end test makes real ones.
type onPage struct {
	ctx                context.Context
	user, session, key ids.UUID
}

// person adds a user named name.
func (w *world) person(name string) ids.UUID {
	w.t.Helper()
	id := ids.NewV7()
	exec(w.t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, id, name)
	return id
}

// signedIn gives user a browser session and a security key, bound as role
// at scope (the org's when scope is zero).
func (w *world) signedIn(user ids.UUID, role tdomain.RoleName, scope tdomain.Scope) onPage {
	w.t.Helper()
	p := onPage{user: user, session: ids.NewV7(), key: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.session[:])
	copy(secret[16:], p.key[:])
	exec(w.t, w.pool, w.org, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`, w.org, p.key, user, p.key[:], secret)
	exec(w.t, w.pool, w.org, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, w.org, p.session, user, secret)
	if scope.ID.IsZero() {
		scope = tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}
	}
	p.ctx = tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: user}, Bindings: []tdomain.Binding{{Role: role, Scope: scope}}},
		Credential: tapp.CredBrowserSession, Session: p.session,
	})
	return p
}

// ceremony stores the open BINDING ceremony the page starts over a release
// binding, as authn's BeginBinding does, and returns the assertion the page
// hands over once VerifyBinding verified it.
func (w *world) ceremony(p onPage, reconciliation ids.UUID, challenge [32]byte) txapp.Assertion {
	w.t.Helper()
	id := ids.NewV7()
	exec(w.t, w.pool, w.org, `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, reconciliation_id,
		expires_at) VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, w.org, id, p.session, p.user, challenge[:], reconciliation)
	return txapp.Assertion{
		Ceremony: id, Credential: p.key, AuthenticatorData: append(make([]byte, 36), 5), ClientDataJSON: []byte(`{"type":"webauthn.get"}`),
		Signature: []byte{0x30, 0x01},
	}
}

// spent reports whether the ceremony of a was consumed.
func (w *world) spent(a txapp.Assertion) bool {
	w.t.Helper()
	return w.count("SELECT count(*) FROM pc.webauthn_ceremonies WHERE id = $1 AND consumed_at IS NOT NULL", a.Ceremony) == 1
}

// entry is the transaction's RECONCILIATION waitlist entry: its state,
// reason and who decided it.
func (w *world) entry(txn ids.UUID) string {
	w.t.Helper()
	var out string
	w.db.AdminQueryRow(w.t, `SELECT state || ' ' || decision_reason || ' ' || coalesce(decided_by, '') FROM pc.waitlist_entries
		WHERE org_id = $1 AND kind = 'RECONCILIATION' AND subject_id = $2`, []any{w.org, txn}, &out)
	return strings.TrimSpace(out)
}

// unknownRefund records a refund of 30.00 on ch_1 whose outcome is unknown
// and whose lookup found nothing in a complete listing 11 minutes after
// dispatch: the evidence a person may release it on. It returns the
// transaction, its reconciliation and the observation.
func (w *world) unknownRefund(s *txapp.Service, run ids.UUID) (finalize.Result, ids.UUID, ids.UUID) {
	w.t.Helper()
	r := w.recorded(run, "ch_1", "30.00", finalize.Unknown, "")
	w.db.AdminExec(w.t, "UPDATE pc.permits SET dispatching_at = now() - interval '11 minutes' WHERE transaction_id = $1", r.TransactionID)
	l := w.lease(s, r.TransactionID)
	a, err := s.Report(context.Background(), w.org, w.gwID, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Complete: true})
	if err != nil || a.State != txdomain.NoneConfirmed || a.Resolved {
		w.t.Fatalf("absent after the window: %+v %v", a, err)
	}
	task, err := ids.ParseUUID(w.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID))
	if err != nil {
		w.t.Fatal(err)
	}
	return r, task, a.Observation
}

// TestHR192_OnlyAnIndependentPersonReleasesWithAKeyOverTheBasis: releasing
// an unknown outcome ("did not occur") is refused to an API key, a service
// account and a CLI session, to the run's launcher, its represented
// principal, the agent's owner and backup owner, and to a Reconciler of
// another team; without an assertion, with an assertion over another basis
// or other evidence, and after the release expired. Every refusal spends
// the ceremony and changes nothing. An independent Reconciler's release
// records the person, session, credential, assertion, basis and evidence,
// releases the budget and the dedupe claim, appends a NONE_CONFIRMED effect
// receipt whose basis is the person, writes the ledger entry, closes the
// waitlist entry and tells the org's admins; an exact repeat is then
// decided again.
func TestHR192_OnlyAnIndependentPersonReleasesWithAKeyOverTheBasis(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	told := &notes{}
	rel := &txapp.Releases{Store: &pgtransactions.Store{Pool: w.pool, Notify: told}, Explorer: &txapp.Explorer{Pool: w.pool}, Effects: s}
	run := w.run(w.grant("500").ID, ids.UUID{})
	r, task, obs := w.unknownRefund(s, run)
	if w.entry(r.TransactionID) != "OPEN" ||
		w.count("SELECT count(*) FROM pc.reconciliation_tasks t JOIN pc.waitlist_entries e ON e.org_id = t.org_id AND e.id = t.waitlist_entry_id WHERE t.id = $1", task) != 1 {
		t.Fatal("the reconciliation is not linked to its open waitlist entry")
	}

	// The people around the run: alice launched it; it acts for pat; olga
	// owns the agent and bea backs her up. admin is the org's admin.
	pat, olga, bea := w.person("pat"), w.person("olga"), w.person("bea")
	w.db.AdminExec(t, `UPDATE pc.runs SET principal_user_id = $2, principal_source = 'subject_token', subject_issuer = 'https://idp.test',
		subject_subject = 'pat' WHERE id = $1`, run, pat)
	w.db.AdminExec(t, "UPDATE pc.agents SET owner_user_id = $2, backup_owner_user_id = $3 WHERE id = $1", w.agent, olga, bea)
	admin := w.person("admin")
	exec(t, w.pool, w.org, "INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')",
		w.org, ids.NewV7(), admin)

	basis := "No refund for ch_1 in the processor's dashboard at 14:05; its log shows the request never arrived."
	req := txapp.ReleaseRequest{Reconciliation: task, Basis: basis, Evidence: []ids.UUID{obs}}

	// Not a person on the page.
	apiKey := tapp.WithCaller(ctx, tapp.Caller{Subject: tdomain.Subject{
		Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing},
		Bindings: []tdomain.Binding{{Role: tdomain.RoleReconciler, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}}},
	}, Credential: tapp.CredAPIKey})
	service := tapp.WithCaller(ctx, tapp.Caller{Subject: tdomain.Subject{
		Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing},
		Bindings: []tdomain.Binding{{Role: tdomain.RoleReconciler, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession, Session: ids.NewV7()})
	rita := w.signedIn(w.person("rita"), tdomain.RoleReconciler, tdomain.Scope{})
	cli := tapp.WithCaller(ctx, tapp.Caller{Subject: tdomain.Subject{
		Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: rita.user},
		Bindings: []tdomain.Binding{{Role: tdomain.RoleReconciler, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}}},
	}, Credential: tapp.CredAccessToken, Session: ids.NewV7()})
	for name, c := range map[string]context.Context{"an API key": apiKey, "a service account": service, "a CLI session": cli} {
		if _, err := rel.BeginRelease(c, req); !errors.Is(err, txapp.ErrBrowserSession) {
			t.Errorf("%s begins a release: %v", name, err)
		}
		if _, err := rel.Release(c, req, time.Now().Add(time.Minute), txapp.Assertion{Ceremony: ids.NewV7()}); !errors.Is(err, txapp.ErrBrowserSession) {
			t.Errorf("%s releases: %v", name, err)
		}
	}

	// The run's and the agent's own people, even holding the role.
	for name, user := range map[string]ids.UUID{"the launcher": w.alice, "the principal": pat, "the owner": olga, "the backup owner": bea} {
		p := w.signedIn(user, tdomain.RoleReconciler, tdomain.Scope{})
		if _, err := rel.BeginRelease(p.ctx, req); !errors.Is(err, txapp.ErrNotIndependent) {
			t.Errorf("%s begins a release: %v", name, err)
		}
		if v, err := rel.View(p.ctx, task); err != nil || v.MayRelease || v.Refusal != txapp.RefusalIndependence {
			t.Errorf("%s's page: %+v %v", name, v.Refusal, err)
		}
		doc := txdomain.Release{Reconciliation: task, Transaction: r.TransactionID, Basis: basis, Evidence: req.Evidence, ExpiresAt: time.Now().Add(time.Minute)}
		b, _ := doc.Binding()
		a := w.ceremony(p, task, b)
		if _, err := rel.Release(p.ctx, req, doc.ExpiresAt, a); !errors.Is(err, txapp.ErrNotIndependent) || !w.spent(a) {
			t.Errorf("%s releases with a key: %v (spent %v)", name, err, w.spent(a))
		}
	}
	// A Reconciler of another team neither sees it nor releases it.
	elsewhere := w.signedIn(w.person("ian"), tdomain.RoleReconciler, tdomain.Scope{Type: tdomain.ScopeTeam, ID: ids.NewV7()})
	if _, err := rel.View(elsewhere.ctx, task); !errors.Is(err, txapp.ErrReconciliationNotFound) {
		t.Fatalf("another team's page: %v", err)
	}
	if _, err := rel.BeginRelease(elsewhere.ctx, req); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("another team's reconciler: %v", err)
	}

	// An independent Reconciler sees the evidence and may release.
	v, err := rel.View(rita.ctx, task)
	if err != nil || !v.MayRelease || len(v.Evidence.Observations) != 1 || v.Evidence.Observations[0].ID != obs ||
		v.Evidence.Transaction.Effect != txdomain.NoneConfirmed {
		t.Fatalf("rita's page: %+v %v", v, err)
	}
	for _, bad := range []txapp.ReleaseRequest{
		{Reconciliation: task, Evidence: req.Evidence},
		{Reconciliation: task, Basis: strings.Repeat("x", txdomain.MaxBasis+1), Evidence: req.Evidence},
	} {
		if _, err := rel.BeginRelease(rita.ctx, bad); !errors.Is(err, txapp.ErrBasis) {
			t.Errorf("basis of %d characters: %v", len(bad.Basis), err)
		}
	}
	if _, err := rel.BeginRelease(rita.ctx, txapp.ReleaseRequest{Reconciliation: task, Basis: basis, Evidence: []ids.UUID{ids.NewV7()}}); !errors.Is(err, txapp.ErrEvidence) {
		t.Fatalf("evidence the transaction does not have: %v", err)
	}
	offer, err := rel.BeginRelease(rita.ctx, req)
	if err != nil || offer.Release.Transaction != r.TransactionID || offer.Release.ExpiresAt.Before(time.Now()) {
		t.Fatalf("offer %+v %v", offer, err)
	}
	if want, _ := offer.Release.Binding(); want != offer.Binding {
		t.Fatal("the offer's binding is not its document's")
	}

	// Without an assertion; over another basis; over other evidence; expired.
	if _, err := rel.Release(rita.ctx, req, offer.Release.ExpiresAt, txapp.Assertion{Ceremony: ids.NewV7(), Credential: rita.key}); !errors.Is(err, txapp.ErrReleaseAssertion) {
		t.Fatalf("no assertion: %v", err)
	}
	a := w.ceremony(rita, task, offer.Binding)
	other := req
	other.Basis = basis + " Checked twice."
	if _, err := rel.Release(rita.ctx, other, offer.Release.ExpiresAt, a); !errors.Is(err, txapp.ErrReleaseAssertion) || !w.spent(a) {
		t.Fatalf("an assertion over another basis: %v", err)
	}
	if _, err := rel.Release(rita.ctx, req, offer.Release.ExpiresAt, a); !errors.Is(err, txapp.ErrReleaseAssertion) {
		t.Fatalf("a spent ceremony: %v", err)
	}
	a = w.ceremony(rita, task, offer.Binding)
	if _, err := rel.Release(rita.ctx, txapp.ReleaseRequest{Reconciliation: task, Basis: basis}, offer.Release.ExpiresAt, a); !errors.Is(err, txapp.ErrReleaseAssertion) || !w.spent(a) {
		t.Fatalf("an assertion over other evidence: %v", err)
	}
	late := txdomain.Release{Reconciliation: task, Transaction: r.TransactionID, Basis: basis, Evidence: req.Evidence, ExpiresAt: time.Now().Add(-time.Second).Truncate(time.Second)}
	b, _ := late.Binding()
	a = w.ceremony(rita, task, b)
	if _, err := rel.Release(rita.ctx, req, late.ExpiresAt, a); !errors.Is(err, txapp.ErrReleaseExpired) || !w.spent(a) {
		t.Fatalf("after expiry: %v", err)
	}
	if got := w.str("SELECT state FROM pc.reconciliation_tasks WHERE id = $1", task); got != "OPEN" {
		t.Fatalf("a refused release changed the task: %s", got)
	}
	if res, sp := w.budget(); res != "30" || sp != "0" {
		t.Fatalf("a refused release moved the budget: reserved %s spent %s", res, sp)
	}

	// An exact repeat (from a run alice launched for herself, under its own
	// grant) waits while the outcome is unknown (HR-007).
	repeats := w.run(w.grant("500").ID, ids.UUID{})
	if again := w.authorize(w.request(repeats, ids.NewV7(), "ch_1", "30.00")); again.Decision != adomain.CannotAuthorize || decisive(again) != "RECONCILIATION_REQUIRED" {
		t.Fatalf("a repeat before the release: %s %s", again.Decision, decisive(again))
	}

	// The release.
	a = w.ceremony(rita, task, offer.Binding)
	k, err := rel.Release(rita.ctx, req, offer.Release.ExpiresAt, a)
	if err != nil {
		t.Fatal(err)
	}
	if k.State != txdomain.TaskNotOccurred || k.Via != txdomain.ViaPerson || k.User == nil || *k.User != rita.user || k.Basis != basis ||
		len(k.Evidence) != 1 || k.Evidence[0] != obs {
		t.Fatalf("released %+v", k)
	}
	if got := w.str(`SELECT session_id::text || ' ' || credential_id::text || ' ' || octet_length(authenticator_data) || ' ' ||
		convert_from(client_data_json, 'UTF8') || ' ' || encode(signature, 'hex') FROM pc.reconciliation_tasks WHERE id = $1`, task); got !=
		rita.session.String()+" "+rita.key.String()+` 37 {"type":"webauthn.get"} 3001` {
		t.Fatalf("the kept assertion %q", got)
	}
	if !w.spent(a) {
		t.Fatal("the ceremony was not consumed with the release")
	}
	if res, sp := w.budget(); res != "0" || sp != "0" {
		t.Fatalf("after the release: reserved %s spent %s, want released", res, sp)
	}
	if got := w.str("SELECT state FROM pc.dedupe_claims WHERE transaction_id = $1", r.TransactionID); got != "RELEASED" {
		t.Fatalf("claim %q", got)
	}
	jws := w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID)
	if pap := claims(t, jws); pap["state"] != "NONE_CONFIRMED" || pap["reason"] != "RELEASED_BY_PERSON" ||
		pap["basis"].(map[string]any)["kind"] != "person" || pap["basis"].(map[string]any)["person"] != rita.user.String() {
		t.Fatalf("effect receipt %v", pap)
	}
	if n := w.count(`SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.transaction.reconciliation_released' AND actor_id = $1`,
		rita.user.String()); n != 1 {
		t.Fatalf("%d release entries", n)
	}
	if got := w.entry(r.TransactionID); got != "APPROVED NOT_OCCURRED user:"+rita.user.String() {
		t.Fatalf("waitlist entry %q", got)
	}
	if len(told.got) != 1 || told.got[0].Type != "transaction.reconciliation_released" || told.got[0].Link != "/reconciliations/"+task.String() {
		t.Fatalf("notices %+v", told.got)
	}

	// Exactly once: a second release (another person, another ceremony)
	// changes nothing.
	ray := w.signedIn(w.person("ray"), tdomain.RoleSecurityAdmin, tdomain.Scope{})
	a = w.ceremony(ray, task, offer.Binding)
	if _, err := rel.Release(ray.ctx, req, offer.Release.ExpiresAt, a); !errors.Is(err, txapp.ErrNotOpen) || !w.spent(a) {
		t.Fatalf("a second release: %v", err)
	}
	if _, err := rel.BeginRelease(ray.ctx, req); !errors.Is(err, txapp.ErrNotOpen) {
		t.Fatalf("a second release begins: %v", err)
	}
	if res, sp := w.budget(); res != "0" || sp != "0" {
		t.Fatalf("after a second release: reserved %s spent %s", res, sp)
	}

	// An exact repeat is decided again.
	if again := w.authorize(w.request(repeats, ids.NewV7(), "ch_1", "30.00")); again.Permit == "" {
		t.Fatalf("a repeat after the release: %s %s", again.Decision, decisive(again))
	}
}

// TestT037_AnotherOrgsReconciliationIsNotFound: a Reconciler of another org
// who names this org's reconciliation (on its page, or in a release) finds
// nothing, and nothing changes.
func TestT037_AnotherOrgsReconciliationIsNotFound(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	rel := &txapp.Releases{Store: &pgtransactions.Store{Pool: w.pool}, Explorer: &txapp.Explorer{Pool: w.pool}, Effects: s}
	r, task, obs := w.unknownRefund(s, w.run(w.grant("500").ID, ids.UUID{}))

	other, user := ids.New[ids.Org](), ids.NewV7()
	exec(t, w.pool, other, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'globex')", other)
	exec(t, w.pool, other, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'mallory')", other, user)
	mallory := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: tdomain.Subject{
			Org: other, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: user},
			Bindings: []tdomain.Binding{{Role: tdomain.RoleReconciler, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: other.UUID()}}},
		},
		Credential: tapp.CredBrowserSession, Session: ids.NewV7(),
	})
	req := txapp.ReleaseRequest{Reconciliation: task, Basis: "Not in our records.", Evidence: []ids.UUID{obs}}
	if _, err := rel.View(mallory, task); !errors.Is(err, txapp.ErrReconciliationNotFound) {
		t.Fatalf("another org's page: %v", err)
	}
	if _, err := rel.BeginRelease(mallory, req); !errors.Is(err, txapp.ErrReconciliationNotFound) {
		t.Fatalf("another org begins a release: %v", err)
	}
	if _, err := rel.Release(mallory, req, time.Now().Add(time.Minute), txapp.Assertion{Ceremony: ids.NewV7()}); !errors.Is(err, txapp.ErrReconciliationNotFound) {
		t.Fatalf("another org releases: %v", err)
	}
	if got := w.str("SELECT state FROM pc.reconciliation_tasks WHERE id = $1", task); got != "OPEN" {
		t.Fatalf("task %s", got)
	}
	if res, _ := w.budget(); res != "30" {
		t.Fatalf("reserved %s for %s", res, r.TransactionID)
	}
}

// TestRace_AnUnknownOutcomeIsReleasedOnce (HR-004): two independent people
// release one unknown outcome at the same moment; exactly one release is
// recorded and the budget is released once.
func TestRace_AnUnknownOutcomeIsReleasedOnce(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	rel := &txapp.Releases{Store: &pgtransactions.Store{Pool: w.pool}, Explorer: &txapp.Explorer{Pool: w.pool}, Effects: s}
	r, task, obs := w.unknownRefund(s, w.run(w.grant("500").ID, ids.UUID{}))
	req := txapp.ReleaseRequest{Reconciliation: task, Basis: "Not in the processor's records.", Evidence: []ids.UUID{obs}}
	people := []onPage{
		w.signedIn(w.person("rita"), tdomain.RoleReconciler, tdomain.Scope{}),
		w.signedIn(w.person("ray"), tdomain.RoleSecurityAdmin, tdomain.Scope{}),
	}
	type attempt struct {
		p      onPage
		a      txapp.Assertion
		expiry time.Time
	}
	var attempts []attempt
	for _, p := range people {
		offer, err := rel.BeginRelease(p.ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		attempts = append(attempts, attempt{p: p, a: w.ceremony(p, task, offer.Binding), expiry: offer.Release.ExpiresAt})
	}
	var wg sync.WaitGroup
	errs := make([]error, len(attempts))
	for i, x := range attempts {
		wg.Go(func() { _, errs[i] = rel.Release(x.p.ctx, req, x.expiry, x.a) })
	}
	wg.Wait()
	ok, notOpen := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, txapp.ErrNotOpen):
			notOpen++
		default:
			t.Fatalf("release: %v", err)
		}
	}
	if ok != 1 || notOpen != 1 {
		t.Fatalf("%d releases, %d refused as not open", ok, notOpen)
	}
	if res, sp := w.budget(); res != "0" || sp != "0" {
		t.Fatalf("reserved %s spent %s", res, sp)
	}
	if n := w.count("SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1 AND basis = 'person'", r.TransactionID); n != 1 {
		t.Fatalf("%d person receipts", n)
	}
}

// TestHR192_TheWaitlistEntryClosesWithItsReconciliation (M5 part 2 audit
// finding F1): an unknown outcome's RECONCILIATION entry, opened by the
// gateway's report or by the sweeper, is linked to its reconciliation, and
// closes when the task resolves: CANCELLED when evidence resolves it (the
// verifier, a late report), APPROVED when a person does. (The target log's
// path is checked in TestHR112_TargetLogsFindEffectsWithoutReceipts, the
// release's in TestHR192_OnlyAnIndependentPersonReleasesWithAKeyOverTheBasis.)
func TestHR192_TheWaitlistEntryClosesWithItsReconciliation(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2", "ch_3")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})
	linked := func(txn ids.UUID) {
		t.Helper()
		if n := w.count(`SELECT count(*) FROM pc.reconciliation_tasks t JOIN pc.waitlist_entries e
			ON e.org_id = t.org_id AND e.id = t.waitlist_entry_id AND e.subject_id = t.transaction_id WHERE t.transaction_id = $1`, txn); n != 1 {
			t.Fatalf("transaction %s: the task names no entry", txn)
		}
	}

	// Reported unknown by the gateway; the verifier finds the refund.
	found := w.recorded(run, "ch_1", "30.00", finalize.Unknown, "")
	linked(found.TransactionID)
	l := w.lease(s, found.TransactionID)
	if a, err := s.Report(ctx, w.org, w.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Complete: true,
		Fields: refund("succeeded", "30.00"),
	}); err != nil || !a.Resolved {
		t.Fatalf("found: %+v %v", a, err)
	}
	if got := w.entry(found.TransactionID); got != "CANCELLED OCCURRED gateway:"+w.gwID.String() {
		t.Fatalf("after the verifier: %q", got)
	}

	// Swept, then reported accepted late.
	late := w.dispatched(run, "ch_2", "20.00")
	w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '1 minute' WHERE id = $1", late.PermitID)
	if _, unknown, err := w.auth.Sweep(ctx, w.org, 30*time.Second); err != nil || unknown != 1 {
		t.Fatalf("sweep: %d %v", unknown, err)
	}
	linked(late.TransactionID)
	if w.entry(late.TransactionID) != "OPEN" {
		t.Fatalf("swept: %q", w.entry(late.TransactionID))
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: late.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: -1}); err != nil {
		t.Fatal(err)
	}
	if got := w.entry(late.TransactionID); got != "CANCELLED OCCURRED gateway:"+w.gwID.String() {
		t.Fatalf("after the late report: %q", got)
	}

	// A person records it as occurred.
	byPerson := w.recorded(run, "ch_3", "10.00", finalize.Unknown, "")
	task, err := ids.ParseUUID(w.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1", byPerson.TransactionID))
	if err != nil {
		t.Fatal(err)
	}
	person, id := w.reconciler("rita")
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	if _, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: task, Basis: "In the processor's dashboard as re_9."}); err != nil {
		t.Fatal(err)
	}
	if got := w.entry(byPerson.TransactionID); got != "APPROVED OCCURRED user:"+id.String() {
		t.Fatalf("after the person: %q", got)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.waitlist.entry_closed'"); n != 3 {
		t.Fatalf("%d closings audited", n)
	}
}
