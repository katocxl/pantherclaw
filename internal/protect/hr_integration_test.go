// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package protect_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	rapp "github.com/katocxl/pantherclaw/internal/releases/app"
	"github.com/katocxl/pantherclaw/internal/releases/domain"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// person is a signed-in person with a security key: page is their
// browser session (where confirmations happen), cli their API session.
type person struct {
	id, key, session ids.UUID
	page, cli        context.Context
}

// hr is protect wired to the real change ceremony (internal/changes).
type hr struct {
	t       *testing.T
	pool    *db.Pool
	org     ids.OrgID
	changes *changes.Service
	gate    *protect.Gate
	svc     *protect.Service
	pub     *protect.Publishers
	windows *rapp.Service
}

func newHR(t *testing.T) *hr {
	t.Helper()
	e := &hr{t: t, pool: dbtest.New(t).AppPool(t), org: ids.New[ids.Org]()}
	e.changes = changes.New(e.pool, "https://pc.test")
	e.gate = &protect.Gate{Requests: protect.Ceremony{Changes: e.changes}}
	e.pub = &protect.Publishers{Pool: e.pool, Gate: e.gate, Editions: business{}, Undo: map[string]protect.Rollback{}}
	e.gate.Compromise = e.pub
	e.changes.Compromise = e.pub
	e.pub.On = append(e.pub.On, func(ctx context.Context, tx db.TenantTx, user ids.UUID, _ time.Time, by tapp.Caller) (map[string]string, error) {
		_, err := e.changes.VoidByPerson(ctx, tx, by, user, "PUBLISHER_COMPROMISED")
		return nil, err
	})
	protect.Register(e.changes, e.gate, e.pub)
	e.svc = &protect.Service{Pool: e.pool, Gate: e.gate}
	e.windows = (&rapp.Service{Pool: e.pool}).WithProtect(e.gate)
	e.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'protect-hr')", e.org)
	return e
}

func (e *hr) exec(sql string, args ...any) {
	e.t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *hr) person(name string, role td.RoleName) person {
	e.t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	e.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, p.id, name)
	e.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		e.org, p.key, p.id, secret[:16], secret)
	e.exec(`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, e.org, p.session, p.id, secret)
	e.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		e.org, ids.NewV7(), string(role), p.id)
	sub := td.Subject{Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}}}
	p.page = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredBrowserSession, Session: p.session})
	p.cli = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredAccessToken, Session: ids.NewV7()})
	return p
}

// confirm signs the request's binding with p's key on their page and
// confirms it.
func (e *hr) confirm(p person, id ids.UUID) (changes.Request, error) {
	e.t.Helper()
	r, err := e.changes.Get(p.page, id)
	if err != nil {
		return r, err
	}
	cer := ids.NewV7()
	e.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, e.org, cer, p.session, p.id, r.Binding[:], r.ID)
	return e.changes.Confirm(p.page, id, changes.Assertion{Ceremony: cer, Credential: p.key})
}

func (e *hr) stepUp(p person) stepup.StepUp { return stepup.StepUp{Credential: p.key, At: time.Now()} }

func (e *hr) row(id ids.UUID) dbq.PcProtectedChange {
	e.t.Helper()
	var out dbq.PcProtectedChange
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetProtectedChange(ctx, e.org, id)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// frozen is a prod window with a freeze running now.
func (e *hr) frozen(p person) rapp.Record {
	e.t.Helper()
	now := time.Now().UTC().Truncate(time.Minute)
	w, err := e.windows.Create(p.cli, domain.Window{Environment: "prod", TimeZone: "UTC",
		Freezes: []domain.Span{{Start: now.Add(-time.Hour), End: now.Add(48 * time.Hour)}}})
	if err != nil {
		e.t.Fatal(err)
	}
	return w
}

func (e *hr) protectRules(p person) {
	e.t.Helper()
	if _, err := e.svc.SetCategoryMode(p.cli, protect.ConsequenceRules, protect.ModeDistinctPublisher); err != nil {
		e.t.Fatal(err)
	}
}

// TestHR292_AWideningChangeWaitsForADistinctPublisher: with
// CONSEQUENCE_RULES on, retiring a window with a current freeze is stored
// with a change request and applies only when a different person holding
// release.window.manage confirms it with a security key; the author and a
// person without the permission cannot. The applied change records author
// and publisher, and the window is retired as the author. Turning the
// category off is itself such a request.
func TestHR292_AWideningChangeWaitsForADistinctPublisher(t *testing.T) {
	e := newHR(t)
	alice, bob := e.person("alice", td.RoleSecurityAdmin), e.person("bob", td.RoleSecurityAdmin)
	viewer := e.person("vic", td.RoleViewer)
	w := e.frozen(alice)
	e.protectRules(alice)
	_, err := e.windows.Retire(alice.cli, w.ID, "freeze no longer needed")
	var held *protect.PendingError
	if !errors.As(err, &held) || !errors.Is(err, protect.ErrPending) {
		t.Fatalf("retire = %v, want PROTECTED_CHANGE_PENDING", err)
	}
	if ws, _ := e.windows.List(alice.cli, "prod", false); len(ws) != 1 {
		t.Fatalf("the window was retired before confirmation: %+v", ws)
	}
	if _, err := e.confirm(alice, held.Request); !errors.Is(err, changes.ErrSamePerson) && !errors.Is(err, changes.ErrNotEligible) {
		t.Fatalf("author confirms = %v", err)
	}
	if _, err := e.confirm(viewer, held.Request); err == nil {
		t.Fatal("a person without release.window.manage confirmed")
	}
	r, err := e.confirm(bob, held.Request)
	if err != nil || r.State != changes.StateApproved {
		t.Fatalf("bob confirms = %v %s", err, r.State)
	}
	got := e.row(held.Change)
	if got.State != protect.StateApplied || got.Author != alice.id || got.Publisher == nil || *got.Publisher != bob.id {
		t.Fatalf("applied change %+v", got)
	}
	ws, _ := e.windows.List(alice.cli, "prod", true)
	if len(ws) != 1 || ws[0].RetiredAt == nil || ws[0].RetiredBy != "user:"+alice.id.String() {
		t.Fatalf("window after confirmation %+v", ws)
	}
	// Turning the category off waits for a second person too.
	_, err = e.svc.SetCategoryMode(alice.cli, protect.ConsequenceRules, protect.ModeOff)
	var off *protect.PendingError
	if !errors.As(err, &off) {
		t.Fatalf("turn off = %v", err)
	}
	if _, err := e.confirm(bob, off.Request); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.GetSettings(alice.cli)
	if st[1].Mode != protect.ModeOff {
		t.Fatalf("settings %+v", st)
	}
}

// TestHR292_EmergencyChangeAppliesNowAndIsReviewedIndependently: a person
// holding incident.respond applies a pending change at once with a
// step-up. It is recorded EMERGENCY, its request is voided, and a review
// request that stays open 72 hours (D74) can be confirmed by neither the
// author nor the person who applied it. A declined change can no longer
// be applied in an emergency (D72 P2).
func TestHR292_EmergencyChangeAppliesNowAndIsReviewedIndependently(t *testing.T) {
	e := newHR(t)
	alice, bob, carol := e.person("alice", td.RoleSecurityAdmin), e.person("bob", td.RoleSecurityAdmin), e.person("carol", td.RoleSecurityAdmin)
	w := e.frozen(alice)
	e.protectRules(alice)
	_, err := e.windows.Retire(alice.cli, w.ID, "emergency release")
	var held *protect.PendingError
	if !errors.As(err, &held) {
		t.Fatalf("retire = %v", err)
	}
	c, err := e.svc.ApplyEmergency(bob.page, held.Request, e.stepUp(bob))
	if err != nil || c.State != protect.StateEmergency || c.ReviewRequestID == nil {
		t.Fatalf("emergency = %v %+v", err, c)
	}
	if r, _ := e.changes.Get(alice.page, held.Request); r.State != changes.StateVoided {
		t.Fatalf("the change's request is %s, want VOIDED", r.State)
	}
	review, err := e.changes.Get(carol.page, *c.ReviewRequestID)
	if err != nil || review.ExpiresAt.Sub(review.CreatedAt) != 72*time.Hour {
		t.Fatalf("review request %v %+v", err, review)
	}
	for _, p := range []person{alice, bob} {
		if _, err := e.confirm(p, review.ID); err == nil {
			t.Fatal("the author or the emergency publisher reviewed it")
		}
	}
	if _, err := e.confirm(carol, review.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.row(c.ID); got.ReviewedBy == nil || *got.ReviewedBy != carol.id {
		t.Fatalf("reviewed %+v", got)
	}
	// A declined change follows its request and is not applied later.
	w2 := e.frozen(alice)
	_, err = e.windows.Retire(alice.cli, w2.ID, "again")
	var second *protect.PendingError
	if !errors.As(err, &second) {
		t.Fatalf("second retire = %v", err)
	}
	if _, err := e.changes.Decline(bob.page, second.Request, "not now"); err != nil {
		t.Fatal(err)
	}
	if got := e.row(second.Change); got.State != protect.StateDeclined {
		t.Fatalf("declined change is %s", got.State)
	}
	if _, err := e.svc.ApplyEmergency(bob.page, second.Request, e.stepUp(bob)); !errors.Is(err, protect.ErrState) {
		t.Fatalf("emergency on a declined change = %v, want refused", err)
	}
}

// TestHR293_ACompromisedPublisherIsStoppedListedAndClearedByTwo: marking
// Mallory compromised (step-up) voids her pending request and blocks her
// confirming others' (a valid signature never exempts); what she published
// since the mark's time is listed and reviewed by someone else; clearing
// needs every item reviewed and two other people.
func TestHR293_ACompromisedPublisherIsStoppedListedAndClearedByTwo(t *testing.T) {
	e := newHR(t)
	alice, bob := e.person("alice", td.RoleSecurityAdmin), e.person("bob", td.RoleSecurityAdmin)
	carol, mallory := e.person("carol", td.RoleSecurityAdmin), e.person("mallory", td.RoleSecurityAdmin)
	e.protectRules(alice)
	// Mallory publishes alice's change, then asks for one of her own.
	w := e.frozen(alice)
	_, err := e.windows.Retire(alice.cli, w.ID, "retire")
	var published *protect.PendingError
	if !errors.As(err, &published) {
		t.Fatal(err)
	}
	if _, err := e.confirm(mallory, published.Request); err != nil {
		t.Fatal(err)
	}
	w2 := e.frozen(mallory)
	_, err = e.windows.Retire(mallory.cli, w2.ID, "mine")
	var hers *protect.PendingError
	if !errors.As(err, &hers) {
		t.Fatal(err)
	}
	w3 := e.frozen(alice)
	_, err = e.windows.Retire(alice.cli, w3.ID, "another")
	var other *protect.PendingError
	if !errors.As(err, &other) {
		t.Fatal(err)
	}
	if _, err := e.pub.MarkCompromised(bob.cli, mallory.id, time.Now().Add(-time.Hour), "phished", stepup.StepUp{}); !stepup.Is(err) {
		t.Fatalf("mark without a step-up = %v", err)
	}
	mark, err := e.pub.MarkCompromised(bob.page, mallory.id, time.Now().Add(-time.Hour), "phished", e.stepUp(bob))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := e.changes.Get(alice.page, hers.Request); r.State != changes.StateVoided {
		t.Fatalf("her pending request is %s", r.State)
	}
	if _, err := e.confirm(mallory, other.Request); !errors.Is(err, changes.ErrCompromised) {
		t.Fatalf("compromised confirmer = %v, want PUBLISHER_COMPROMISED", err)
	}
	cp, err := e.pub.Get(bob.cli, mark.ID)
	if err != nil || len(cp.Items) != 1 || cp.Items[0].Kind != protect.ItemProtectedChange || cp.Items[0].ID != published.Change.String() {
		t.Fatalf("exposure %v %+v", err, cp.Items)
	}
	if _, err := e.pub.ClearCompromise(bob.cli, mark.ID); !errors.Is(err, protect.ErrUnreviewed) {
		t.Fatalf("clear before review = %v", err)
	}
	if _, err := e.pub.ReviewExposed(mallory.cli, mark.ID, protect.ItemProtectedChange, published.Change.String(), protect.DecisionKeep, ""); err == nil {
		t.Fatal("mallory reviewed her own item")
	}
	if _, err := e.pub.ReviewExposed(carol.cli, mark.ID, protect.ItemProtectedChange, published.Change.String(), protect.DecisionKeep, "checked"); err != nil {
		t.Fatal(err)
	}
	req, err := e.pub.ClearCompromise(bob.cli, mark.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.confirm(mallory, req); err == nil {
		t.Fatal("mallory confirmed her own clearing")
	}
	if _, err := e.confirm(bob, req); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.pub.Get(bob.cli, mark.ID); got.State != protect.CompromiseActive {
		t.Fatal("one confirmation cleared the mark")
	}
	if r, err := e.confirm(carol, req); err != nil || r.State != changes.StateApproved {
		t.Fatalf("second confirmation %v %s", err, r.State)
	}
	if got, _ := e.pub.Get(bob.cli, mark.ID); got.State != protect.CompromiseCleared {
		t.Fatalf("mark is %s after two confirmations", got.State)
	}
}

// TestT129_AConfirmationNeverAppliesAnUnreviewedChange: a publisher's
// confirmation of a change whose subject changed since it was asked voids
// the request instead of applying it (D72 P5), and the change follows it.
func TestT129_AConfirmationNeverAppliesAnUnreviewedChange(t *testing.T) {
	e := newHR(t)
	alice, bob := e.person("alice", td.RoleSecurityAdmin), e.person("bob", td.RoleSecurityAdmin)
	x := e.frozen(alice)
	e.protectRules(alice)
	_, err := e.windows.Create(alice.cli, domain.Window{
		Environment: "prod", TimeZone: "UTC", Weekly: []domain.Weekly{{Day: "mon", Start: "09:00", Minutes: 60}},
	})
	var held *protect.PendingError
	if !errors.As(err, &held) {
		t.Fatalf("create = %v", err)
	}
	later := time.Now().UTC().Truncate(time.Minute)
	if _, err := e.windows.Create(bob.cli, domain.Window{Environment: "prod", TimeZone: "UTC",
		Freezes: append(x.Freezes, domain.Span{Start: later.Add(72 * time.Hour), End: later.Add(96 * time.Hour)})}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.confirm(bob, held.Request); !errors.Is(err, changes.ErrVoided) {
		t.Fatalf("confirm after the subject changed = %v, want CHANGE_VOIDED", err)
	}
	if got := e.row(held.Change); got.State != protect.StateVoided {
		t.Fatalf("change is %s", got.State)
	}
	ws, _ := e.windows.List(bob.cli, "prod", false)
	if len(ws) != 1 || len(ws[0].Freezes) != 2 {
		t.Fatalf("windows %+v", ws)
	}
}
