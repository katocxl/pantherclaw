// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package protect_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
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

// requests is an in-memory change ceremony: it records what the Gate
// opens and voids.
type requests struct {
	mu     sync.Mutex
	opened map[ids.UUID]protect.Request
	voided map[ids.UUID]string
}

func (r *requests) Open(_ context.Context, _ db.TenantTx, q protect.Request) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := ids.NewV7()
	r.opened[id] = q
	return id, nil
}

func (r *requests) Void(_ context.Context, _ db.TenantTx, id ids.UUID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.voided[id] = reason
	return nil
}

type env struct {
	pool     *db.Pool
	org      ids.OrgID
	reqs     *requests
	gate     *protect.Gate
	svc      *protect.Service
	pub      *protect.Publishers
	windows  *rapp.Service
	author   ids.UUID
	other    ids.UUID
	readOnly ids.UUID
	third    ids.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{pool: d.AppPool(t), org: ids.New[ids.Org](), author: ids.NewV7(), other: ids.NewV7(), readOnly: ids.NewV7(), third: ids.NewV7()}
	e.reqs = &requests{opened: map[ids.UUID]protect.Request{}, voided: map[ids.UUID]string{}}
	e.gate = &protect.Gate{Requests: e.reqs}
	e.pub = &protect.Publishers{Pool: e.pool, Gate: e.gate, Editions: business{}}
	e.gate.Compromise = e.pub
	e.svc = &protect.Service{Pool: e.pool, Gate: e.gate}
	e.windows = (&rapp.Service{Pool: e.pool}).WithProtect(e.gate)
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'protect')", e.org)
	for _, u := range []struct {
		id   ids.UUID
		role td.RoleName
	}{{e.author, td.RoleSecurityAdmin}, {e.other, td.RoleSecurityAdmin}, {e.readOnly, td.RoleViewer}, {e.third, td.RoleSecurityAdmin}} {
		e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, u.id, u.id.String())
		e.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			e.org, ids.NewV7(), string(u.role), u.id)
	}
	return e
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) as(user ids.UUID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession})
}

// frozen creates a window for prod with a freeze from now on.
func (e *env) frozen(t *testing.T) rapp.Record {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Minute)
	r, err := e.windows.Create(e.as(e.author, td.RoleSecurityAdmin), domain.Window{
		Environment: "prod", TimeZone: "UTC",
		Freezes: []domain.Span{{Start: now.Add(-time.Hour), End: now.Add(48 * time.Hour)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) change(t *testing.T, id ids.UUID) dbq.PcProtectedChange {
	t.Helper()
	var out dbq.PcProtectedChange
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetProtectedChange(ctx, e.org, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestGate_OffAppliesAsBefore: with the category OFF (no row), a
// freeze-dropping retirement applies at once, as without protection.
func TestGate_OffAppliesAsBefore(t *testing.T) {
	e := newEnv(t)
	w := e.frozen(t)
	r, err := e.windows.Retire(e.as(e.author, td.RoleSecurityAdmin), w.ID, "done")
	if err != nil || r.RetiredAt == nil {
		t.Fatalf("retire with the category off: %v %+v", err, r)
	}
	if len(e.reqs.opened) != 0 {
		t.Fatalf("requests opened with the category off: %d", len(e.reqs.opened))
	}
}

// TestGate_DistinctPublisherHoldsAndApplies: with CONSEQUENCE_RULES on, a
// freeze-dropping retirement is stored PENDING with a request; its author
// cannot confirm it, a viewer cannot, another holder of
// release.window.manage can; applying re-runs the retirement as the
// author. A newer change for the same window voids the older one.
// Turning the category off is itself a request.
func TestGate_DistinctPublisherHoldsAndApplies(t *testing.T) {
	e := newEnv(t)
	w := e.frozen(t)
	mgr := e.as(e.author, td.RoleSecurityAdmin)
	if _, err := e.svc.SetCategoryMode(mgr, protect.ConsequenceRules, protect.ModeDistinctPublisher); err != nil {
		t.Fatal(err)
	}
	_, err := e.windows.Retire(mgr, w.ID, "first")
	var first *protect.PendingError
	if !errors.As(err, &first) || !errors.Is(err, protect.ErrPending) {
		t.Fatalf("retire = %v, want pending", err)
	}
	_, err = e.windows.Retire(mgr, w.ID, "second")
	var held *protect.PendingError
	if !errors.As(err, &held) {
		t.Fatalf("second retire = %v, want pending", err)
	}
	if got := e.change(t, first.Change); got.State != protect.StateVoided || e.reqs.voided[first.Request] == "" {
		t.Fatalf("older change %s, request voided %q", got.State, e.reqs.voided[first.Request])
	}
	if got := e.reqs.opened[held.Request]; got.Domain != protect.DomainProtected || got.Kind != string(protect.ConsequenceRules) ||
		got.Required != 1 || got.Subject != held.Change {
		t.Fatalf("request %+v", got)
	}
	ctx := context.Background()
	err = e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		for _, c := range []struct {
			user ids.UUID
			ok   bool
			why  string
		}{{e.author, false, "SAME_PERSON"}, {e.readOnly, false, "MISSING_PERMISSION"}, {e.other, true, ""}} {
			ok, why, err := e.gate.Eligible(ctx, tx, held.Request, c.user)
			if err != nil || ok != c.ok || why != c.why {
				t.Errorf("eligible(%s) = %v %q %v, want %v %q", c.user, ok, why, err, c.ok, c.why)
			}
		}
		return e.gate.Apply(ctx, tx, held.Request, []ids.UUID{e.other})
	})
	if err != nil {
		t.Fatal(err)
	}
	got := e.change(t, held.Change)
	if got.State != protect.StateApplied || got.Publisher == nil || *got.Publisher != e.other || got.Author != e.author {
		t.Fatalf("applied change %+v", got)
	}
	list, err := e.windows.List(mgr, "prod", true)
	if err != nil || len(list) != 1 || list[0].RetiredAt == nil || list[0].RetiredBy != "user:"+e.author.String() {
		t.Fatalf("window after apply: %v %+v", err, list)
	}
	// Turning the category off waits for a second person.
	if _, err := e.svc.SetCategoryMode(mgr, protect.ConsequenceRules, protect.ModeOff); !errors.Is(err, protect.ErrPending) {
		t.Fatalf("turn off = %v, want pending", err)
	}
	st, err := e.svc.GetSettings(mgr)
	if err != nil || st[1].Category != protect.ConsequenceRules || st[1].Mode != protect.ModeDistinctPublisher {
		t.Fatalf("settings after an unconfirmed turn-off: %v %+v", err, st)
	}
}

// TestGate_CompromisedPublisherIsNotEligible: a person marked compromised
// cannot confirm a protected change, whatever permissions they hold.
func TestGate_CompromisedPublisherIsNotEligible(t *testing.T) {
	e := newEnv(t)
	w := e.frozen(t)
	mgr := e.as(e.author, td.RoleSecurityAdmin)
	if _, err := e.svc.SetCategoryMode(mgr, protect.ConsequenceRules, protect.ModeDistinctPublisher); err != nil {
		t.Fatal(err)
	}
	_, err := e.windows.Retire(mgr, w.ID, "retire")
	var held *protect.PendingError
	if !errors.As(err, &held) {
		t.Fatalf("retire = %v", err)
	}
	cred := e.key(t, e.author)
	e.exec(t, `INSERT INTO pc.compromised_publishers (org_id, id, user_id, since, reason, marked_by, marked_credential)
		VALUES ($1, $2, $3, now() - interval '1 day', 'test', $4, $5)`, e.org, ids.NewV7(), e.other, e.author, cred)
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		ok, why, err := e.gate.Eligible(ctx, tx, held.Request, e.other)
		if err != nil || ok || why != "COMPROMISED" {
			t.Errorf("eligible = %v %q %v, want COMPROMISED", ok, why, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// business is a Business licence.
type business struct{}

func (business) Current(context.Context) (bdomain.Entitlements, error) {
	return bdomain.Entitlements{Edition: bdomain.Business}, nil
}

// key gives user an active security key and returns it.
func (e *env) key(t *testing.T, user ids.UUID) ids.UUID {
	t.Helper()
	cred := ids.NewV7()
	e.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name) VALUES ($1, $2, $3, decode(md5($4) || md5($4), 'hex'), decode(repeat('cd', 32), 'hex'), -7, false, false,
		'none', 'k')`, e.org, cred, user, cred.String())
	return cred
}

// stepUp is a fresh step-up of user with a new key.
func (e *env) stepUp(t *testing.T, user ids.UUID) stepup.StepUp {
	t.Helper()
	return stepup.StepUp{Credential: e.key(t, user), At: time.Now()}
}

func (e *env) onConsequenceRules(t *testing.T) {
	t.Helper()
	if _, err := e.svc.SetCategoryMode(e.as(e.author, td.RoleSecurityAdmin), protect.ConsequenceRules, protect.ModeDistinctPublisher); err != nil {
		t.Fatal(err)
	}
}

// TestGate_OnNeedsRequests: a category is not turned on while nobody could
// confirm a change in it (D72 P6).
func TestGate_OnNeedsRequests(t *testing.T) {
	e := newEnv(t)
	svc := &protect.Service{Pool: e.pool, Gate: &protect.Gate{}}
	if _, err := svc.SetCategoryMode(e.as(e.author, td.RoleSecurityAdmin), protect.Custody, protect.ModeDistinctPublisher); !errors.Is(err, protect.ErrUnavailable) {
		t.Fatalf("turn on without requests = %v, want unavailable", err)
	}
}

// TestGate_SubjectChangedVoids: a confirmed change whose subject changed
// since it was asked is refused SUBJECT_CHANGED, so the ceremony voids it
// (D72 P5). A asks to replace window X, dropping its freeze. Meanwhile X is
// replaced by a window with one more freeze, which drops nothing and so
// applies at once.
func TestGate_SubjectChangedVoids(t *testing.T) {
	e := newEnv(t)
	x := e.frozen(t)
	e.onConsequenceRules(t)
	_, err := e.windows.Create(e.as(e.author, td.RoleSecurityAdmin), domain.Window{
		Environment: "prod", TimeZone: "UTC", Weekly: []domain.Weekly{{Day: "mon", Start: "09:00", Minutes: 60}},
	})
	var held *protect.PendingError
	if !errors.As(err, &held) {
		t.Fatalf("dropping create = %v, want pending", err)
	}
	later := time.Now().Truncate(time.Minute)
	more := append(slices.Clone(x.Freezes), domain.Span{Start: later.Add(72 * time.Hour), End: later.Add(96 * time.Hour)})
	if _, err := e.windows.Create(e.as(e.other, td.RoleSecurityAdmin), domain.Window{Environment: "prod", TimeZone: "UTC", Freezes: more}); err != nil {
		t.Fatalf("adding a freeze applies at once: %v", err)
	}
	err = e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Apply(ctx, tx, held.Request, []ids.UUID{e.third})
	})
	var ve *protect.VoidError
	if !errors.As(err, &ve) || ve.VoidReason() != protect.ReasonSubjectChanged || !errors.Is(err, protect.ErrSubjectChanged) {
		t.Fatalf("apply after the subject changed = %v, want SUBJECT_CHANGED", err)
	}
	list, err := e.windows.List(e.as(e.other, td.RoleSecurityAdmin), "prod", false)
	if err != nil || len(list) != 1 || len(list[0].Freezes) != 2 {
		t.Fatalf("the newer window stays: %v %+v", err, list)
	}
}

// TestGate_EmergencyReviewIsIndependent: an emergency change applies now
// and its review can be confirmed by neither its author nor the person who
// applied it (D72 P3), only by a third holder of the permission.
func TestGate_EmergencyReviewIsIndependent(t *testing.T) {
	e := newEnv(t)
	w := e.frozen(t)
	e.onConsequenceRules(t)
	_, err := e.windows.Retire(e.as(e.author, td.RoleSecurityAdmin), w.ID, "retire")
	var held *protect.PendingError
	if !errors.As(err, &held) {
		t.Fatalf("retire = %v", err)
	}
	if _, err := e.svc.ApplyEmergency(e.as(e.other, td.RoleSecurityAdmin), held.Request, stepup.StepUp{}); !stepup.Is(err) {
		t.Fatalf("emergency without a step-up = %v, want STEP_UP_REQUIRED", err)
	}
	c, err := e.svc.ApplyEmergency(e.as(e.other, td.RoleSecurityAdmin), held.Request, e.stepUp(t, e.other))
	if err != nil || c.State != protect.StateEmergency || c.ReviewRequestID == nil {
		t.Fatalf("emergency = %v %+v", err, c)
	}
	if e.reqs.voided[held.Request] == "" {
		t.Fatal("the pending request was not voided")
	}
	review := *c.ReviewRequestID
	err = e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		for _, u := range []ids.UUID{e.author, e.other} {
			if ok, why, err := e.gate.Eligible(ctx, tx, review, u); err != nil || ok || why != "SAME_PERSON" {
				t.Errorf("review eligible(%s) = %v %q %v", u, ok, why, err)
			}
		}
		if ok, _, err := e.gate.Eligible(ctx, tx, review, e.third); err != nil || !ok {
			t.Errorf("third eligible = %v %v", ok, err)
		}
		return e.gate.Apply(ctx, tx, review, []ids.UUID{e.third})
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.change(t, c.ID); got.ReviewedBy == nil || *got.ReviewedBy != e.third {
		t.Fatalf("reviewed %+v", got)
	}
}

// TestPublishers_MarkBlocksFilesAndReviews: marking a person voids their
// pending protected change, and they then file none (D72 P8). A reviewer
// under another active mark reviews nothing (P9); another person reviews
// KEEP. Without the edition every publisher use case is refused (P11).
func TestPublishers_MarkBlocksFilesAndReviews(t *testing.T) {
	e := newEnv(t)
	w := e.frozen(t)
	e.onConsequenceRules(t)
	_, err := e.windows.Retire(e.as(e.author, td.RoleSecurityAdmin), w.ID, "retire")
	var held *protect.PendingError
	if !errors.As(err, &held) {
		t.Fatalf("retire = %v", err)
	}
	kid := "org-packages-" + strings.Repeat("A", 22)
	e.exec(t, `INSERT INTO pc.package_signing_keys (org_id, id, kid, public_key, name, state, created_by)
		VALUES ($1, $2, $3, decode(repeat('ab', 32), 'hex'), 'k', 'ACTIVE', $4)`, e.org, ids.NewV7(), kid, "user:"+e.author.String())
	marker := e.as(e.other, td.RoleSecurityAdmin)
	mark, err := e.pub.MarkCompromised(marker, e.author, time.Now().Add(-time.Hour), "phished", e.stepUp(t, e.other))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.change(t, held.Change); got.State != protect.StateVoided || e.reqs.voided[held.Request] == "" {
		t.Fatalf("pending change after the mark: %s", got.State)
	}
	if _, err := e.windows.Retire(e.as(e.author, td.RoleSecurityAdmin), w.ID, "again"); !errors.Is(err, protect.ErrCompromised) {
		t.Fatalf("compromised author files = %v, want PUBLISHER_COMPROMISED", err)
	}
	if _, err := e.pub.MarkCompromised(marker, e.third, time.Now().Add(-time.Hour), "also", e.stepUp(t, e.other)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pub.ReviewExposed(e.as(e.third, td.RoleSecurityAdmin), mark.ID, protect.ItemPackageKey, kid, protect.DecisionKeep, ""); !errors.Is(err, protect.ErrCompromised) {
		t.Fatalf("marked reviewer = %v, want PUBLISHER_COMPROMISED", err)
	}
	if _, err := e.pub.ReviewExposed(marker, mark.ID, protect.ItemPackageKey, kid, protect.DecisionRollback, ""); !errors.Is(err, protect.ErrNoRollback) {
		t.Fatalf("rollback without a path = %v, want ROLLBACK_UNAVAILABLE", err)
	}
	item, err := e.pub.ReviewExposed(marker, mark.ID, protect.ItemPackageKey, kid, protect.DecisionKeep, "rotated already")
	if err != nil || item.Review == nil || item.Review.Decision != protect.DecisionKeep {
		t.Fatalf("keep = %v %+v", err, item)
	}
	community := &protect.Publishers{Pool: e.pool, Gate: e.gate}
	if _, err := community.List(marker, false, 10); !errors.Is(err, protect.ErrEdition) {
		t.Fatalf("list without the edition = %v", err)
	}
}
