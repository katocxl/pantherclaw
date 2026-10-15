// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package protect_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	rapp "github.com/katocxl/pantherclaw/internal/releases/app"
	"github.com/katocxl/pantherclaw/internal/releases/domain"
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
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{pool: d.AppPool(t), org: ids.New[ids.Org](), author: ids.NewV7(), other: ids.NewV7(), readOnly: ids.NewV7()}
	e.reqs = &requests{opened: map[ids.UUID]protect.Request{}, voided: map[ids.UUID]string{}}
	e.gate = &protect.Gate{Requests: e.reqs}
	e.pub = &protect.Publishers{Pool: e.pool, Gate: e.gate}
	e.gate.Compromise = e.pub
	e.svc = &protect.Service{Pool: e.pool, Gate: e.gate}
	e.windows = (&rapp.Service{Pool: e.pool}).WithProtect(e.gate)
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'protect')", e.org)
	for _, u := range []struct {
		id   ids.UUID
		role td.RoleName
	}{{e.author, td.RoleSecurityAdmin}, {e.other, td.RoleSecurityAdmin}, {e.readOnly, td.RoleViewer}} {
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
	cred := ids.NewV7()
	e.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name) VALUES ($1, $2, $3, decode(repeat('ab', 16), 'hex'), decode(repeat('cd', 32), 'hex'), -7, false, false,
		'none', 'k')`, e.org, cred, e.author)
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
