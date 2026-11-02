// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/app"
	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	"github.com/katocxl/pantherclaw/internal/contentsignals/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type requests struct {
	mu     sync.Mutex
	opened map[ids.UUID]protect.Request
}

func (r *requests) Open(_ context.Context, _ db.TenantTx, q protect.Request) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := ids.NewV7()
	r.opened[id] = q
	return id, nil
}

func (r *requests) Void(context.Context, db.TenantTx, ids.UUID, string) error { return nil }

func (r *requests) Pending(_ context.Context, _ db.TenantTx, id ids.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, open := r.opened[id]
	return open, nil
}

type edition struct{ e billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

type person struct {
	id, key, session ids.UUID
	ctx              context.Context
}

type env struct {
	d                        *dbtest.DB
	pool                     *db.Pool
	org                      ids.OrgID
	edition                  *edition
	gate                     *protect.Gate
	svc                      *app.Service
	alice, bob               person
	environ, agent, instance ids.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{d: d, pool: d.AppPool(t), edition: &edition{e: billing.Business}, org: ids.New[ids.Org]()}
	e.gate = &protect.Gate{Requests: &requests{opened: map[ids.UUID]protect.Request{}}}
	e.svc = &app.Service{Pool: e.pool, Editions: e.edition}
	e.svc.RegisterProtect(e.gate)
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'content')", e.org)
	e.alice, e.bob = e.person(t, "alice"), e.person(t, "bob")

	team := ids.NewV7()
	e.environ, e.agent, e.instance = ids.NewV7(), ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", e.org, team)
	e.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')", e.org, e.environ, team)
	e.exec(t, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'refund-bot', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, e.org, e.agent, team, e.environ, e.alice.id)
	e.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, e.org, e.instance, e.agent, fmt.Sprintf("%043d", time.Now().UnixNano()%1e12))
	return e
}

func (e *env) person(t *testing.T, name string) person {
	t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	e.d.AdminExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, p.id, name)
	e.d.AdminExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		e.org, ids.NewV7(), string(td.RoleSecurityAdmin), p.id)
	e.d.AdminExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		e.org, p.key, p.id, secret[:16], secret)
	e.d.AdminExec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, e.org, p.session, p.id, secret)
	e.stepUp(t, p)
	p.ctx = tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{
			Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
		},
		Credential: tapp.CredBrowserSession, Session: p.session,
	})
	return p
}

func (e *env) stepUp(t *testing.T, p person) {
	t.Helper()
	e.d.AdminExec(t, "UPDATE pc.sessions SET step_up_at = now(), step_up_credential_id = $1 WHERE id = $2", p.key, p.session)
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) confirm(held *protect.PendingError, who ids.UUID) error {
	return e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Apply(ctx, tx, held.Request, []ids.UUID{who})
	})
}

func (e *env) mode(t *testing.T) domain.Mode {
	t.Helper()
	s, err := e.svc.Get(e.alice.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return s.Mode()
}

func (e *env) set(t *testing.T, to domain.Mode) app.Result {
	t.Helper()
	r, err := e.svc.SetMode(e.alice.ctx, to, "a reason")
	if err != nil {
		t.Fatalf("to %s: %v", to, err)
	}
	return r
}

// TestHR647_ModesStartOffAndGoUpStepByStep: no row is OFF, ACTIVE is reached
// only from WATCHING, and only with a fresh step-up.
//
// Covers: F936
func TestHR647_ModesStartOffAndGoUpStepByStep(t *testing.T) {
	e := newEnv(t)
	if m := e.mode(t); m != domain.ModeOff {
		t.Fatalf("mode %s", m)
	}
	if _, err := e.svc.SetMode(e.alice.ctx, domain.ModeActive, "a reason"); !errors.Is(err, app.ErrWatchFirst) {
		t.Fatalf("OFF to ACTIVE: %v", err)
	}
	e.set(t, domain.ModeWatching)
	e.d.AdminExec(t, "UPDATE pc.sessions SET step_up_at = NULL WHERE id = $1", e.alice.session)
	if _, err := e.svc.SetMode(e.alice.ctx, domain.ModeActive, "a reason"); !errors.Is(err, rapp.ErrStepUp) {
		t.Fatalf("ACTIVE without a step-up: %v", err)
	}
	if m := e.mode(t); m != domain.ModeWatching {
		t.Fatalf("mode %s", m)
	}
	e.stepUp(t, e.alice)
	e.set(t, domain.ModeActive)
	if m := e.mode(t); m != domain.ModeActive {
		t.Fatalf("mode %s", m)
	}
}

// TestHR647_OnlyAPersonSetsAMode: a service account with the role cannot.
//
// Covers: F936
func TestHR647_OnlyAPersonSetsAMode(t *testing.T) {
	e := newEnv(t)
	svc := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	if _, err := e.svc.SetMode(svc, domain.ModeWatching, "a reason"); err == nil {
		t.Fatal("a service account set a mode")
	}
}

// TestHR652_LeavingActiveWaitsForASecondPerson: leaving ACTIVE changes
// nothing until someone other than its author confirms it, and without a Gate
// it fails closed.
//
// Covers: F936
func TestHR652_LeavingActiveWaitsForASecondPerson(t *testing.T) {
	e := newEnv(t)
	e.set(t, domain.ModeWatching)
	e.set(t, domain.ModeActive)

	nogate := &app.Service{Pool: e.pool, Editions: e.edition}
	if _, err := nogate.SetMode(e.alice.ctx, domain.ModeOff, "a reason"); !errors.Is(err, protect.ErrUnavailable) {
		t.Fatalf("without a Gate: %v", err)
	}

	r := e.set(t, domain.ModeOff)
	if r.Held == nil {
		t.Fatal("applied at once")
	}
	if m := e.mode(t); m != domain.ModeActive {
		t.Fatalf("mode %s", m)
	}
	if err := e.confirm(r.Held, e.alice.id); err == nil {
		t.Fatal("the author confirmed their own weakening")
	}
	if m := e.mode(t); m != domain.ModeActive {
		t.Fatalf("after the author's confirm: %s", m)
	}
	if err := e.confirm(r.Held, e.bob.id); err != nil {
		t.Fatalf("a second person: %v", err)
	}
	if m := e.mode(t); m != domain.ModeOff {
		t.Fatalf("after a second person: %s", m)
	}
}

// TestHR652_ALapseKeepsTheModeAndAllowsTurningOff: a lapse changes no mode, a
// way up needs Business, and the way down does not.
//
// Covers: F936
func TestHR652_ALapseKeepsTheModeAndAllowsTurningOff(t *testing.T) {
	e := newEnv(t)
	e.set(t, domain.ModeWatching)
	e.edition.e = billing.Community
	if m := e.mode(t); m != domain.ModeWatching {
		t.Fatalf("mode %s", m)
	}
	if _, err := e.svc.SetMode(e.alice.ctx, domain.ModeActive, "a reason"); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("up on a lapse: %v", err)
	}
	e.set(t, domain.ModeOff)
	if m := e.mode(t); m != domain.ModeOff {
		t.Fatalf("mode %s", m)
	}
	if _, err := e.svc.SetMode(e.alice.ctx, domain.ModeWatching, "a reason"); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("on without Business: %v", err)
	}
}

type alerts struct{ got []reflexdomain.Signal }

func (a *alerts) Raise(_ context.Context, _ pgx.Tx, s reflexdomain.Signal) (ids.UUID, error) {
	a.got = append(a.got, s)
	return ids.NewV7(), nil
}

type failures struct{ got []reflexdomain.Failure }

func (f *failures) Report(_ context.Context, _ pgx.Tx, x reflexdomain.Failure) (ids.UUID, error) {
	f.got = append(f.got, x)
	return ids.NewV7(), nil
}

func (e *env) run(t *testing.T, parent ids.UUID) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	if parent.IsZero() {
		e.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id,
			principal_source, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', now() + interval '8 hours')`,
			e.org, id, e.agent, e.instance, e.environ, e.alice.id)
		return id
	}
	e.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_instance_id, principal_user_id,
		principal_source, parent_run_id, depth, expires_at) VALUES ($1, $2, $3, $4, $5, $4, $6, 'parent_run', $7, 1, now() + interval '4 hours')`,
		e.org, id, e.agent, e.instance, e.environ, e.alice.id, parent)
	return id
}

func (e *env) observe(t *testing.T, s *app.Sink, run ids.UUID, sf ports.Surface, f ...domain.Finding) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return s.Observe(ctx, tx, app.Observed{Org: e.org, Run: run, Transaction: ids.NewV7(), Surface: sf, Findings: f})
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) flag(t *testing.T, run ids.UUID) []byte {
	t.Helper()
	var raw []byte
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		st, err := dbq.New(tx).ContentRunState(ctx, e.org, run)
		raw = st.Flag
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *env) kinds(t *testing.T, run ids.UUID) []string {
	t.Helper()
	k, _ := domain.ParseFlag(e.flag(t, run))
	return k
}

var (
	flagged = domain.Finding{Kind: domain.KindInjectionPhrase, Location: "result/a"}
	large   = domain.Finding{Kind: domain.KindScanIncomplete, Location: domain.IncompleteOverBound}
)

// TestHR648_AResultFlagLandsOnTheTreeAndCountsInWatching: at OFF nothing is
// kept; a sub-run's flag lands on its tree's root; WATCHING counts by reason
// and the settings show it; an alert is labelled inference and holds no value;
// and a scan that could not finish is one owned failure per reason.
//
// Covers: F939, F941
func TestHR648_AResultFlagLandsOnTheTreeAndCountsInWatching(t *testing.T) {
	e := newEnv(t)
	root := e.run(t, ids.UUID{})
	child := e.run(t, root)
	a, f := &alerts{}, &failures{}
	s := &app.Sink{Raiser: a, Failures: f}

	e.observe(t, s, child, ports.SurfaceResult, flagged)
	if k := e.kinds(t, root); len(k) != 0 || len(a.got) != 0 {
		t.Fatalf("OFF kept %v %v", k, a.got)
	}
	e.set(t, domain.ModeWatching)
	e.observe(t, s, child, ports.SurfaceResult, flagged, large)
	e.observe(t, s, child, ports.SurfaceResult, large)
	if k := e.kinds(t, root); !slices.Equal(k, []string{domain.KindInjectionPhrase, domain.KindScanIncomplete}) {
		t.Fatalf("root %v", k)
	}
	if k := e.kinds(t, child); len(k) != 2 {
		t.Fatalf("the child reads the root's flag: %v", k)
	}
	got, err := e.svc.Get(e.alice.ctx)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, w := range got.WouldHold {
		counts[w.Reason] = w.Count
	}
	if counts[domain.IncompleteOverBound] != 2 || counts[domain.KindInjectionPhrase] != 1 {
		t.Fatalf("would hold %v", counts)
	}
	if len(a.got) != 1 || a.got[0].Basis != reflexdomain.BasisInferred || !strings.Contains(a.got[0].Title, "inference") {
		t.Fatalf("alerts %+v", a.got)
	}
	if len(f.got) != 2 || f.got[0].DedupeKey != f.got[1].DedupeKey {
		t.Fatalf("failures %+v", f.got)
	}
}

// TestHR650_ActiveCountsNothingAndStillFails: ACTIVE holds rather than
// counts, and a scan that could not finish is an owned failure there too.
//
// Covers: F939
func TestHR650_ActiveCountsNothingAndStillFails(t *testing.T) {
	e := newEnv(t)
	run := e.run(t, ids.UUID{})
	f := &failures{}
	s := &app.Sink{Failures: f}
	e.set(t, domain.ModeWatching)
	e.set(t, domain.ModeActive)
	e.observe(t, s, run, ports.SurfaceResult, domain.Finding{Kind: domain.KindScanIncomplete, Location: domain.IncompleteClassifier})
	got, err := e.svc.Get(e.alice.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.WouldHold) != 0 || len(f.got) != 1 {
		t.Fatalf("%+v %+v", got.WouldHold, f.got)
	}
	if k := e.kinds(t, run); !slices.Equal(k, []string{domain.KindScanIncomplete}) {
		t.Fatalf("flag %v", k)
	}
}

// TestHR649_AFlagKeepsNoValue: what the fact stores is kinds, a count and a
// time, and an unknown kind from a gateway restricts as a classifier flag.
//
// Covers: F937
func TestHR649_AFlagKeepsNoValue(t *testing.T) {
	e := newEnv(t)
	run := e.run(t, ids.UUID{})
	e.set(t, domain.ModeWatching)
	e.observe(t, &app.Sink{}, run, ports.SurfaceResult, domain.Finding{Kind: "something new", Location: "result/key"})
	if k := e.kinds(t, run); !slices.Equal(k, []string{domain.KindClassifierFlag}) {
		t.Fatalf("flag %v", k)
	}
	if raw := string(e.flag(t, run)); strings.Contains(raw, "result/key") || strings.Contains(raw, "something new") {
		t.Fatalf("the fact keeps more than kinds: %s", raw)
	}
}
