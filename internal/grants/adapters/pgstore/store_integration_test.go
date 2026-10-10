// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

type allow struct{}

func (allow) Require(tapp.Caller, tdomain.Permission, tdomain.Path) error { return nil }

type noDefs struct{}

func (noDefs) Active(context.Context, ids.OrgID, string) (*defs.Definition, error) { return nil, nil } //nolint:nilnil // none

type world struct {
	t        *testing.T
	pool     *db.Pool
	store    *pgstore.Store
	svc      *app.Service
	org      ids.OrgID
	alice    ids.UUID
	agent    ids.UUID
	instance ids.UUID
	env      ids.UUID
	ctx      context.Context
}

func exec(t *testing.T, p *db.Pool, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func newWorld(t *testing.T, p *db.Pool) *world {
	t.Helper()
	w := &world{t: t, pool: p, store: &pgstore.Store{Pool: p}, org: ids.New[ids.Org](), alice: ids.NewV7(), agent: ids.NewV7(), instance: ids.NewV7(), env: ids.NewV7()}
	team := ids.NewV7()
	exec(t, p, w.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	if err := p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertContainment(ctx, w.org)
	}); err != nil {
		t.Fatal(err)
	}
	exec(t, p, w.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", w.org, team)
	exec(t, p, w.org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')", w.org, w.env, team)
	exec(t, p, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.alice)
	exec(t, p, w.org, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'refund-bot', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, w.org, w.agent, team, w.env, w.alice)
	exec(t, p, w.org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, w.instance, w.agent, fmt.Sprintf("%043d", time.Now().UnixNano()%1e12))
	w.svc = &app.Service{Repo: w.store, Subjects: w.store, Defs: noDefs{}, Authz: allow{}, Clock: clock.System{}}
	w.ctx = tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: w.alice}}})
	return w
}

func (w *world) issue(maxChildren int) domain.Grant {
	w.t.Helper()
	b, _ := domain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"], "targets": {"payments.charge": {"prefixes": ["ch_"]}}}`))
	g, err := w.svc.Issue(w.ctx, app.IssueRequest{
		AgentID: w.agent, Principal: domain.Principal{Kind: domain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Delegation: domain.Delegation{Depth: 2, MaxChildren: maxChildren},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return g
}

// run inserts an active run; a child run has a parent and no grant yet.
func (w *world) run(grant domain.GrantID, parent ids.UUID) ids.UUID {
	w.t.Helper()
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

func (w *world) delegate(parentRun ids.UUID, depth int) (domain.Grant, error) {
	child := w.run(domain.GrantID{}, parentRun)
	maxChildren := 0
	if depth > 0 {
		maxChildren = 1
	}
	return w.svc.Delegate(context.Background(), app.Workload{Org: w.org, InstanceID: w.instance, RunID: parentRun},
		app.DelegateRequest{ChildRunID: child, Delegation: domain.Delegation{Depth: depth, MaxChildren: maxChildren}})
}

func (w *world) epoch() int64 {
	var e int64
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", w.org).Scan(&e)
	}); err != nil {
		w.t.Fatal(err)
	}
	return e
}

// orphans counts active grants under a revoked ancestor.
func (w *world) orphans() int {
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pc.grants g
			JOIN pc.grant_lineage l ON l.org_id = g.org_id AND l.grant_id = g.id
			JOIN pc.grants a ON a.org_id = l.org_id AND a.id = l.ancestor_id
			WHERE g.state = 'ACTIVE' AND a.state = 'REVOKED'`).Scan(&n)
	}); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func TestIntGrantsRoundTripAndRevisions(t *testing.T) {
	w := newWorld(t, dbtest.New(t).AppPool(t))
	g := w.issue(3)
	v, err := w.svc.Get(w.ctx, g.ID)
	if err != nil || len(v.Lineage) != 1 || v.Grant.Revision != 1 || v.Grant.Bounds.Operations == nil {
		t.Fatalf("Get = %+v %v", v, err)
	}
	before := w.epoch()
	narrowed := g.Bounds
	narrowed.Targets = &map[string]domain.Match{"payments.charge": {IDs: []string{"ch_1"}}}
	next, rev, err := w.svc.Revise(w.ctx, app.ReviseRequest{ID: g.ID, Revision: 1, Bounds: narrowed, Delegation: g.Delegation})
	if err != nil || rev.Widens || next.Revision != 2 || w.epoch() != before+1 {
		t.Fatalf("narrowing: %+v %+v %v (epoch %d → %d)", next, rev, err, before, w.epoch())
	}
	if got, _ := w.store.Grant(context.Background(), w.org, g.ID); got.Revision != 2 || got.Bounds.Within(narrowed) != nil || narrowed.Within(got.Bounds) != nil {
		t.Fatalf("stored revision %+v", got)
	}
	if _, _, err := w.svc.Revise(w.ctx, app.ReviseRequest{ID: g.ID, Revision: 1, Bounds: narrowed, Delegation: g.Delegation}); !errors.Is(err, app.ErrRevisionChanged) {
		t.Fatalf("a stale revision: %v", err)
	}
	other := ids.New[ids.Org]()
	exec(t, w.pool, other, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other)
	if _, err := w.store.Grant(context.Background(), other, g.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("another org read the grant: %v", err)
	}
}

func TestHR047_RevocationCascadesInOneTransaction(t *testing.T) {
	w := newWorld(t, dbtest.New(t).AppPool(t))
	root := w.issue(5)
	rootRun := w.run(root.ID, ids.UUID{})
	child, err := w.delegate(rootRun, 1)
	if err != nil {
		t.Fatal(err)
	}
	childRun := ids.UUID{}
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.runs WHERE org_id = $1 AND grant_id = $2", w.org, child.ID.UUID()).Scan(&childRun)
	}); err != nil {
		t.Fatal(err)
	}
	grandchild, err := w.delegate(childRun, 0)
	if err != nil {
		t.Fatal(err)
	}
	if chain, _ := w.store.Chain(context.Background(), w.org, grandchild.ID); len(chain) != 3 || chain[0].ID != root.ID || chain[2].Depth != 2 {
		t.Fatalf("chain %+v", chain)
	}
	before := w.epoch()
	revoked, err := w.svc.Revoke(w.ctx, root.ID, "task finished")
	if err != nil || len(revoked) != 3 {
		t.Fatalf("revoked %v, %v", revoked, err)
	}
	if w.epoch() != before+1 || w.orphans() != 0 {
		t.Fatalf("epoch %d → %d, orphans %d", before, w.epoch(), w.orphans())
	}
}

// TestHR047_DelegationRacingRevocationLeavesNoOrphan: delegations that race
// a revocation either commit first and are revoked with their parent, or see
// the parent revoked; no active grant is ever left under a revoked one.
func TestHR047_DelegationRacingRevocationLeavesNoOrphan(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	for round := range 5 {
		w := newWorld(t, p)
		root := w.issue(10)
		rootRun := w.run(root.ID, ids.UUID{})
		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() { _, _ = w.delegate(rootRun, 0) })
		}
		wg.Go(func() {
			if _, err := w.svc.Revoke(w.ctx, root.ID, "race"); err != nil {
				t.Errorf("round %d: revoke: %v", round, err)
			}
		})
		wg.Wait()
		if n := w.orphans(); n != 0 {
			t.Fatalf("round %d: %d active grants under a revoked parent", round, n)
		}
	}
}

func TestHR047_ConcurrentDelegationsRespectFanOutInTheDatabase(t *testing.T) {
	w := newWorld(t, dbtest.New(t).AppPool(t))
	root := w.issue(3)
	rootRun := w.run(root.ID, ids.UUID{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 12 {
		wg.Go(func() {
			if _, err := w.delegate(rootRun, 0); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 3 {
		t.Fatalf("%d delegations succeeded, want the fan-out of 3", ok)
	}
	if active, total, err := w.store.ChildCounts(context.Background(), w.org, root.ID, time.Now()); err != nil || active != 3 || total != 3 {
		t.Fatalf("counts %d %d %v", active, total, err)
	}
}

func TestIntGuardrailRevisions(t *testing.T) {
	w := newWorld(t, dbtest.New(t).AppPool(t))
	org := domain.Scope{Kind: domain.ScopeOrg}
	two := 2
	week := 7 * 24 * time.Hour
	b, _ := domain.DecodeBounds([]byte(`{"operations": ["payments.*"]}`))
	before := w.epoch()
	e, _, err := w.svc.PutEnvelope(w.ctx, app.EnvelopeRequest{
		Scope: org, Name: "org", Bounds: b,
		Settings: domain.Settings{MaxDepth: &two, MaxRootLifetime: &week}, MinAttestation: 1,
	})
	if err != nil || w.epoch() != before+1 {
		t.Fatalf("create: %v (epoch %d → %d)", err, before, w.epoch())
	}
	got, err := w.svc.Envelope(w.ctx, org)
	if err != nil || got.ID != e.ID || *got.Settings.MaxDepth != 2 || *got.Settings.MaxRootLifetime != week || got.MinAttestation != 1 {
		t.Fatalf("read back %+v %v", got, err)
	}
	if _, _, err := w.svc.PutEnvelope(w.ctx, app.EnvelopeRequest{Scope: org, Name: "org"}); !errors.Is(err, app.ErrRevisionChanged) {
		t.Fatalf("a stale revision: %v", err)
	}
	if _, ch, err := w.svc.PutEnvelope(w.ctx, app.EnvelopeRequest{Scope: org, Revision: 1, Name: "org"}); err != nil || !ch.Widens {
		t.Fatalf("widening: %+v %v", ch, err)
	}
	team := domain.Scope{Kind: domain.ScopeTeam, ID: ids.NewV7()}
	if _, _, err := w.svc.PutEnvelope(w.ctx, app.EnvelopeRequest{Scope: team, Name: "ghost"}); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("a guardrail for a team that does not exist: %v", err)
	}
}

// TestHR176_ARevisionAnswersAnAccessRequest: a revision citing the grant's
// open access request closes it as APPROVED in the same transaction; one
// citing anything else fails and stores no revision.
func TestHR176_ARevisionAnswersAnAccessRequest(t *testing.T) {
	w := newWorld(t, dbtest.New(t).AppPool(t))
	g := w.issue(3)
	run := w.run(g.ID, ids.UUID{})
	entry, err := waitlist.NewWriter(w.pool).RequestAccess(w.ctx, run, "refunds over 50 USD for ticket 77", nil)
	if err != nil || entry.State != "OPEN" || entry.SubjectID != g.ID.UUID() {
		t.Fatalf("request: %+v, %v", entry, err)
	}
	if _, _, err := w.svc.Revise(w.ctx, app.ReviseRequest{
		ID: g.ID, Revision: 1, Bounds: g.Bounds, Delegation: g.Delegation,
		AccessRequest: ids.NewV7(),
	}); !errors.Is(err, app.ErrAccessRequestNotOpen) {
		t.Fatalf("an unknown access request: %v", err)
	}
	if got, _ := w.store.Grant(context.Background(), w.org, g.ID); got.Revision != 1 {
		t.Fatalf("a failed revision was stored: %d", got.Revision)
	}
	if _, _, err := w.svc.Revise(w.ctx, app.ReviseRequest{
		ID: g.ID, Revision: 1, Bounds: g.Bounds, Delegation: g.Delegation,
		AccessRequest: entry.ID,
	}); err != nil {
		t.Fatal(err)
	}
	var state, by, reason string
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state, decided_by, decision_reason FROM pc.waitlist_entries WHERE id = $1", entry.ID).Scan(&state, &by, &reason)
	}); err != nil || state != "APPROVED" || by != "user:"+w.alice.String() || reason != "revision 2" {
		t.Fatalf("the answered request: %s %s %q, %v", state, by, reason, err)
	}
	if _, _, err := w.svc.Revise(w.ctx, app.ReviseRequest{
		ID: g.ID, Revision: 2, Bounds: g.Bounds, Delegation: g.Delegation,
		AccessRequest: entry.ID,
	}); !errors.Is(err, app.ErrAccessRequestNotOpen) {
		t.Fatalf("a closed access request: %v", err)
	}
}
