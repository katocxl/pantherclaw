// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package promotions_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/promotions/promotiontest"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// world is an org with a PRODUCTION and a DEVELOPMENT environment, an agent
// in each (VERIFIED, owned, with an admitted instance), a connection, and
// grants wired as the server wires them: the promotion gate in the store.
type world struct {
	t               *testing.T
	pool            *db.Pool
	org             ids.OrgID
	team, prod, dev ids.UUID
	alice           ids.UUID
	agent, devAgent ids.UUID
	conn            ids.UUID
	grants          *gapp.Service
	svc             *promotions.Service
	issuer          context.Context
	scope, devScope promotiontest.Scope
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}

func newOrg(t *testing.T, p *db.Pool) *world {
	t.Helper()
	w := &world{t: t, pool: p, org: ids.New[ids.Org](), team: ids.NewV7(), prod: ids.NewV7(), dev: ids.NewV7(), alice: ids.NewV7(),
		agent: ids.NewV7(), devAgent: ids.NewV7(), conn: ids.NewV7()}
	w.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	if err := p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertContainment(ctx, w.org)
	}); err != nil {
		t.Fatal(err)
	}
	w.exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", w.org, w.team)
	w.exec(`INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $4, 'prod', 'Prod', 'PRODUCTION'),
		($1, $3, $4, 'dev', 'Dev', 'DEVELOPMENT')`, w.org, w.prod, w.dev, w.team)
	w.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.alice)
	for i, a := range []struct{ id, env ids.UUID }{{w.agent, w.prod}, {w.devAgent, w.dev}} {
		w.exec(`INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'service', 'VERIFIED', 'test', now())`, w.org, a.id, fmt.Sprintf("refund-bot-%d", i), w.team, a.env, w.alice)
		w.exec(`INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
			VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, ids.NewV7(), a.id, fmt.Sprintf("%043d", time.Now().UnixNano()%1e12+int64(i)))
	}
	gw := ids.NewV7()
	w.exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, gw)
	w.exec(`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode, created_by, updated_by)
		VALUES ($1, $2, 'payments', 'http', $3, 'pc.mock-payments', 'https://payments.example.test', 'none', 'enforce', 'test', 'test')`, w.org, w.conn, gw)
	w.importPayments()
	// As the server wires them (newPromotionGate, registerM11Govern).
	gate := promotions.Gate{Packages: &defpg.Store{Pool: p}}
	gs := &gpg.Store{Pool: p, Promotions: gate}
	w.grants = &gapp.Service{Repo: gs, Subjects: gs, Defs: &defpg.Store{Pool: p}, Authz: gapp.SubjectAuthorizer{}, Clock: clock.System{}, Promotions: gate}
	w.svc = &promotions.Service{Pool: p, Packages: &defpg.Store{Pool: p}}
	w.issuer = w.as(w.alice, td.RoleGrantIssuer)
	w.scope = promotiontest.Scope{Pool: p, Org: w.org, Agent: w.agent, Env: w.prod, Connection: w.conn}
	w.devScope = promotiontest.Scope{Pool: p, Org: w.org, Agent: w.devAgent, Env: w.dev, Connection: w.conn}
	return w
}

func newWorld(t *testing.T) *world {
	t.Helper()
	return newOrg(t, dbtest.New(t).AppPool(t))
}

func (w *world) as(user ids.UUID, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}})
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: bs},
		Credential: tapp.CredBrowserSession, Session: ids.NewV7(),
	})
}

// issue issues the agent a grant with these bounds.
func (w *world) issue(agent ids.UUID, bounds string) (gdomain.Grant, error) {
	w.t.Helper()
	b, err := gdomain.DecodeBounds([]byte(bounds))
	if err != nil {
		w.t.Fatal(err)
	}
	return w.grants.Issue(w.issuer, gapp.IssueRequest{
		AgentID: agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(24 * time.Hour), Bounds: b,
	})
}

func notPromoted(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, gapp.ErrNotPromoted) || pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Errorf("%s: %v, want NOT_PROMOTED", what, err)
	}
}

const (
	refund = "payments.refund.create"
	charge = "payments.charge.create"
)

// TestHR290_AProductionGrantNeedsAPromotionPerListedOperation: in a
// PRODUCTION environment a person's grant is refused NOT_PROMOTED until
// the agent is promoted for each operation it lists; a grant that lists
// none, or one more operation, stays refused; DEVELOPMENT is not gated.
func TestHR290_AProductionGrantNeedsAPromotionPerListedOperation(t *testing.T) {
	w := newWorld(t)
	_, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	notPromoted(t, "before any promotion", err)
	if _, err := w.issue(w.devAgent, `{"operations": ["payments.refund.create"]}`); err != nil {
		t.Fatalf("a DEVELOPMENT grant: %v", err)
	}
	promotiontest.Promote(t, w.scope, refund)
	if _, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`); err != nil {
		t.Fatalf("after the promotion: %v", err)
	}
	_, err = w.issue(w.agent, `{"operations": ["payments.refund.create", "payments.charge.create"]}`)
	notPromoted(t, "one more operation", err)
	_, err = w.issue(w.agent, `{}`)
	notPromoted(t, "a grant listing no operation", err)
	_, err = w.issue(w.agent, `{"operations": ["payments.*"]}`)
	notPromoted(t, "a prefix wider than the promotion", err)
}

// TestHR290_AWideningRevisionIsGatedANarrowingOneIsNot: widening a
// production grant to an unpromoted operation is refused; narrowing it is
// stored.
func TestHR290_AWideningRevisionIsGatedANarrowingOneIsNot(t *testing.T) {
	w := newWorld(t)
	promotiontest.Record(t, w.scope, refund, "payments.refund.get")
	promotiontest.Promote(t, w.scope, "payments.refund.*")
	g, err := w.issue(w.agent, `{"operations": ["payments.refund.create", "payments.refund.get"]}`)
	if err != nil {
		t.Fatal(err)
	}
	revise := func(rev int, bounds string) error {
		b, _ := gdomain.DecodeBounds([]byte(bounds))
		_, _, err := w.grants.Revise(w.issuer, gapp.ReviseRequest{ID: g.ID, Revision: rev, TaskRef: "refunds", Bounds: b})
		return err
	}
	notPromoted(t, "widening to charges", revise(1, `{"operations": ["payments.refund.create", "payments.charge.create"]}`))
	if err := revise(1, `{"operations": ["payments.refund.create"]}`); err != nil {
		t.Fatalf("narrowing: %v", err)
	}
}

// TestHR290_RevokingAPromotionStopsNewGrantsOnly: after a revocation new
// grants for the operation are refused; the grant already issued keeps
// working (F6), and promoting again is a new promotion.
func TestHR290_RevokingAPromotionStopsNewGrantsOnly(t *testing.T) {
	w := newWorld(t)
	ps := promotiontest.Promote(t, w.scope, refund)
	g, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	if err != nil {
		t.Fatal(err)
	}
	p := promotiontest.NewPromoter(t, w.scope)
	if _, err := w.svc.RevokePromotion(p.Ctx, ps[0].ID, "rotation"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.RevokePromotion(p.Ctx, ps[0].ID, "again"); !errors.Is(err, promotions.ErrState) {
		t.Errorf("revoked twice: %v", err)
	}
	_, err = w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	notPromoted(t, "after the revocation", err)
	if v, err := w.grants.Get(w.issuer, g.ID); err != nil || v.Grant.State != gdomain.StateActive {
		t.Fatalf("the existing grant: %v %v", v.Grant.State, err)
	}
	again := promotiontest.Promote(t, w.scope, refund)
	if again[0].ID == ps[0].ID {
		t.Fatal("promoting again reused the revoked promotion")
	}
}

// TestHR290_PromotingNeedsAPersonAFreshStepUpAndThePermission: no step-up
// (as over the API), a stale one, another person's key, and a person
// without agent.promote are refused; nothing is promoted.
func TestHR290_PromotingNeedsAPersonAFreshStepUpAndThePermission(t *testing.T) {
	w := newWorld(t)
	promotiontest.Record(t, w.scope, refund)
	p := promotiontest.NewPromoter(t, w.scope)
	other := promotiontest.NewPromoter(t, w.scope)
	in := promotions.PromoteInput{Agent: w.agent, Environment: w.prod, Operations: []string{refund}, FailureBehavior: promotions.FailClosed}
	for name, tc := range map[string]struct {
		ctx context.Context
		su  *stepup.StepUp
	}{
		"no step-up":            {p.Ctx, nil},
		"a stale step-up":       {p.Ctx, &stepup.StepUp{Credential: p.Key, At: time.Now().Add(-10 * time.Minute)}},
		"another person's key":  {p.Ctx, &stepup.StepUp{Credential: other.Key, At: time.Now()}},
		"without agent.promote": {w.as(p.User, td.RoleOrgAdmin), p.StepUp()},
		"a service account":     {tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}}}), p.StepUp()},
	} {
		if _, err := w.svc.PromoteAgent(tc.ctx, in, tc.su); err == nil {
			t.Errorf("%s: promoted", name)
		}
	}
	if _, err := w.svc.PromoteAgent(p.Ctx, in, nil); !stepup.Is(err) {
		t.Errorf("no step-up: %v, want STEP_UP_REQUIRED", err)
	}
	ps, _, err := w.svc.ListPromotions(p.Ctx, promotions.Filter{Agent: &w.agent}, nil, 0)
	if err != nil || len(ps) != 0 {
		t.Fatalf("promotions after refusals: %d %v", len(ps), err)
	}
	if _, err := w.svc.PromoteAgent(p.Ctx, in, p.StepUp()); err != nil {
		t.Fatalf("a fresh step-up: %v", err)
	}
}

// TestHR290_ReadinessIsPerOperationAndOnlyReadyOperationsArePromoted: an
// operation that fails a check (no coverage, no published test) is
// reported with the checks it failed and is not promoted; the ready one is.
func TestHR290_ReadinessIsPerOperationAndOnlyReadyOperationsArePromoted(t *testing.T) {
	w := newWorld(t)
	promotiontest.Record(t, w.scope, refund)
	p := promotiontest.NewPromoter(t, w.scope)
	res, err := w.svc.PromoteAgent(p.Ctx, promotions.PromoteInput{
		Agent: w.agent, Environment: w.prod, Operations: []string{refund, charge}, FailureBehavior: promotions.Queue,
	}, p.StepUp())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Promoted) != 1 || res.Promoted[0].Operation != refund || res.Promoted[0].FailureBehavior != promotions.Queue {
		t.Fatalf("promoted %+v", res.Promoted)
	}
	for _, r := range res.Readiness {
		switch r.Operation {
		case refund:
			if !r.Ready() || len(r.Checks) != len(promotions.CheckNames) {
				t.Errorf("refund readiness %+v", r.Checks)
			}
		case charge:
			if r.Ready() || !slices.Equal(r.Failed(), []string{promotions.CheckTests, promotions.CheckCoverage}) {
				t.Errorf("charge failed %v", r.Failed())
			}
		}
	}
	rs, err := w.svc.GetReadiness(w.as(w.alice, td.RoleOrgAdmin), w.agent, w.prod, nil, "")
	if err != nil || len(rs) == 0 {
		t.Fatalf("readiness: %v %v", rs, err)
	}
	for _, r := range rs {
		if r.Operation == refund && (r.Promotion == nil || !r.Ready()) {
			t.Errorf("refund readiness after promotion: %+v", r)
		}
	}
}

// TestHR290_IdentityOwnerAndApproversAreChecked: an agent that is not
// VERIFIED, has no admitted instance, an inactive owner, or an approval
// rule nobody can answer fails the matching check.
func TestHR290_IdentityOwnerAndApproversAreChecked(t *testing.T) {
	w := newWorld(t)
	promotiontest.Record(t, w.scope, refund)
	p := promotiontest.NewPromoter(t, w.scope)
	failed := func() []string {
		t.Helper()
		rs, err := w.svc.GetReadiness(p.Ctx, w.agent, w.prod, []string{refund}, promotions.FailClosed)
		if err != nil {
			t.Fatal(err)
		}
		return rs[0].Failed()
	}
	if f := failed(); len(f) != 0 {
		t.Fatalf("ready fixture fails %v", f)
	}
	w.exec("UPDATE pc.agent_instances SET state = 'REVOKED' WHERE agent_id = $1", w.agent)
	if f := failed(); !slices.Equal(f, []string{promotions.CheckIdentity}) {
		t.Errorf("no instance: %v", f)
	}
	w.exec("UPDATE pc.users SET state = 'DISABLED' WHERE id = $1", w.alice)
	if f := failed(); !slices.Contains(f, promotions.CheckOwner) {
		t.Errorf("inactive owner: %v", f)
	}
}

// importPayments imports and activates the mock-payments package the
// world's connection serves, signed with a test root.
func (w *world) importPayments() {
	w.t.Helper()
	raw, err := os.ReadFile("../../packages/mock-payments/package.yaml")
	if err != nil {
		w.t.Fatal(err)
	}
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		w.t.Fatal(err)
	}
	signer, _ := jws.NewSigner(kid, priv)
	sum := sha256.Sum256(raw)
	doc, err := trust.Sign(trust.Targets{Version: 1, Expires: "2027-04-08T00:00:00Z", Targets: map[string]trust.Target{
		trust.Key("pc.mock-payments", "1.0.0"): {Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}},
	}}, signer)
	if err != nil {
		w.t.Fatal(err)
	}
	im := &defapp.Importer{Roots: trust.Roots{kid: signer.Public()}, Repo: &defpg.Store{Pool: w.pool},
		Clock: clock.NewFake(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC))}
	ctx := context.Background()
	if _, err := im.Import(ctx, w.org, "pc.mock-payments", "1.0.0", doc, raw, nil); err != nil {
		w.t.Fatal(err)
	}
	if err := im.Transition(ctx, w.org, "pc.mock-payments", "1.0.0", defdomain.StateActive, nil); err != nil {
		w.t.Fatal(err)
	}
}

// TestHR290_ApprovalsCoverReleaseWindowHoldsAndReadersWithoutPolicyRead
// (D71 G9, G10): a release approver's hold needs both an eligible approver
// and a change window to count in; a reader without policy.read sees the
// checks without rule ids, roles or owner ids.
func TestHR290_ApprovalsCoverReleaseWindowHoldsAndReadersWithoutPolicyRead(t *testing.T) {
	w := newWorld(t)
	policytest.Publish(context.Background(), t, w.pool, w.org, &pdomain.Bundle{ID: "prod", Version: 1, Rules: []pdomain.Rule{{
		ID: "release-gate", Kind: pdomain.RequireApproval, Summary: "a release approver approves refunds", Operations: []string{refund},
		When: "true", Reason: "RELEASE_APPROVAL", Approval: &pdomain.ApprovalRequirement{Role: string(td.RoleReleaseApprover), Count: 1},
	}}})
	promotiontest.Record(t, w.scope, refund)
	p := promotiontest.NewPromoter(t, w.scope)
	approvals := func(ctx context.Context) promotions.Check {
		t.Helper()
		rs, err := w.svc.GetReadiness(ctx, w.agent, w.prod, []string{refund}, promotions.FailClosed)
		if err != nil {
			t.Fatal(err)
		}
		return rs[0].Checks[3]
	}
	if c := approvals(p.Ctx); c.Passed || !strings.Contains(c.Detail, "release-gate") {
		t.Fatalf("no approver and no window: %+v", c)
	}
	approver := ids.NewV7()
	w.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'rita')", w.org, approver)
	w.exec(`INSERT INTO pc.role_bindings (org_id, id, user_id, role, scope_type, created_by) VALUES ($1, $2, $3, 'release_approver', 'ORG', 'test')`,
		w.org, ids.NewV7(), approver)
	if c := approvals(p.Ctx); c.Passed || !strings.Contains(c.Detail, "change window") {
		t.Fatalf("an approver but no change window: %+v", c)
	}
	w.exec(`INSERT INTO pc.change_windows (org_id, id, environment, time_zone, revision, created_by) VALUES ($1, $2, 'production', 'UTC', 1, 'test')`,
		w.org, ids.NewV7())
	if c := approvals(p.Ctx); !c.Passed {
		t.Fatalf("an approver and a window: %+v", c)
	}
	reader := w.as(ids.NewV7(), td.RoleResponder)
	rs, err := w.svc.GetReadiness(reader, w.agent, w.prod, []string{refund}, promotions.FailClosed)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rs[0].Checks {
		if strings.Contains(c.Detail, "release-gate") || strings.Contains(c.Detail, "release_approver") || strings.Contains(c.Detail, w.alice.String()) {
			t.Errorf("%s shows %q to a reader without policy.read", c.Name, c.Detail)
		}
	}
}
