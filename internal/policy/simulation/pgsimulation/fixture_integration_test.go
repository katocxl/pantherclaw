// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgsimulation_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
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
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	"github.com/katocxl/pantherclaw/internal/policy/simulation/pgsimulation"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type allow struct{}

func (allow) Require(tapp.Caller, td.Permission, td.Path) error { return nil }

type team struct{}

func (team) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Team, Status: billing.StatusValid}, nil
}

// world is an org with the mock-payments package active, an agent, an
// Authority over PostgreSQL that keeps replay inputs, and the simulation
// service and runner as the server wires them.
type world struct {
	t                    testing.TB
	db                   *dbtest.DB
	pool                 *db.Pool
	org                  ids.OrgID
	alice, billing       ids.UUID
	agent, instance, env ids.UUID
	grants               *gapp.Service
	facts                *factapp.Service
	mapper               *mapping.Mapper
	auth                 *finalize.Authority
	gw                   finalize.Gateway
	conn                 ids.UUID
	human                context.Context
	svc                  *simulation.Service
	runner               *simulation.Runner
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

func newWorld(t testing.TB) *world {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	w := &world{t: t, db: d, pool: p, org: ids.New[ids.Org](), alice: ids.NewV7(), billing: ids.NewV7(), agent: ids.NewV7(), instance: ids.NewV7(), env: ids.NewV7()}
	teamID := ids.NewV7()
	exec(t, p, w.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	if err := p.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error { return dbq.New(tx).InsertContainment(ctx, w.org) }); err != nil {
		t.Fatal(err)
	}
	exec(t, p, w.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", w.org, teamID)
	exec(t, p, w.org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')", w.org, w.env, teamID)
	exec(t, p, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.alice)
	exec(t, p, w.org, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'test')", w.org, w.billing)
	exec(t, p, w.org, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'refund-bot', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, w.org, w.agent, teamID, w.env, w.alice)
	exec(t, p, w.org, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, w.instance, w.agent, fmt.Sprintf("%043d", time.Now().UnixNano()%1e12))
	w.human = w.as(td.KindUser, w.alice, td.RolePolicyAuthor)

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
	if _, err := w.facts.RegisterProvider(w.as(td.KindUser, w.alice), "billing.system", w.billing, []fdomain.Declaration{
		{Name: "payments.charge.refundable", Type: fdomain.TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
	}); err != nil {
		t.Fatal(err)
	}
	gs := &gpg.Store{Pool: p, Promotions: grantstest.OpenGate{}}
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
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	sealer := recording.NewSealer(pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(p, kp), time.Minute, clock.System{})))
	w.auth = &finalize.Authority{
		Pipeline: &pipeline.Pipeline{Reader: reader}, Store: &pgauthority.Store{Pool: p}, Receipts: receipts, Permits: permits, Inputs: sealer,
	}
	gw := ids.NewV7()
	exec(t, p, w.org, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, gw)
	w.gw = finalize.Gateway{ID: gw.String(), Org: w.org}
	w.conn = ids.NewV7()
	exec(t, p, w.org, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode,
		default_mode, created_by, updated_by) VALUES ($1, $2, 'payments', 'http', $3, 'pc.mock-payments', 'https://payments.example.test',
		'none', 'enforce', 'test', 'test')`, w.org, w.conn, gw)

	// The simulation as the server wires it: the replay engine's source
	// for versions, the engine for the runner, an insert-only job client.
	src := &pgauthority.ReplaySource{Pool: p, Definitions: defs, FactStore: facts}
	insert, err := jobs.NewClient(p, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w.svc = &simulation.Service{
		Store: pgsimulation.Store{Pool: p, Jobs: insert}, Versions: src, Editions: team{},
		IsNotFound: func(err error) bool { return err == replay.ErrNotFound }, //nolint:errorlint // the sentinel itself
	}
	w.runner = &simulation.Runner{
		Store: pgsimulation.Store{Pool: p}, Versions: src, Chunk: 2, Editions: team{},
		Replay: &replay.Engine{Source: src, Inputs: recording.NewSealer(pccrypto.NewEnvelope(keystore.NewDEKStore(p, kp)))},
	}
	return w
}

// as is a caller of w's org holding roles at the org.
func (w *world) as(kind td.PrincipalKind, id ids.UUID, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}})
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: kind, ID: id}, Bindings: bs}})
}

func (w *world) refundable(charges ...string) {
	w.t.Helper()
	ctx := w.as(td.KindServiceAccount, w.billing)
	var obs []fdomain.Observation
	for _, c := range charges {
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
}

func (w *world) run() ids.UUID {
	w.t.Helper()
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create", "payments.refund.get"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	lim, _ := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"], "currency": "USD", "limit": "500", "period": "none"}]}`))
	g, err := w.grants.Issue(w.as(td.KindUser, w.alice), gapp.IssueRequest{
		AgentID: w.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.alice}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Limits: lim, Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	id := ids.NewV7()
	exec(w.t, w.pool, w.org, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id,
		principal_source, grant_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', $7, now() + interval '8 hours')`,
		w.org, id, w.agent, w.instance, w.env, w.alice, g.ID.UUID())
	return id
}

// refund decides a refund of amount on charge through the Authority.
func (w *world) refund(run ids.UUID, charge, amount string) finalize.Result {
	w.t.Helper()
	p, err := w.mapper.MCP(context.Background(), mapping.Context{
		Org: w.org.String(), Env: w.env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: w.instance.String(),
		Connection: w.conn.String(),
	}, "create_refund", []byte(`{"charge":"`+charge+`","amount":"`+amount+`","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		w.t.Fatal(err)
	}
	r, err := w.auth.Authorize(context.Background(), w.gw, pipeline.Request{
		Org: w.org, Action: p, Identity: pipeline.Identity{InstanceID: w.instance, AgentID: w.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

// policy stores rules as a new version of the org's policy, published
// unless draft (test setup through policytest, D10); it returns its id.
func (w *world) policy(draft bool, rules ...pdomain.Rule) ids.UUID {
	w.t.Helper()
	store := &polpg.Store{Pool: w.pool}
	id, _, err := store.CreateVersion(context.Background(), w.org, &pdomain.Bundle{ID: "org-policy", Rules: rules}, w.alice.String(), nil)
	if err != nil {
		w.t.Fatal(err)
	}
	if !draft {
		policytest.PublishVersion(context.Background(), w.t, w.pool, w.org, id)
	}
	return id
}

// finish runs a simulation's steps until it finishes.
func (w *world) finish(id ids.UUID) {
	w.t.Helper()
	for i := 0; i < 100; i++ {
		more, err := w.runner.Step(context.Background(), w.org, id)
		if err != nil {
			w.t.Fatal(err)
		}
		if !more {
			return
		}
	}
	w.t.Fatal("the simulation never finished")
}

// rowCounts counts the rows of every table in schema pc, as the admin.
func (w *world) rowCounts() map[string]int64 {
	w.t.Helper()
	var list string
	w.db.AdminQueryRow(w.t, `SELECT string_agg(c.relname, ',' ORDER BY c.relname) FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'pc' AND c.relkind IN ('r', 'p')`, nil, &list)
	out := map[string]int64{}
	for _, tb := range strings.Split(list, ",") {
		var n int64
		w.db.AdminQueryRow(w.t, fmt.Sprintf("SELECT count(*) FROM pc.%s", pgx.Identifier{tb}.Sanitize()), nil, &n)
		out[tb] = n
	}
	return out
}

var (
	holdOver50 = pdomain.Rule{
		ID: "hold", Kind: pdomain.RequireApproval, Summary: "over 50 needs approval", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("50", "USD")`, Reason: "REFUND_OVER_50", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
	holdOver20 = pdomain.Rule{
		ID: "hold-20", Kind: pdomain.RequireApproval, Summary: "over 20 needs approval", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("20", "USD")`, Reason: "REFUND_OVER_20", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
	forbidOver60 = pdomain.Rule{
		ID: "no-large-refunds", Kind: pdomain.Forbid, Summary: "no refunds over 60", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("60", "USD")`, Reason: "REFUND_TOO_LARGE",
	}
)
