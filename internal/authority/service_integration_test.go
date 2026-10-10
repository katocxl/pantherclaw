// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	factsapp "github.com/katocxl/pantherclaw/internal/facts/app"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// allow lets the fixture act as an authorized caller of the use cases.
type allow struct{}

func (allow) Require(tenancy.Caller, td.Permission, td.Path) error { return nil }

type fixture struct {
	pool *db.Pool
	svc  *authority.Service
	reg  *keys.Registry
	gw   authority.Gateway
	conn ids.UUID

	// The authority every run gets: the reference package, a fact provider
	// for refundable charges, and a grant per agent with these terms.
	mapper   *mapping.Mapper
	facts    *factsapp.Service
	billing  ids.UUID
	grants   *grantsapp.Service
	limit    string
	maxCount int
	grantOf  map[ids.UUID]gdomain.GrantID

	ident            *iapp.Service
	runs             *runsapp.Service
	inv              *aapp.Inventory
	team, env, owner ids.UUID
	// wl is an admitted instance of a verified agent; run is bound to it
	// and to grant.
	wl    workload
	run   ids.UUID
	grant gdomain.GrantID
}

// setupBase seeds an org with containment, the reference package (imported
// and active) and a fact provider, and builds the Authority on the
// decision pipeline. Grants are issued with limit (a task budget, USD) and
// maxCount refunds (0: no count limit).
func setupBase(t *testing.T, limit string, maxCount int, ttl time.Duration) fixture {
	t.Helper()
	p := dbtest.New(t).AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	gw := ids.NewV7()
	f := fixture{
		pool: p, gw: authority.Gateway{ID: gw.String(), Org: org}, conn: ids.NewV7(), limit: limit, maxCount: maxCount,
		billing: ids.NewV7(), grantOf: map[ids.UUID]gdomain.GrantID{},
	}
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	// The gateway and the enforce-mode connection every action goes
	// through (PAP-1 §6).
	f.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", org, gw)
	f.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by) VALUES ($1, $2, 'payments', 'http', $3, 'pc.mock-payments', 'https://payments.example.test', 'none',
		'enforce', 'test', 'test')`, org, f.conn, gw)
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertContainment(ctx, org)
	}); err != nil {
		t.Fatal(err)
	}

	// The package, signed with a test root, imported and activated.
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := jws.NewSigner(kid, priv)
	sum := sha256.Sum256(mockpayments.Package)
	doc, err := trust.Sign(trust.Targets{
		Version: 1, Expires: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: map[string]trust.Target{trust.Key(mockpayments.Name, mockpayments.Version): {
			Length: int64(len(mockpayments.Package)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])},
		}},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	defStore := &defspg.Store{Pool: p}
	im := &defsapp.Importer{Roots: trust.Roots{kid: signer.Public()}, Repo: defStore, Clock: clock.System{}}
	if _, err := im.Import(ctx, org, mockpayments.Name, mockpayments.Version, doc, mockpayments.Package, nil); err != nil {
		t.Fatal(err)
	}
	if err := im.Transition(ctx, org, mockpayments.Name, mockpayments.Version, defs.StateActive, nil); err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(mockpayments.Package)
	if err != nil {
		t.Fatal(err)
	}
	if f.mapper, err = mapping.New(pkg, celenv.DefaultLimits); err != nil {
		t.Fatal(err)
	}

	// A fact provider for refundable charges.
	f.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'billing', 'test')", org, f.billing)
	factStore := &factspg.Store{Pool: p}
	f.facts = &factsapp.Service{Store: factStore, Authz: allow{}}
	human := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}}})
	if _, err := f.facts.RegisterProvider(human, "billing.system", f.billing, []fdomain.Declaration{
		{Name: "payments.charge.refundable", Type: fdomain.TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
	}); err != nil {
		t.Fatal(err)
	}
	gs := &grantspg.Store{Pool: p}
	f.grants = &grantsapp.Service{Repo: gs, Subjects: gs, Defs: defStore, Authz: allow{}, Clock: clock.System{}}

	f.reg = keys.NewRegistry()
	for _, purpose := range []keys.Purpose{keys.PurposePermits, keys.PurposeReceipts} {
		k, _ := keys.GenerateSigningKey(purpose)
		if err := f.reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	receipts, _ := f.reg.Signer(keys.PurposeReceipts)
	permits, _ := f.reg.Signer(keys.PurposePermits)
	reader := &pgauthority.Reader{Pool: p, Definitions: defStore, Policies: &polpg.Store{Pool: p}, FactStore: factStore, Grants: gs, Limits: celenv.DefaultLimits}
	f.svc = authority.New(authority.Config{
		Decider: &finalize.Authority{
			Pipeline: &pipeline.Pipeline{Reader: reader}, Store: &pgauthority.Store{Pool: p},
			Receipts: receipts, Permits: permits, PermitTTL: ttl,
		},
		Logger: pclog.Discard(),
	})
	return f
}

// grantFor issues (once per agent) a root grant for the owner: refunds of
// at most $100 each, the fixture's task budget.
func (f fixture) grantFor(t *testing.T, agent ids.UUID) gdomain.GrantID {
	t.Helper()
	if g, ok := f.grantOf[agent]; ok {
		return g
	}
	b, err := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.create"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	count := ""
	if f.maxCount > 0 {
		count = fmt.Sprintf(`, "max_count": "%d"`, f.maxCount)
	}
	lim, err := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "` + f.limit + `"` + count + `, "period": "none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.grants.Issue(f.ownerCtx(), grantsapp.IssueRequest{
		AgentID: agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: f.owner}, TaskRef: "refunds",
		ExpiresAt: time.Now().Add(48 * time.Hour), Bounds: b, Limits: lim,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.grantOf[agent] = g.ID
	return g.ID
}

// refundable reports the charges as refundable, as the billing provider.
func (f fixture) refundable(t *testing.T, charges ...string) {
	t.Helper()
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.gw.Org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: f.billing},
	}})
	for len(charges) > 0 {
		n := min(len(charges), factsapp.MaxObservations)
		var obs []fdomain.Observation
		for _, c := range charges[:n] {
			obs = append(obs, fdomain.Observation{
				Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: c,
				Value: jsontext.Value(`{"bool": true}`), ObservedAt: time.Now().Add(-time.Second),
			})
		}
		res, err := f.facts.PutFacts(ctx, obs)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res {
			if r.Err != nil {
				t.Fatalf("fact %s: %v", r.SubjectID, r.Err)
			}
		}
		charges = charges[n:]
	}
}

// charge returns a new refundable charge: identical irreversible refunds
// are parked (HR-007), so each action refunds its own charge.
func (f fixture) charge(t *testing.T) string {
	t.Helper()
	u := ids.NewV7()
	c := "ch_" + hex.EncodeToString(u[10:])
	f.refundable(t, c)
	return c
}

func (f fixture) action(t *testing.T, amount string, run, act ids.UUID) []byte {
	t.Helper()
	return f.actionOn(t, f.charge(t), amount, run, act, f.env.String(), f.wl.inst.Instance.String())
}

// actionAs is an action of instance in env, on a new charge.
func (f fixture) actionAs(t *testing.T, amount string, run, act ids.UUID, env, instance string) []byte {
	t.Helper()
	return f.actionOn(t, f.charge(t), amount, run, act, env, instance)
}

// actionOn is the canonical refund of charge, mapped by the package.
func (f fixture) actionOn(t *testing.T, charge, amount string, run, act ids.UUID, env, instance string) []byte {
	t.Helper()
	p, err := f.mapper.MCP(context.Background(), mapping.Context{
		Org: f.gw.Org.String(), Env: env, RunID: run.String(), ActionID: act.String(), AgentInstance: instance,
		Connection: f.conn.String(),
	}, "create_refund", []byte(`{"charge":"`+charge+`","amount":"`+amount+`","currency":"USD","reason":"duplicate"}`))
	if err != nil {
		t.Fatal(err)
	}
	return p.Canonical
}

// budgetState is the main grant's task budget account (zero before any
// action debits it).
type budgetState struct {
	Reserved, Spent           money.Decimal
	ReservedCount, SpentCount int32
}

func (f fixture) budgetRow(t *testing.T) budgetState {
	t.Helper()
	var b budgetState
	err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		err := tx.QueryRow(ctx, `SELECT reserved, spent, reserved_count, spent_count FROM pc.budget_accounts
			WHERE org_id = $1 AND owner_id = $2`, f.gw.Org, f.grant.UUID()).Scan(&b.Reserved, &b.Spent, &b.ReservedCount, &b.SpentCount)
		if db.IsNoRows(err) {
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// settle runs the sweep, which applies the recorded outcomes to the budget
// rows (ADR-0015), and returns how many reservations it applied.
func (f fixture) settle(t *testing.T) int {
	t.Helper()
	r, err := f.svc.SweepOrg(context.Background(), f.gw.Org, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return r.Applied
}

func (f fixture) authorize(t *testing.T, amount string) authority.Result {
	t.Helper()
	res, err := f.svc.Authorize(context.Background(), f.gw, f.action(t, amount, f.run, ids.NewV7()), f.creds(t, f.wl, f.wl.token))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestIntAllowDispatchCommit(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "30.00")
	if res.Decision != domain.Allow || res.Permit == "" || res.Receipt == "" || res.BasisDigest == "" || len(res.Checklist) == 0 {
		t.Fatalf("authorize = %+v", res)
	}
	// The permit verifies with the permits key only, and binds the action.
	v, _ := f.reg.Verifier(keys.PurposePermits, authority.TypePermit)
	payload, _, err := v.Verify(res.Permit)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Aud string `json:"aud"`
		Jti string `json:"jti"`
		Exp int64  `json:"exp"`
		Pap struct {
			Act   string `json:"act"`
			Epoch int64  `json:"epoch"`
			Txn   string `json:"txn"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != "gw:"+f.gw.ID || claims.Jti != res.PermitID.String() || claims.Pap.Act != res.ActionHash ||
		claims.Pap.Epoch != res.Epoch || claims.Pap.Txn != res.TransactionID.String() {
		t.Fatalf("permit claims %+v do not bind the decision %+v", claims, res)
	}
	if ttl := time.Until(time.Unix(claims.Exp, 0)); ttl > 6*time.Second {
		t.Fatalf("permit lives %v, want ≈ 5s (HR-009)", ttl)
	}
	rv, _ := f.reg.Verifier(keys.PurposeReceipts, authority.TypeDecisionReceipt)
	if _, _, err := rv.Verify(res.Receipt); err != nil {
		t.Fatalf("decision receipt: %v", err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "30" || b.Spent.String() != "0" {
		t.Fatalf("after authorize: reserved %s spent %s", b.Reserved, b.Spent)
	}
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(`{"id":"re_1"}`))
	receipt, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{
		Permit: res.PermitID, Outcome: authority.Accepted, TargetStatus: 200, ResponseDigest: digest[:], DispatchMS: 12,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := f.reg.Verifier(keys.PurposeReceipts, authority.TypeExecutionReceipt)
	if body, _, err := ev.Verify(receipt); err != nil || !jsontext.Value(body).IsValid() {
		t.Fatalf("execution receipt: %v", err)
	}
	// The commit reaches the budget row with the settlement (ADR-0015);
	// until then the row still counts it reserved.
	if b := f.budgetRow(t); b.Reserved.String() != "30" || b.Spent.String() != "0" {
		t.Fatalf("before the settlement: reserved %s spent %s", b.Reserved, b.Spent)
	}
	if n := f.settle(t); n != 1 {
		t.Fatalf("settled %d reservations, want 1", n)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "0" || b.Spent.String() != "30" || b.SpentCount != 1 {
		t.Fatalf("after commit: reserved %s spent %s count %d", b.Reserved, b.Spent, b.SpentCount)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.execution_attempts WHERE org_id = $1 AND target_status = 200 AND dispatch_ms = 12
		AND response_digest IS NOT NULL`); n != 1 {
		t.Fatalf("execution attempts with the reported details: %d", n)
	}
}

func TestHR009_PermitIsSingleUse(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "10.00")
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); !errors.Is(err, authority.ErrPermitUsed) {
		t.Fatalf("second BeginDispatch: %v, want ErrPermitUsed", err)
	}
	other := authority.Gateway{ID: "gw-other", Org: f.gw.Org}
	res2 := f.authorize(t, "10.00")
	if _, err := f.svc.BeginDispatch(ctx, other, res2.PermitID, res2.Epoch, authority.Outbound{}); !errors.Is(err, authority.ErrPermitUnknown) {
		t.Fatalf("another gateway used the permit: %v", err)
	}
}

func TestHR001_BeginDispatchRejectsStaleEpochAndKillSwitch(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "10.00")
	err := f.pool.InTenantTx(ctx, f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).BumpEpoch(ctx, f.gw.Org) // e.g. an agent was suspended (HR-002)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); !errors.Is(err, authority.ErrEpochStale) {
		t.Fatalf("BeginDispatch after epoch bump: %v, want ErrEpochStale", err)
	}
	res2 := f.authorize(t, "10.00")
	err = f.pool.InTenantTx(ctx, f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).EngageKillSwitch(ctx, "test", "test", f.gw.Org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res2.PermitID, res2.Epoch, authority.Outbound{}); !errors.Is(err, authority.ErrKillSwitch) {
		t.Fatalf("BeginDispatch under kill switch: %v", err)
	}
	if res := f.authorize(t, "10.00"); res.Decision != domain.Deny || res.Permit != "" {
		t.Fatalf("authorize under kill switch: %+v", res)
	}
}

func TestHR001_BeginDispatchRejectsExpiredPermit(t *testing.T) {
	f := setup(t, "1000", 0, time.Microsecond)
	res := f.authorize(t, "10.00")
	if _, err := f.svc.BeginDispatch(context.Background(), f.gw, res.PermitID, res.Epoch, authority.Outbound{}); !errors.Is(err, authority.ErrPermitExpired) {
		t.Fatalf("expired permit: %v, want ErrPermitExpired", err)
	}
}

func TestT012_SameActionDifferentHashIsTampered(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	ctx := context.Background()
	run, act, charge := f.run, ids.NewV7(), f.charge(t)
	env, inst := f.env.String(), f.wl.inst.Instance.String()
	first, err := f.svc.Authorize(ctx, f.gw, f.actionOn(t, charge, "30.00", run, act, env, inst), f.creds(t, f.wl, f.wl.token))
	if err != nil || first.Decision != domain.Allow {
		t.Fatalf("first = %+v, %v", first, err)
	}
	again, err := f.svc.Authorize(ctx, f.gw, f.actionOn(t, charge, "30.00", run, act, env, inst), f.creds(t, f.wl, f.wl.token))
	if err != nil || again.Decision != domain.Allow || again.Permit != "" || again.TransactionID != first.TransactionID || !again.Repeat {
		t.Fatalf("retry returned %+v, %v; want the stored ALLOW without a second permit (HR-005)", again, err)
	}
	tampered, err := f.svc.Authorize(ctx, f.gw, f.actionOn(t, charge, "90.00", run, act, env, inst), f.creds(t, f.wl, f.wl.token))
	if err != nil || tampered.Decision != domain.Deny || tampered.Reasons[0].Code != domain.ReasonActionTampered || tampered.Permit != "" {
		t.Fatalf("changed amount under the same action id: %+v, %v", tampered, err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "30" {
		t.Fatalf("reserved %s, want only the first 30", b.Reserved)
	}
}

func TestIntDenialsReserveNothing(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	if res := f.authorize(t, "125.00"); res.Decision != domain.Deny || res.Reasons[0].Code != gdomain.ReasonGrantLimitExceeded {
		t.Fatalf("$125 = %+v", res)
	}
	other := authority.Gateway{ID: f.gw.ID, Org: ids.New[ids.Org]()}
	res, err := f.svc.Authorize(context.Background(), other, f.action(t, "10.00", f.run, ids.NewV7()), f.creds(t, f.wl, f.wl.token))
	if err != nil || res.Decision != domain.Deny || res.Reasons[0].Code != domain.ReasonOrgMismatch {
		t.Fatalf("org mismatch = %+v, %v", res, err)
	}
	if res, _ := f.svc.Authorize(context.Background(), f.gw, []byte(`{"v":1}`), f.creds(t, f.wl, f.wl.token)); res.Decision != domain.CannotAuthorize {
		t.Fatalf("garbage = %+v", res)
	}
	if b := f.budgetRow(t); !b.Reserved.IsZero() {
		t.Fatalf("denials reserved %s", b.Reserved)
	}
}

func TestT011_NoOverspendUnder1000ConcurrentReservations(t *testing.T) {
	for name, tc := range map[string]struct {
		limit   string
		count   int
		allowed int
	}{
		"amount limit (3 × $30 ≤ $100)": {"100", 0, 3},
		"one refund":                    {"1000", 1, 1},
	} {
		t.Run(name, func(t *testing.T) {
			f := setup(t, tc.limit, tc.count, 5*time.Second)
			var wg sync.WaitGroup
			var mu sync.Mutex
			counts := map[domain.Decision]int{}
			nonce, err := f.ident.Nonce(context.Background(), f.gw.Org)
			if err != nil {
				t.Fatal(err)
			}
			charges := make([]string, 1000)
			for i := range charges {
				charges[i] = fmt.Sprintf("ch_race%d", i)
			}
			f.refundable(t, charges...)
			env, inst := f.env.String(), f.wl.inst.Instance.String()
			for i := range 1000 {
				c, action := f.credsWith(t, f.wl, f.wl.token, nonce), f.actionOn(t, charges[i], "30.00", f.run, ids.NewV7(), env, inst)
				wg.Go(func() {
					res, err := f.svc.Authorize(context.Background(), f.gw, action, c)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					counts[res.Decision]++
					mu.Unlock()
				})
			}
			wg.Wait()
			// Every action that does not fit is refused; under contention a
			// few may be CANNOT_AUTHORIZE (CONCURRENT_CHANGE), never ALLOW.
			if counts[domain.Allow] != tc.allowed || counts[domain.Deny]+counts[domain.CannotAuthorize] != 1000-tc.allowed {
				t.Fatalf("decisions = %v, want %d ALLOW and the rest refused", counts, tc.allowed)
			}
			b := f.budgetRow(t)
			want, _ := money.MustParse("30").MulInt(int64(tc.allowed))
			if !b.Reserved.Equal(want) || int(b.ReservedCount) != tc.allowed {
				t.Fatalf("reserved %s (%d), want %s (%d)", b.Reserved, b.ReservedCount, want, tc.allowed)
			}
		})
	}
}

func TestT024_CrashMidDispatchYieldsUnknown(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "40.00")
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); err != nil {
		t.Fatal(err)
	}
	// The gateway "crashes": RecordExecution never arrives.
	r, err := f.svc.SweepOrg(ctx, f.gw.Org, 0)
	if err != nil || r.Unknown != 1 || r.Released != 0 {
		t.Fatalf("sweep = %+v, %v; want one UNKNOWN, nothing released", r, err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "40" {
		t.Fatalf("reservation released after a crash mid-dispatch: reserved %s (HR-003)", b.Reserved)
	}
	// A gateway that reports after the sweeper is heard as evidence (G0 M7,
	// PAP-1 §7.4, HR-192): a late failure releases nothing, because only a
	// person may release an unknown outcome; a late acceptance shows the
	// effect happened and commits the reservation, once.
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{Permit: res.PermitID, Outcome: authority.Failed, TargetStatus: 402}); err != nil {
		t.Fatalf("late failure: %v", err)
	}
	if b := f.budgetRow(t); b.Reserved.String() != "40" || !b.Spent.IsZero() {
		t.Fatalf("a late failure settled the reservation: reserved %s spent %s (HR-003, HR-192)", b.Reserved, b.Spent)
	}
	for range 2 {
		if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{Permit: res.PermitID, Outcome: authority.Accepted}); err != nil {
			t.Fatalf("late acceptance: %v", err)
		}
		if b := f.budgetRow(t); !b.Reserved.IsZero() || b.Spent.String() != "40" {
			t.Fatalf("a late acceptance settled %s reserved, %s spent; want it committed once", b.Reserved, b.Spent)
		}
	}
	// A permit the gateway already recorded is not recorded again.
	done := f.authorize(t, "10.00")
	if _, err := f.svc.BeginDispatch(ctx, f.gw, done.PermitID, done.Epoch, authority.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{Permit: done.PermitID, Outcome: authority.Failed, TargetStatus: 402}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{Permit: done.PermitID, Outcome: authority.Accepted}); !errors.Is(err, authority.ErrNotDispatching) {
		t.Fatalf("a second record of a recorded permit: %v, want ErrNotDispatching", err)
	}
}

func TestHR003_SweeperReleasesOnlyExpiredIssued(t *testing.T) {
	f := setup(t, "1000", 0, time.Microsecond)
	ctx := context.Background()
	for _, amount := range []string{"25.00", "10.50", "4.25"} {
		f.authorize(t, amount)
	}
	r, err := f.svc.SweepOrg(ctx, f.gw.Org, time.Hour)
	if err != nil || r.Released != 3 || r.Unknown != 0 || r.Applied != 3 {
		t.Fatalf("sweep = %+v, %v", r, err)
	}
	if b := f.budgetRow(t); !b.Reserved.IsZero() || b.ReservedCount != 0 {
		t.Fatalf("expired permit's reservation not released: %s", b.Reserved)
	}
	if r, _ := f.svc.SweepOrg(ctx, f.gw.Org, time.Hour); r.Released != 0 {
		t.Fatal("sweeper released twice")
	}
}

func TestIntFailedDispatchReleases(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	ctx := context.Background()
	res := f.authorize(t, "20.00")
	if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{Permit: res.PermitID, Outcome: authority.Failed, TargetStatus: 402}); err != nil {
		t.Fatal(err)
	}
	if n := f.settle(t); n != 1 {
		t.Fatalf("settled %d reservations, want 1", n)
	}
	if b := f.budgetRow(t); !b.Reserved.IsZero() || !b.Spent.IsZero() {
		t.Fatalf("after failure: reserved %s spent %s", b.Reserved, b.Spent)
	}
}
