// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package retention_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type notes struct {
	mu   sync.Mutex
	sent []napp.Message
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

func (n *notes) all() []napp.Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.sent)
}

type fixture struct {
	d                       *dbtest.DB
	p, rp                   *db.Pool
	org                     ids.OrgID
	manager, admin, auditor ids.UUID
	notify                  *notes
	svc                     *retention.Service
	remover                 *retention.Remover
	checkpoint              *checkpoints.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	path := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(path); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(context.Background(), p, kp, reg); err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		d: d, p: p, rp: d.Pool(t, d.Retention), org: ids.New[ids.Org](), manager: ids.NewV7(), admin: ids.NewV7(),
		auditor: ids.NewV7(), notify: &notes{},
	}
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", f.org)
	for role, u := range map[td.RoleName]ids.UUID{td.RoleRecordsManager: f.manager, td.RoleOrgAdmin: f.admin, td.RoleAuditor: f.auditor} {
		f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", f.org, u, string(role))
		f.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			f.org, ids.NewV7(), string(role), u)
	}
	f.svc = &retention.Service{Pool: p, Notify: f.notify}
	f.remover = &retention.Remover{Pool: f.rp, App: p, Log: pclog.Discard()}
	f.checkpoint = &checkpoints.Service{Pool: p, Keys: reg, LogOrigin: "pc.test", Log: pclog.Discard()}
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// as returns a context with a caller of the org.
func (f *fixture) as(kind td.PrincipalKind, id ids.UUID, cred tenancy.Credential, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: kind, ID: id}, Bindings: bs}, Credential: cred,
	})
}

func (f *fixture) records() context.Context {
	return f.as(td.KindUser, f.manager, tenancy.CredAccessToken, td.RoleRecordsManager)
}

// entries appends n entries of kind recorded at, with canonical bodies
// naming object, and chains them.
func (f *fixture) entries(t *testing.T, kind string, at time.Time, n int, object string) {
	t.Helper()
	for i := range n {
		body := `{"i":` + string(rune('0'+i)) + `,"object":{"id":"` + object + `","type":"thing"}}`
		f.exec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, occurred_at, body)
			VALUES ($1, $2, $3, 'system', 'test', $4, $5)`, f.org, ids.NewV7(), kind, at, []byte(body))
	}
	f.chain(t)
}

func (f *fixture) chain(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	want := f.count(t, "SELECT count(*) FROM pc.ledger_entries")
	for deadline := time.Now().Add(30 * time.Second); ; {
		if _, err := ledger.ChainAll(ctx, f.p, f.org, 500); err != nil {
			t.Fatal(err)
		}
		if f.count(t, "SELECT count(*) FROM pc.ledger_chain") == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the entries were not chained within 30 seconds")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (f *fixture) seal(t *testing.T) {
	t.Helper()
	for {
		res, err := f.checkpoint.Checkpoint(context.Background(), f.org)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Signed {
			return
		}
	}
}

func (f *fixture) verify(t *testing.T) {
	t.Helper()
	if _, err := ledger.Verify(context.Background(), f.p, f.org); err != nil {
		t.Fatalf("the chain no longer verifies: %v", err)
	}
	if _, err := f.checkpoint.Verify(context.Background(), f.org); err != nil {
		t.Fatalf("the daily verification fails: %v", err)
	}
}

// TestHR198_ChainAndCheckpointsStillVerifyAfterRemoval: expired bodies of
// chained, checkpointed entries are removed; an expired entry no checkpoint
// covers yet and an uncategorized one keep theirs; the chain, the
// checkpoints and the daily verification still pass, and the job's own
// audit entries chain and checkpoint like any other.
func TestHR198_ChainAndCheckpointsStillVerifyAfterRemoval(t *testing.T) {
	f := newFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour).UTC().Truncate(time.Microsecond)
	f.entries(t, "audit.security.thing_changed", old, 3, ids.NewV7().String())
	f.entries(t, "audit.approval.requested", old, 2, ids.NewV7().String())
	f.entries(t, "receipt.decision", old, 2, "x")
	f.entries(t, "test.other", old, 1, "x")
	f.entries(t, "audit.security.recent", time.Now(), 1, "x")
	f.seal(t)
	f.entries(t, "audit.security.unsealed", old, 1, "x")

	res, err := f.remover.Run(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total() != 7 {
		t.Fatalf("removed %d bodies, want 7: %+v", res.Total(), res.Removed)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE body IS NULL AND kind IN ('test.other', 'audit.security.recent', 'audit.security.unsealed')"); n != 0 {
		t.Fatalf("%d bodies removed that must stay", n)
	}
	f.verify(t)
	f.chain(t)
	f.seal(t)
	f.verify(t)
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.evidence.retention_removed'"); n != 3 {
		t.Fatalf("%d audit entries for three categories", n)
	}
	// Now covered by a checkpoint, the last old entry goes too.
	if res, err := f.remover.Run(context.Background(), f.org); err != nil || res.Total() != 1 {
		t.Fatalf("second run removed %d (%v)", res.Total(), err)
	}
	f.chain(t)
	f.seal(t)
	f.verify(t)
}

// TestHR198_HoldsBlockRemovalAndApplyAtOnce: an org hold keeps everything,
// a time range hold what it covers, and a hold on an id the audit events
// that name it; a released hold no longer does.
func TestHR198_HoldsBlockRemovalAndApplyAtOnce(t *testing.T) {
	f := newFixture(t)
	old := time.Now().Add(-400 * 24 * time.Hour).UTC().Truncate(time.Microsecond)
	older := old.Add(-10 * 24 * time.Hour)
	agent := ids.NewV7()
	f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", f.org, agent)
	f.entries(t, "audit.agent.suspended", old, 2, agent.String())
	f.entries(t, "audit.security.thing", older, 2, ids.NewV7().String())
	f.entries(t, "audit.security.thing", old, 1, ids.NewV7().String())
	f.seal(t)
	ctx := f.records()
	hold, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: retention.ScopeOrg, Reason: "litigation"})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := f.remover.Run(context.Background(), f.org); err != nil || res.Total() != 0 {
		t.Fatalf("an org hold kept nothing: removed %d (%v)", res.Total(), err)
	}
	start, end := older.Add(-time.Hour), older.Add(time.Hour)
	if _, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: retention.ScopeTimeRange, Start: &start, End: &end, Reason: "audit"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: retention.ScopeAgent, ID: &agent, Reason: "incident"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReleaseHold(ctx, hold.ID, "the matter closed"); err != nil {
		t.Fatal(err)
	}
	res, err := f.remover.Run(context.Background(), f.org)
	if err != nil || res.Total() != 1 {
		t.Fatalf("with an agent and a time range hold: removed %d, want 1 (%v)", res.Total(), err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE body IS NULL AND (kind = 'audit.agent.suspended' OR occurred_at < $1)", old); n != 0 {
		t.Fatalf("%d held bodies removed", n)
	}
	f.verify(t)
}

// TestHR198_ShorteningTakesEffectAfterSevenDaysAndIsAudited: a Records
// Manager's shorter period is recorded at once, takes effect 7 days later,
// is audited and is notified to the org's admins and auditors; a longer
// one applies at once and cancels a pending shortening.
func TestHR198_ShorteningTakesEffectAfterSevenDaysAndIsAudited(t *testing.T) {
	f := newFixture(t)
	ctx := f.records()
	f.entries(t, "receipt.decision", time.Now().Add(-100*24*time.Hour), 2, "x")
	f.seal(t)
	ch, err := f.svc.SetPolicy(ctx, retention.Receipts, 30)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.Changed || !ch.Shortened || ch.Policy.Current.Days != 365 || ch.Policy.Pending == nil || ch.Policy.Pending.Days != 30 {
		t.Fatalf("change = %+v", ch)
	}
	if d := ch.Policy.Pending.Effective.Sub(ch.Policy.Pending.Created); d != retention.ShorteningDelay {
		t.Fatalf("the shortening takes effect after %s", d)
	}
	sent := f.notify.all()
	if len(sent) != 1 || sent[0].Type != "evidence.retention_shortened" || sent[0].Params["days"] != "30" ||
		!slices.Contains(sent[0].Personal, f.admin) || !slices.Contains(sent[0].Personal, f.auditor) || slices.Contains(sent[0].Personal, f.manager) {
		t.Fatalf("notifications = %+v", sent)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.evidence.retention_changed' AND actor_id = $1`, f.manager.String()); n != 1 {
		t.Fatalf("%d audit entries for the change", n)
	}
	// Before the 7 days nothing goes; after them, under revision 2.
	f.remover.Shift = 6 * 24 * time.Hour
	if res, err := f.remover.Run(context.Background(), f.org); err != nil || res.Total() != 0 {
		t.Fatalf("the shortening applied early: removed %d (%v)", res.Total(), err)
	}
	f.remover.Shift = 7*24*time.Hour + time.Minute
	if res, err := f.remover.Run(context.Background(), f.org); err != nil || res.Total() != 2 {
		t.Fatalf("after 7 days: removed %d (%v)", res.Total(), err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries e JOIN pc.retention_policies p ON p.org_id = e.org_id
		AND p.id = e.removed_by_policy WHERE p.revision = 2 AND p.days = 30`); n != 2 {
		t.Fatalf("%d removals name revision 2", n)
	}

	// A longer period applies at once and is not notified.
	ch, err = f.svc.SetPolicy(ctx, retention.Approvals, 400)
	if err != nil || !ch.Changed || ch.Shortened || ch.Policy.Current.Days != 400 || ch.Policy.Pending != nil {
		t.Fatalf("lengthening = %+v, %v", ch, err)
	}
	// A shortening, then the period in effect again: withdrawn.
	if _, err := f.svc.SetPolicy(ctx, retention.Approvals, 365); err != nil {
		t.Fatal(err)
	}
	ch, err = f.svc.SetPolicy(ctx, retention.Approvals, 400)
	if err != nil || !ch.Changed || ch.Policy.Pending != nil || ch.Policy.Current.Days != 400 {
		t.Fatalf("cancelling = %+v, %v", ch, err)
	}
	if ch, err := f.svc.SetPolicy(ctx, retention.Approvals, 400); err != nil || ch.Changed {
		t.Fatalf("the same period again = %+v, %v", ch, err)
	}
	if len(f.notify.all()) != 2 {
		t.Fatalf("notifications = %+v", f.notify.all())
	}
	ps, err := f.svc.Policies(ctx)
	if err != nil || len(ps) != 5 {
		t.Fatalf("policies = %+v, %v", ps, err)
	}
	for _, p := range ps {
		if p.Category == retention.Approvals && (p.Current.Days != 400 || p.Pending != nil || p.Current.Number != 4) {
			t.Fatalf("approvals = %+v", p)
		}
		if p.Category == retention.NormalizedFacts && (p.Current.Days != 90 || p.Current.SetBy != nil || p.Current.Number != 1) {
			t.Fatalf("normalized facts default = %+v", p)
		}
	}
	for _, days := range []int{29, 3651} {
		if _, err := f.svc.SetPolicy(ctx, retention.Receipts, days); !errors.Is(err, retention.ErrDays) {
			t.Fatalf("receipts kept %d days: %v", days, err)
		}
	}
	if _, err := f.svc.SetPolicy(ctx, "versions", 400); !errors.Is(err, retention.ErrCategory) {
		t.Fatalf("versions: %v", err)
	}
}

// TestHR198_OnlyAPersonHoldingTheRetentionPermissionManagesIt: Org Admin,
// Auditor, service accounts and API keys are refused every use case.
func TestHR198_OnlyAPersonHoldingTheRetentionPermissionManagesIt(t *testing.T) {
	f := newFixture(t)
	refused := map[string]context.Context{
		"an org admin":      f.as(td.KindUser, f.admin, tenancy.CredAccessToken, td.RoleOrgAdmin),
		"an auditor":        f.as(td.KindUser, f.auditor, tenancy.CredAccessToken, td.RoleAuditor),
		"a service account": f.as(td.KindServiceAccount, ids.NewV7(), tenancy.CredAccessToken, td.RoleRecordsManager),
		"an api key":        f.as(td.KindServiceAccount, ids.NewV7(), tenancy.CredAPIKey, td.RoleRecordsManager),
	}
	for name, ctx := range refused {
		if _, err := f.svc.Policies(ctx); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s reads policies: %v", name, err)
		}
		if _, err := f.svc.SetPolicy(ctx, retention.Receipts, 30); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s shortens retention: %v", name, err)
		}
		if _, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: retention.ScopeOrg, Reason: "r"}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s places a hold: %v", name, err)
		}
		if _, err := f.svc.ListHolds(ctx, "", 0, ""); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s lists holds: %v", name, err)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM pc.retention_policies WHERE set_by IS NOT NULL"); n != 0 {
		t.Fatalf("%d revisions recorded by refused callers", n)
	}
}

// TestHR198_LegalHoldsAreScopedToTheOrgAndAudited: a hold names only an
// agent, run or transaction of the caller's org (another org's id is not
// found, T-037); releasing is audited, notified and happens once; holds
// list newest first.
func TestHR198_LegalHoldsAreScopedToTheOrgAndAudited(t *testing.T) {
	f := newFixture(t)
	g := newFixture(t)
	agent := ids.NewV7()
	g.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')", g.org, agent)
	ctx := f.records()
	if _, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: retention.ScopeAgent, ID: &agent, Reason: "r"}); !errors.Is(err, retention.ErrScopeNotFound) {
		t.Fatalf("a hold on another org's agent: %v", err)
	}
	missing := ids.NewV7()
	for _, s := range []retention.HoldScope{retention.ScopeRun, retention.ScopeTransaction} {
		if _, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: s, ID: &missing, Reason: "r"}); !errors.Is(err, retention.ErrScopeNotFound) {
			t.Fatalf("a %s hold on nothing: %v", s, err)
		}
	}
	h1, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: retention.ScopeOrg, Reason: "first"})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := f.svc.CreateHold(ctx, retention.HoldRequest{Scope: retention.ScopeOrg, Reason: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.notify.all()) != 0 {
		t.Fatal("placing a hold is notified")
	}
	gh, err := g.svc.CreateHold(g.records(), retention.HoldRequest{Scope: retention.ScopeOrg, Reason: "theirs"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ReleaseHold(ctx, gh.ID, "not mine"); !errors.Is(err, retention.ErrHoldNotFound) {
		t.Fatalf("releasing another org's hold: %v", err)
	}
	if _, err := f.svc.ReleaseHold(ctx, h1.ID, ""); !errors.Is(err, retention.ErrReason) {
		t.Fatalf("releasing without a reason: %v", err)
	}
	r, err := f.svc.ReleaseHold(ctx, h1.ID, "settled")
	if err != nil || r.State != retention.HoldReleased || r.ReleasedBy == nil || *r.ReleasedBy != f.manager {
		t.Fatalf("release = %+v, %v", r, err)
	}
	if _, err := f.svc.ReleaseHold(ctx, h1.ID, "settled"); !errors.Is(err, retention.ErrHoldNotActive) {
		t.Fatalf("a second release: %v", err)
	}
	sent := f.notify.all()
	if len(sent) != 1 || sent[0].Type != "evidence.legal_hold_released" || sent[0].Params["hold"] != h1.ID.String() ||
		!slices.Contains(sent[0].Personal, f.auditor) {
		t.Fatalf("notifications = %+v", sent)
	}
	for _, kind := range []string{"audit.evidence.legal_hold_created", "audit.evidence.legal_hold_released"} {
		if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = $1", kind); n == 0 {
			t.Fatalf("no %s entry", kind)
		}
	}
	if n := f.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE convert_from(body, 'UTF8') LIKE '%settled%' OR convert_from(body, 'UTF8') LIKE '%first%'"); n != 0 {
		t.Fatal("a person's reason reached the audit ledger body")
	}
	page, err := f.svc.ListHolds(ctx, "", 1, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != h2.ID || page.Next == "" {
		t.Fatalf("first page = %+v, %v", page, err)
	}
	page, err = f.svc.ListHolds(ctx, "", 1, page.Next)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != h1.ID {
		t.Fatalf("second page = %+v, %v", page, err)
	}
	active, err := f.svc.ListHolds(ctx, retention.HoldActive, 0, "")
	if err != nil || len(active.Items) != 1 || active.Items[0].ID != h2.ID {
		t.Fatalf("active holds = %+v, %v", active, err)
	}
}

// TestIntRetentionJobRunsThroughTheLister: the hourly dispatcher finds due
// orgs through the audited lister and runs each once a day.
func TestIntRetentionJobRunsThroughTheLister(t *testing.T) {
	f := newFixture(t)
	reg := jobs.NewRegistry()
	if err := retention.Register(reg, f.remover); err != nil {
		t.Fatal(err)
	}
	client, err := jobs.NewClient(f.p, reg, jobs.Config{
		Queues: map[string]int{"default": 2}, PeriodicJobs: retention.PeriodicJobs(), Logger: pclog.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Stop(context.Background()) }()
	for deadline := time.Now().Add(60 * time.Second); f.count(t, "SELECT count(*) FROM pc.retention_status WHERE last_run_at IS NOT NULL") == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the org was not run within 60 seconds")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var audited int
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.cross_org_list_audit WHERE purpose = 'retention_due'", nil, &audited)
	if audited == 0 {
		t.Fatal("the lister call was not audited")
	}
}
