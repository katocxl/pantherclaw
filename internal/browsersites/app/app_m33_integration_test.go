// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/browsersites/app"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// person is a signed-in person with a security key.
type person struct {
	id, key, session ids.UUID
	page             context.Context
}

type world struct {
	t       *testing.T
	pool    *db.Pool
	org     ids.OrgID
	gateway ids.UUID
	changes *changes.Service
	svc     *app.Service
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, pool: dbtest.New(t).AppPool(t), org: ids.New[ids.Org](), gateway: ids.NewV7()}
	w.changes = changes.New(w.pool, "https://pc.test")
	gate := &protect.Gate{Requests: protect.Ceremony{Changes: w.changes}, Failures: &failures.Sink{}}
	protect.Register(w.changes, gate, &protect.Publishers{Pool: w.pool, Gate: gate})
	w.svc = &app.Service{Pool: w.pool}
	w.svc.RegisterProtect(gate)
	w.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'browser-m33')", w.org)
	w.exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, w.gateway)
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) str(sql string, args ...any) string {
	w.t.Helper()
	var s string
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&s)
	}); err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *world) person(name string, role td.RoleName) person {
	w.t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	w.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, p.id, name)
	w.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		w.org, p.key, p.id, secret[:16], secret)
	w.exec(`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, w.org, p.session, p.id, secret)
	w.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		w.org, ids.NewV7(), string(role), p.id)
	sub := td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}
	p.page = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredBrowserSession, Session: p.session})
	return p
}

// confirm signs the request's binding with p's key and confirms it.
func (w *world) confirm(p person, id ids.UUID) (changes.Request, error) {
	w.t.Helper()
	r, err := w.changes.Get(p.page, id)
	if err != nil {
		return r, err
	}
	cer := ids.NewV7()
	w.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, w.org, cer, p.session, p.id, r.Binding[:], r.ID)
	return w.changes.Confirm(p.page, id, changes.Assertion{Ceremony: cer, Credential: p.key})
}

// listed is the org's site list as the browser step reads it.
func (w *world) listed() []string {
	w.t.Helper()
	sites, err := (&pgauthority.Reader{Pool: w.pool}).BrowserSites(context.Background(), w.org)
	if err != nil {
		w.t.Fatal(err)
	}
	var out []string
	for _, s := range sites {
		h := s.Host
		if s.IncludeSubdomains {
			h = "*." + h
		}
		out = append(out, h)
	}
	return out
}

func (w *world) audits(name string) int {
	w.t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", w.org, "audit."+name).Scan(&n)
	}); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func (w *world) configVersion() string {
	return w.str("SELECT config_version::text FROM pc.gateways WHERE id = $1", w.gateway)
}

// TestHR749_AddingASiteWaitsForASecondPerson: an addition is a protected
// change: nothing is listed until a different person confirms it with a
// security key; then the browser step reads it, the gateways' configuration
// version moves, and it is audited with the host, subdomains, compare and
// the selector count; removal applies at once, audited, and moves the
// version again.
func TestHR749_AddingASiteWaitsForASecondPerson(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.person("alice", td.RoleSecurityAdmin), w.person("bob", td.RoleSecurityAdmin)
	v0 := w.configVersion()
	held, err := w.svc.Add(alice.page, app.Site{
		Host: "docs.example.com", IncludeSubdomains: true, Compare: true,
		ClickSelectors: []string{"button.delete", "a.pay"}, Note: "docs",
	}, "our docs site")
	if err != nil || held == nil {
		t.Fatalf("add: %v %v", held, err)
	}
	if got := w.listed(); len(got) != 0 || w.configVersion() != v0 {
		t.Fatalf("listed before confirmation: %v (version %s → %s)", got, v0, w.configVersion())
	}
	if _, err := w.confirm(alice, held.Request); err == nil {
		t.Fatal("the author confirmed her own addition")
	}
	if _, err := w.confirm(bob, held.Request); err != nil {
		t.Fatalf("bob confirms: %v", err)
	}
	if got := w.listed(); len(got) != 1 || got[0] != "*.docs.example.com" {
		t.Fatalf("after confirmation: %v", got)
	}
	v1 := w.configVersion()
	if v1 == v0 {
		t.Fatal("the gateways' configuration version did not move on an addition")
	}
	if w.audits(auditkind.BrowserSiteAdded) != 1 {
		t.Fatal("the addition is not audited")
	}
	body := w.str("SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE kind = $1", "audit."+auditkind.BrowserSiteAdded)
	for _, want := range []string{`"host":"docs.example.com"`, `"include_subdomains":"true"`, `"compare":"true"`, `"selector_count":"2"`} {
		if !strings.Contains(body, want) {
			t.Errorf("audit lacks %s: %s", want, body)
		}
	}
	if _, err := w.svc.Add(alice.page, app.Site{Host: "docs.example.com", IncludeSubdomains: true}, "again"); !errors.Is(err, app.ErrListed) {
		t.Fatalf("adding a listed site: %v", err)
	}
	rows, err := w.svc.List(alice.page)
	if err != nil || len(rows) != 1 || !rows[0].Compare || len(rows[0].ClickSelectors) != 2 {
		t.Fatalf("list: %+v %v", rows, err)
	}
	if err := w.svc.Remove(alice.page, rows[0].ID, "site retired"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := w.listed(); len(got) != 0 || w.audits(auditkind.BrowserSiteRemoved) != 1 || w.configVersion() == v1 {
		t.Fatalf("after removal: %v, version %s", got, w.configVersion())
	}
	if err := w.svc.Remove(alice.page, rows[0].ID, "again"); !errors.Is(err, app.ErrMissing) {
		t.Fatalf("removing a removed site: %v", err)
	}
}

// TestHR749_OnlyValidSitesFromAPersonWithManage: a malformed host, too many
// or too long selectors, a long note, a missing reason, a person without
// org.owned_accounts.manage and a service account are refused, and nothing
// is filed; the database refuses a malformed row too.
func TestHR749_OnlyValidSitesFromAPersonWithManage(t *testing.T) {
	w := newWorld(t)
	alice := w.person("alice", td.RoleSecurityAdmin)
	seventeen := make([]string, 17)
	for i := range seventeen {
		seventeen[i] = "a"
	}
	for name, tc := range map[string]struct {
		site   app.Site
		reason string
		want   error
	}{
		"ip":             {app.Site{Host: "10.0.0.1"}, "r", app.ErrHost},
		"one label":      {app.Site{Host: "localhost"}, "r", app.ErrHost},
		"port":           {app.Site{Host: "example.com:8443"}, "r", app.ErrHost},
		"upper case":     {app.Site{Host: "Example.com"}, "r", app.ErrHost},
		"wildcard":       {app.Site{Host: "*.example.com"}, "r", app.ErrHost},
		"17 selectors":   {app.Site{Host: "example.com", ClickSelectors: seventeen}, "r", app.ErrSelectors},
		"long selector":  {app.Site{Host: "example.com", ClickSelectors: []string{strings.Repeat("a", 257)}}, "r", app.ErrSelectors},
		"empty selector": {app.Site{Host: "example.com", ClickSelectors: []string{""}}, "r", app.ErrSelectors},
		"long note":      {app.Site{Host: "example.com", Note: strings.Repeat("n", 257)}, "r", app.ErrNote},
		"no reason":      {app.Site{Host: "example.com"}, "", app.ErrReason},
	} {
		if _, err := w.svc.Add(alice.page, tc.site, tc.reason); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	viewer := w.person("victor", td.RoleViewer)
	if _, err := w.svc.Add(viewer.page, app.Site{Host: "example.com"}, "mine"); err == nil {
		t.Fatal("a person without manage filed an addition")
	}
	if _, err := w.svc.List(viewer.page); err == nil {
		t.Fatal("a person without org.owned_accounts.read read the list")
	}
	robot := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{
			Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
		},
		Credential: tapp.CredAccessToken, Session: ids.NewV7(),
	})
	if _, err := w.svc.Add(robot, app.Site{Host: "example.com"}, "mine"); err == nil {
		t.Fatalf("a service account filed an addition: %v", err)
	}
	if err := w.svc.Remove(robot, ids.NewV7(), "gone"); err == nil {
		t.Fatalf("a service account removed a site: %v", err)
	}
	if n := w.str("SELECT count(*)::text FROM pc.change_requests WHERE org_id = $1", w.org); n != "0" {
		t.Fatalf("%s change requests filed", n)
	}
	// The table's own checks refuse what Go would refuse.
	for _, row := range []struct{ host, note string }{
		{"10.0.0.1", ""}, {"localhost", ""}, {"Example.com", ""}, {"example.com", strings.Repeat("n", 257)},
	} {
		err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO pc.browser_sites (id, org_id, host, include_subdomains, note, created_by)
				VALUES ($1, $2, $3, false, $4, 'test')`, ids.NewV7(), w.org, row.host, row.note)
			return err
		})
		if err == nil {
			t.Errorf("the table took %q / %d-char note", row.host, len(row.note))
		}
	}
	err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.browser_sites (id, org_id, host, include_subdomains, click_selectors, created_by)
			VALUES ($1, $2, 'example.com', false, $3, 'test')`, ids.NewV7(), w.org, seventeen)
		return err
	})
	if err == nil {
		t.Error("the table took 17 selectors")
	}
}

// TestHR749_AtMost500SitesPerOrg: the 501st addition is refused
// (BROWSER_SITE_LIMIT) before anything is filed.
func TestHR749_AtMost500SitesPerOrg(t *testing.T) {
	w := newWorld(t)
	alice := w.person("alice", td.RoleSecurityAdmin)
	w.exec(`INSERT INTO pc.browser_sites (id, org_id, host, include_subdomains, created_by)
		SELECT gen_random_uuid(), $1, 's' || g || '.example.com', false, 'test' FROM generate_series(1, 499) g`, w.org)
	held, err := w.svc.Add(alice.page, app.Site{Host: "last.example.com"}, "the 500th")
	if err != nil || held == nil {
		t.Fatalf("the 500th: %v", err)
	}
	w.exec(`INSERT INTO pc.browser_sites (id, org_id, host, include_subdomains, created_by)
		VALUES (gen_random_uuid(), $1, 's500.example.com', false, 'test')`, w.org)
	if _, err := w.svc.Add(alice.page, app.Site{Host: "more.example.com"}, "the 501st"); !errors.Is(err, app.ErrLimit) {
		t.Fatalf("the 501st: %v", err)
	}
}

// compareWorld is a world with a local connection served by w.gateway.
func compareWorld(t *testing.T) (*world, ids.UUID) {
	t.Helper()
	w := newWorld(t)
	conn := ids.NewV7()
	w.exec(`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, access_mode, created_by, updated_by)
		VALUES ($1, $2, 'browser', 'local', $3, 'pc.browser', 'none', 'test', 'test')`, w.org, conn, w.gateway)
	w.exec(`INSERT INTO pc.browser_sites (id, org_id, host, include_subdomains, compare, created_by) VALUES
		(gen_random_uuid(), $1, 'news.example.com', true, true, 'test'),
		(gen_random_uuid(), $1, 'shop.example.com', false, false, 'test')`, w.org)
	return w, conn
}

func mismatch(host string) app.PageCompare {
	return app.PageCompare{
		Run: ids.NewV7(), Transaction: ids.NewV7(), Host: host, PathSHA256: strings.Repeat("ab", 32),
		AgentStatus: 200, PlainStatus: 200, AgentBytes: 1200, PlainBytes: 5400, SimilarityPermille: 125,
	}
}

// TestHR750_AComparedMismatchIsRecordedOncePerHour: the serving gateway's
// report on a compare site is recorded as browser.cloaking_suspected, with
// the gateway as actor, digests and numbers only; the same page again
// within the hour is not recorded; after the hour it is.
func TestHR750_AComparedMismatchIsRecordedOncePerHour(t *testing.T) {
	w, conn := compareWorld(t)
	now := time.Now()
	c := &app.Compares{Pool: w.pool, Now: func() time.Time { return now }}
	ctx := context.Background()
	in := mismatch("eu.news.example.com")
	if ok, err := c.ReportPageCompare(ctx, w.org, w.gateway, conn, in); err != nil || !ok {
		t.Fatalf("first report: %v %v", ok, err)
	}
	if ok, err := c.ReportPageCompare(ctx, w.org, w.gateway, conn, in); err != nil || ok {
		t.Fatalf("again within the hour: %v %v", ok, err)
	}
	other := in
	other.PathSHA256 = strings.Repeat("cd", 32)
	if ok, err := c.ReportPageCompare(ctx, w.org, w.gateway, conn, other); err != nil || !ok {
		t.Fatalf("another page: %v %v", ok, err)
	}
	now = now.Add(app.CompareThrottle)
	if ok, err := c.ReportPageCompare(ctx, w.org, w.gateway, conn, in); err != nil || !ok {
		t.Fatalf("after the hour: %v %v", ok, err)
	}
	if n := w.audits(auditkind.BrowserCloakingSuspected); n != 3 {
		t.Fatalf("%d records", n)
	}
	body := w.str("SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE kind = $1 ORDER BY id LIMIT 1",
		"audit."+auditkind.BrowserCloakingSuspected)
	for _, want := range []string{
		`"host":"eu.news.example.com"`, `"path_sha256":"` + in.PathSHA256 + `"`, `"agent_status":"200"`, `"plain_bytes":"5400"`,
		`"similarity_permille":"125"`, `"run_id":"` + in.Run.String() + `"`, `"object":{"id":"` + conn.String() + `","type":"connection"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("record lacks %s: %s", want, body)
		}
	}
	// Digests and numbers only: the nine details and nothing else.
	if n := strings.Count(body, `":"`); n != 9+4 { // nine details; name, outcome, the object id and type
		t.Errorf("record carries %d string members: %s", n, body)
	}
	if actor := w.str("SELECT actor_id FROM pc.ledger_entries WHERE kind = $1 ORDER BY id LIMIT 1",
		"audit."+auditkind.BrowserCloakingSuspected); !strings.Contains(actor, w.gateway.String()) {
		t.Errorf("actor %s, want the gateway %s", actor, w.gateway)
	}
}

// TestHR750_OnlyTheServingGatewayAndACompareSite: another gateway, an
// unknown connection, a listed site not marked for the compare, an unlisted
// host and an IP host are refused, and nothing is recorded.
func TestHR750_OnlyTheServingGatewayAndACompareSite(t *testing.T) {
	w, conn := compareWorld(t)
	other := ids.NewV7()
	w.exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", w.org, other)
	c := &app.Compares{Pool: w.pool}
	ctx := context.Background()
	for name, tc := range map[string]struct {
		gateway, conn ids.UUID
		host          string
		want          error
	}{
		"other gateway":   {other, conn, "news.example.com", app.ErrCompareConnection},
		"unknown conn":    {w.gateway, ids.NewV7(), "news.example.com", app.ErrCompareConnection},
		"not compared":    {w.gateway, conn, "shop.example.com", app.ErrCompareHost},
		"unlisted":        {w.gateway, conn, "evil.example.net", app.ErrCompareHost},
		"lookalike":       {w.gateway, conn, "badnews.example.com", app.ErrCompareHost},
		"ip":              {w.gateway, conn, "10.0.0.1", app.ErrCompareHost},
		"subdomain owner": {w.gateway, conn, "example.com", app.ErrCompareHost},
	} {
		if ok, err := c.ReportPageCompare(ctx, w.org, tc.gateway, tc.conn, mismatch(tc.host)); ok || !errors.Is(err, tc.want) {
			t.Errorf("%s: %v %v, want %v", name, ok, err, tc.want)
		}
	}
	if n := w.audits(auditkind.BrowserCloakingSuspected); n != 0 {
		t.Fatalf("%d records", n)
	}
}
