// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package support_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const issuer = "https://idp.test"

// plans is a fixed plan for every org.
type plans struct {
	mode    entitlements.Mode
	edition billing.Edition
}

func (p *plans) Mode() entitlements.Mode { return p.mode }
func (p *plans) For(context.Context, ids.OrgID) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: p.edition, Status: billing.StatusValid}, nil
}

type fixture struct {
	t                 *testing.T
	d                 *dbtest.DB
	pool              *db.Pool
	plans             *plans
	svc               *support.Service
	staffOrg, custOrg ids.OrgID
	account, account2 ids.UUID // the staff members' accounts
	staffUser, staff2 ids.UUID
	staffKey, staff2K ids.UUID
	admin, adminKey   ids.UUID // an org admin of the customer
	twin, twinKey     ids.UUID // an org admin of the customer linked to the staff member's account
	service           ids.UUID // a service account holding org_admin
	cfg               support.Config
	keyN              byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		t: t, d: d, pool: d.AppPool(t), plans: &plans{mode: entitlements.ModeExternal, edition: billing.Enterprise},
		staffOrg: ids.New[ids.Org](), custOrg: ids.New[ids.Org](), account: ids.NewV7(), account2: ids.NewV7(),
		staffUser: ids.NewV7(), staff2: ids.NewV7(), admin: ids.NewV7(), twin: ids.NewV7(), service: ids.NewV7(),
	}
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'staff'), ($2, 'customer')", f.staffOrg, f.custOrg)
	d.AdminExec(t, "INSERT INTO pc.accounts (id, issuer, subject, email) VALUES ($1, $3, 'staff-1', 'one@support.test'), ($2, $3, 'staff-2', 'two@support.test')",
		f.account, f.account2, issuer)
	f.user(f.staffOrg, f.staffUser, "staff-1", &f.account)
	f.user(f.staffOrg, f.staff2, "staff-2", &f.account2)
	f.user(f.custOrg, f.admin, "admin", nil)
	f.user(f.custOrg, f.twin, "staff-1", &f.account)
	f.staffKey, f.staff2K = f.key(f.staffOrg, f.staffUser), f.key(f.staffOrg, f.staff2)
	f.adminKey, f.twinKey = f.key(f.custOrg, f.admin), f.key(f.custOrg, f.twin)
	for _, u := range []ids.UUID{f.admin, f.twin} {
		d.AdminExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`,
			f.custOrg, ids.NewV7(), u)
	}
	d.AdminExec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'robot', 'test')", f.custOrg, f.service)
	d.AdminExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by) VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`,
		f.custOrg, ids.NewV7(), f.service)
	f.cfg = support.Config{StaffOrg: f.staffOrg, Staff: []support.Identity{{Issuer: issuer, Subject: "staff-1"}, {Issuer: issuer, Subject: "staff-2"}}}
	f.svc = support.New(f.pool, f.cfg, f.plans, nil, nil)
	return f
}

func (f *fixture) user(org ids.OrgID, id ids.UUID, subject string, account *ids.UUID) {
	f.d.AdminExec(f.t, "INSERT INTO pc.users (org_id, id, issuer, subject, email, account_id) VALUES ($1, $2, $3, $4, $4 || '@example.test', $5)",
		org, id, issuer, subject, account)
}

func (f *fixture) key(org ids.OrgID, user ids.UUID) ids.UUID {
	f.keyN++
	id := ids.NewV7()
	f.d.AdminExec(f.t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		org, id, user, bytes.Repeat([]byte{f.keyN}, 16), bytes.Repeat([]byte{f.keyN}, 32))
	return id
}

func person(org ids.OrgID, user ids.UUID) tapp.Caller {
	bs := []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}
	return tapp.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: bs},
		Credential: tapp.CredBrowserSession, Session: ids.NewV7(),
	}
}

func fresh(key ids.UUID) *stepup.StepUp { return &stepup.StepUp{Credential: key, At: time.Now()} }

func (f *fixture) staff(user, key ids.UUID) support.Staff {
	return support.Staff{Caller: person(f.staffOrg, user), StepUp: fresh(key)}
}

func (f *fixture) as(c tapp.Caller) context.Context { return tapp.WithCaller(context.Background(), c) }

func (f *fixture) adminCtx() context.Context { return f.as(person(f.custOrg, f.admin)) }

func (f *fixture) request(scope string) support.Request {
	f.t.Helper()
	r, err := f.svc.Request(context.Background(), f.staff(f.staffUser, f.staffKey), support.RequestInput{
		Org: f.custOrg, Task: "Investigate ticket 4711: held merges never release", Scope: scope, Hours: 4,
	})
	if err != nil {
		f.t.Fatalf("request: %v", err)
	}
	return r
}

func (f *fixture) approve(r support.Request) support.Grant {
	f.t.Helper()
	_, g, err := f.svc.Decide(f.adminCtx(), r.ID, true, fresh(f.adminKey))
	if err != nil {
		f.t.Fatalf("approve: %v", err)
	}
	return *g
}

func (f *fixture) open(r support.Request) support.Opened {
	f.t.Helper()
	o, err := f.svc.Open(context.Background(), f.staff(f.staffUser, f.staffKey), f.custOrg, r.ID)
	if err != nil {
		f.t.Fatalf("open: %v", err)
	}
	return o
}

func (f *fixture) authenticate(cookie string) (tapp.Caller, error) {
	return f.svc.Authenticate(context.Background(), cookie, "/pantherclaw.v1.AgentService/ListAgents")
}

// backdate moves a grant's window into the past (triggers off for the
// fixture only).
func (f *fixture) backdate(grant ids.UUID) {
	f.d.AdminDo(f.t, func(c *pgx.Conn) error {
		ctx := context.Background()
		if _, err := c.Exec(ctx, "SET session_replication_role = replica"); err != nil {
			return err
		}
		_, err := c.Exec(ctx, "UPDATE pc.support_access_grants SET starts_at = now() - interval '5 hours', expires_at = now() - interval '1 hour' WHERE id = $1", grant)
		if err != nil {
			return err
		}
		_, err = c.Exec(ctx, "SET session_replication_role = origin")
		return err
	})
}

// TestHR385_OnlyAnApprovedUnexpiredUnrevokedGrantAuthenticates: there is
// no standing access. No session opens before an approval; an approved
// grant opens one, whose subject holds only the support roles; revoking
// the grant, its expiry, removing the staff member from the list, a plan
// that is not Enterprise and a self-hosted licence each end it.
func TestHR385_OnlyAnApprovedUnexpiredUnrevokedGrantAuthenticates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.request("")
	if _, err := f.svc.Open(ctx, f.staff(f.staffUser, f.staffKey), f.custOrg, r.ID); !errors.Is(err, support.ErrNoGrant) {
		t.Fatalf("open before approval: %v", err)
	}
	g := f.approve(r)
	if g.State != support.GrantActive || g.ExpiresAt.Sub(g.StartsAt) != 4*time.Hour {
		t.Fatalf("grant = %+v", g)
	}
	// Another staff member never opens someone else's grant.
	if _, err := f.svc.Open(ctx, f.staff(f.staff2, f.staff2K), f.custOrg, r.ID); !errors.Is(err, support.ErrNoGrant) {
		t.Fatalf("open by another staff member: %v", err)
	}
	o := f.open(r)
	c, err := f.authenticate(o.Secret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !c.Support() || c.Principal.ID != f.account || c.SupportGrant != g.ID || c.Credential != tapp.CredSupportSession {
		t.Fatalf("caller = %+v", c)
	}
	if !c.CanAnywhere(td.PermAgentRead) || c.CanAnywhere(td.PermAgentManage) || c.CanAnywhere(td.PermEvidenceReadRestricted) {
		t.Fatal("a read-only support session holds the wrong permissions")
	}

	// Revoked: the session ends at once and no new one opens.
	if _, err := f.svc.Revoke(f.adminCtx(), g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.authenticate(o.Secret); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("after revoke: %v", err)
	}
	if _, err := f.svc.Open(ctx, f.staff(f.staffUser, f.staffKey), f.custOrg, r.ID); !errors.Is(err, support.ErrNoGrant) {
		t.Fatalf("open after revoke: %v", err)
	}

	// Expired.
	r2 := f.request(tapp.SupportScopeReadPlusEvidence)
	g2 := f.approve(r2)
	o2 := f.open(r2)
	c2, err := f.authenticate(o2.Secret)
	if err != nil || !c2.CanAnywhere(td.PermEvidenceReadRestricted) {
		t.Fatalf("evidence scope: %v", err)
	}
	f.backdate(g2.ID)
	if _, err := f.authenticate(o2.Secret); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("after expiry: %v", err)
	}
	var reason string
	f.d.AdminQueryRow(t, "SELECT end_reason FROM pc.support_sessions WHERE id = $1", []any{o2.Session}, &reason)
	if reason != "GRANT_ENDED" {
		t.Errorf("expired grant ended the session with %q", reason)
	}

	// Unlisted staff, a plan that is not Enterprise, a self-hosted server.
	r3 := f.request("")
	f.approve(r3)
	o3 := f.open(r3)
	unlisted := support.New(f.pool, support.Config{StaffOrg: f.staffOrg, Staff: []support.Identity{{Issuer: issuer, Subject: "staff-2"}}}, f.plans, nil, nil)
	f.plans.edition = billing.Business
	if _, err := f.authenticate(o3.Secret); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("business plan: %v", err)
	}
	if _, err := f.svc.Request(ctx, f.staff(f.staffUser, f.staffKey), support.RequestInput{Org: f.custOrg, Task: "x", Hours: 1}); !errors.Is(err, support.ErrEdition) {
		t.Fatalf("request on business: %v", err)
	}
	f.plans.edition, f.plans.mode = billing.Enterprise, entitlements.ModeLicence
	if _, err := f.authenticate(o3.Secret); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("licence mode: %v", err)
	}
	if _, err := f.svc.Request(ctx, f.staff(f.staffUser, f.staffKey), support.RequestInput{Org: f.custOrg, Task: "x", Hours: 1}); !errors.Is(err, support.ErrNeedsHosted) {
		t.Fatalf("request in licence mode: %v", err)
	}
	f.plans.mode = entitlements.ModeExternal
	if _, err := unlisted.Authenticate(ctx, o3.Secret, "/p"); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("unlisted staff: %v", err)
	}
	if _, err := f.authenticate(o3.Secret); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatal("a session ended for an unlisted staff member came back")
	}

	// The tenancy loader gives a support principal bindings only from a
	// grant in force.
	err = f.pool.InTenantTx(ctx, f.custOrg, func(ctx context.Context, tx db.TenantTx) error {
		bs, err := tapp.SupportBindings(ctx, dbq.New(tx), f.custOrg, f.account2)
		if err != nil || len(bs) != 0 {
			t.Errorf("bindings without a grant = %v, %v", bs, err)
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
}

// TestHR386_ApprovalNeedsAnOrgAdminsStepUpAndNeverTheRequester: deciding
// needs support.manage, a person, and a fresh step-up with their own
// active key; the requesting account never decides, even as an org admin
// of the org (and the database refuses it too); asking needs the staff
// member's own step-up.
func TestHR386_ApprovalNeedsAnOrgAdminsStepUpAndNeverTheRequester(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.Request(ctx, support.Staff{Caller: person(f.staffOrg, f.staffUser)}, support.RequestInput{
		Org: f.custOrg, Task: "x", Hours: 1,
	}); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("request without a step-up: %v", err)
	}
	if _, err := f.svc.Request(ctx, support.Staff{Caller: person(f.staffOrg, f.staffUser), StepUp: fresh(f.staff2K)}, support.RequestInput{
		Org: f.custOrg, Task: "x", Hours: 1,
	}); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("request with another person's key: %v", err)
	}
	for name, in := range map[string]support.RequestInput{
		"no task":    {Org: f.custOrg, Hours: 1},
		"long task":  {Org: f.custOrg, Task: strings.Repeat("a", 201), Hours: 1},
		"control":    {Org: f.custOrg, Task: "a\nb", Hours: 1},
		"73 hours":   {Org: f.custOrg, Task: "x", Hours: 73},
		"scope":      {Org: f.custOrg, Task: "x", Hours: 1, Scope: "READ_WRITE"},
		"staff org":  {Org: f.staffOrg, Task: "x", Hours: 1},
		"no org":     {Task: "x", Hours: 1},
		"zero hours": {Org: f.custOrg, Task: "x"},
	} {
		if _, err := f.svc.Request(ctx, f.staff(f.staffUser, f.staffKey), in); !errors.Is(err, support.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := f.request("")
	if _, _, err := f.svc.Decide(f.adminCtx(), r.ID, true, nil); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("approve over the API: %v", err)
	}
	stale := &stepup.StepUp{Credential: f.adminKey, At: time.Now().Add(-6 * time.Minute)}
	if _, _, err := f.svc.Decide(f.adminCtx(), r.ID, true, stale); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("stale step-up: %v", err)
	}
	if _, _, err := f.svc.Decide(f.adminCtx(), r.ID, true, fresh(f.twinKey)); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("another person's key: %v", err)
	}
	svcCaller := tapp.Caller{Subject: td.Subject{
		Org: f.custOrg, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: f.service},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: f.custOrg.UUID()}}},
	}}
	if _, _, err := f.svc.Decide(f.as(svcCaller), r.ID, true, fresh(f.adminKey)); !errors.Is(err, support.ErrHuman) {
		t.Fatalf("service account: %v", err)
	}
	if _, _, err := f.svc.Decide(f.as(person(f.custOrg, f.twin)), r.ID, true, fresh(f.twinKey)); !errors.Is(err, support.ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	if _, _, err := f.svc.Decide(f.as(person(f.custOrg, f.twin)), r.ID, false, fresh(f.twinKey)); !errors.Is(err, support.ErrSelfApproval) {
		t.Fatalf("self denial: %v", err)
	}
	var refused int
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.support.self_decision_refused'",
		[]any{f.custOrg}, &refused)
	if refused != 2 {
		t.Errorf("self decisions audited %d times, want 2", refused)
	}
	// The database refuses it whatever the application does.
	err := f.pool.InTenantTx(ctx, f.custOrg, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.support_access_requests SET state = 'APPROVED', decided_by = $2, decided_credential = $3,
			decided_at = now() WHERE org_id = $1 AND id = $4`, f.custOrg, f.twin, f.twinKey, r.ID)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Fatalf("self approval in the database: %v", err)
	}
	if _, _, err := f.svc.Decide(f.adminCtx(), r.ID, false, fresh(f.adminKey)); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if _, _, err := f.svc.Decide(f.adminCtx(), r.ID, true, fresh(f.adminKey)); !errors.Is(err, support.ErrNotPending) {
		t.Fatalf("decide twice: %v", err)
	}
}

// TestHR388_EverySupportSessionCallIsAuditedInTheCustomersLedger: each
// authenticated call is one ledger entry of the customer org, by
// support/<account>, naming the procedure and the grant; the request, the
// approval and the session are audited too.
func TestHR388_EverySupportSessionCallIsAuditedInTheCustomersLedger(t *testing.T) {
	f := newFixture(t)
	r := f.request("")
	g := f.approve(r)
	o := f.open(r)
	for _, p := range []string{"/pantherclaw.v1.AgentService/ListAgents", "/pantherclaw.v1.AgentService/UpdateAgent"} {
		if _, err := f.svc.Authenticate(context.Background(), o.Secret, p); err != nil {
			t.Fatal(err)
		}
	}
	var calls int
	f.d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.support.call'
		AND actor_type = 'support' AND actor_id = $2 AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'grant' = $3
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'procedure' LIKE '/pantherclaw.v1.AgentService/%'`,
		[]any{f.custOrg, f.account.String(), g.ID.String()}, &calls)
	if calls != 2 {
		t.Errorf("support calls audited = %d, want 2", calls)
	}
	for _, kind := range []string{"audit.support.access_requested", "audit.support.access_approved", "audit.support.session_opened"} {
		var n int
		f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", []any{f.custOrg, kind}, &n)
		if n != 1 {
			t.Errorf("%s recorded %d times", kind, n)
		}
	}
}

// TestT174_RogueStaffCannotReachAnOrgWithoutTheCustomer: a staff member
// cannot approve their own request, open someone else's grant, open a
// session without a grant or a step-up, or act as staff without being on
// the list; non-staff users of the staff org are not staff.
func TestT174_RogueStaffCannotReachAnOrgWithoutTheCustomer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.request("")
	if _, err := f.svc.Open(ctx, support.Staff{Caller: person(f.staffOrg, f.staffUser)}, f.custOrg, r.ID); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("open without a step-up: %v", err)
	}
	if _, _, err := f.svc.Decide(f.as(person(f.custOrg, f.twin)), r.ID, true, fresh(f.twinKey)); !errors.Is(err, support.ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	// A staff-org user whose account is not listed is no staff member.
	only2 := support.New(f.pool, support.Config{StaffOrg: f.staffOrg, Staff: []support.Identity{{Issuer: issuer, Subject: "staff-2"}}}, f.plans, nil, nil)
	if _, err := only2.Request(ctx, f.staff(f.staffUser, f.staffKey), support.RequestInput{Org: f.custOrg, Task: "x", Hours: 1}); !errors.Is(err, support.ErrNotStaff) {
		t.Fatalf("unlisted staff: %v", err)
	}
	if ok, err := only2.IsStaff(ctx, person(f.staffOrg, f.staffUser)); ok || err != nil {
		t.Fatalf("IsStaff unlisted = %v, %v", ok, err)
	}
	// A customer user, however privileged, is not staff.
	if _, err := f.svc.Request(ctx, support.Staff{Caller: person(f.custOrg, f.admin), StepUp: fresh(f.adminKey)},
		support.RequestInput{Org: f.custOrg, Task: "x", Hours: 1}); !errors.Is(err, support.ErrNotStaff) {
		t.Fatalf("customer as staff: %v", err)
	}
	f.approve(r)
	if _, err := f.svc.Open(ctx, f.staff(f.staff2, f.staff2K), f.custOrg, r.ID); !errors.Is(err, support.ErrNoGrant) {
		t.Fatalf("someone else's grant: %v", err)
	}
	if _, err := f.svc.StaffRequest(ctx, person(f.staffOrg, f.staff2), f.custOrg.UUID(), r.ID); !errors.Is(err, support.ErrRequestNotFound) {
		t.Fatalf("someone else's request: %v", err)
	}
}

// TestT175_AStolenSupportSessionEndsWithItsGrant: a stolen support cookie
// works only while its grant is in force and the session is live, only in
// its own org, and the staff member's logout ends it.
func TestT175_AStolenSupportSessionEndsWithItsGrant(t *testing.T) {
	f := newFixture(t)
	r := f.request("")
	f.approve(r)
	o := f.open(r)
	other := ids.New[ids.Org]()
	forged := strings.Replace(o.Secret, strings.ReplaceAll(f.custOrg.String(), "-", ""), strings.ReplaceAll(other.String(), "-", ""), 1)
	if forged == o.Secret {
		t.Fatal("the cookie does not carry its org")
	}
	if _, err := f.authenticate(forged); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("cookie moved to another org: %v", err)
	}
	if _, err := f.authenticate(o.Secret + "x"); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("tampered cookie: %v", err)
	}
	// Idle for longer than 30 minutes ends it.
	f.d.AdminExec(t, "UPDATE pc.support_sessions SET last_seen_at = now() - interval '31 minutes' WHERE id = $1", o.Session)
	if _, err := f.authenticate(o.Secret); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("idle session: %v", err)
	}
	o2 := f.open(r)
	if err := f.svc.Logout(context.Background(), o2.Secret); err != nil {
		t.Fatal(err)
	}
	if _, err := f.authenticate(o2.Secret); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("after logout: %v", err)
	}
	// A session never outlives its grant.
	o3 := f.open(r)
	var sessionEnd, grantEnd time.Time
	f.d.AdminQueryRow(t, `SELECT s.expires_at, g.expires_at FROM pc.support_sessions s JOIN pc.support_access_grants g
		ON g.org_id = s.org_id AND g.id = s.grant_id WHERE s.id = $1`, []any{o3.Session}, &sessionEnd, &grantEnd)
	if sessionEnd.After(grantEnd) {
		t.Errorf("session ends %v after its grant %v", sessionEnd, grantEnd)
	}
}
