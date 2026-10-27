// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/datarequests"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/server"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/usage"
)

// The M13 exit journey (G0 M13 exit criteria, wave 3). The same HTTP steps
// run against the local stack (TestE2E_M13_ExitJourney) and, once hosted
// staging exists, against it (TestE2E_M13_StagingJourney, skipped unless
// PC_E2E_STAGING_URL is set; docs/runbooks/m13-exit.md). A local run is
// local evidence only: it is never the hosted L3 evidence of the exit.

// m13Client calls one deployment the way a client outside it does: over
// HTTP at base, as a browser session (cookies from c's jar, same origin) or
// with a bearer credential.
type m13Client struct {
	base   string
	c      *http.Client
	bearer string
}

// connect sends one Connect JSON call and returns the status, the body and
// the response headers.
func (m m13Client) connect(t *testing.T, procedure, body string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, m.base+procedure, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if m.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+m.bearer)
	} else {
		req.Header.Set("PC-CSRF", "1")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Origin", m.base)
	}
	res, err := m.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, string(out), res.Header
}

// readyz returns /readyz's status and body.
func (m m13Client) readyz(t *testing.T) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, m.base+"/readyz", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	return res.StatusCode, strings.TrimSpace(string(out))
}

// journeyReady checks the deployment is ready: database, schema, workers
// and no maintenance hold (HR-370, HR-379).
func (m m13Client) journeyReady(t *testing.T) {
	t.Helper()
	if code, body := m.readyz(t); code != http.StatusOK || !strings.Contains(body, `"ready":true`) {
		t.Fatalf("/readyz = %d %s, want ready", code, body)
	}
}

// journeyUsage checks the org's usage meters are visible to the caller
// and not enforced (HR-377): ListUsage answers and today has at least one
// agent.
func (m m13Client) journeyUsage(t *testing.T) {
	t.Helper()
	code, body, _ := m.connect(t, pantherclawv1connect.UsageServiceListUsageProcedure, `{"days":7}`)
	if code != http.StatusOK {
		t.Fatalf("ListUsage = %d %s", code, body)
	}
	var out struct {
		Days []struct {
			Day    string `json:"day"`
			Agents int    `json:"agents"`
		} `json:"days"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || len(out.Days) == 0 || out.Days[0].Agents < 1 {
		t.Fatalf("ListUsage = %s (%v), want a metered day with an agent", body, err)
	}
}

// pinTrust runs `pclaw evidence trust` against base, as a user pins the
// deployment's evidence keys on first use, and returns the trust file.
func pinTrust(t *testing.T, base string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "trust.json")
	var out, errb bytes.Buffer
	if code := pclaw.Run(context.Background(), []string{"evidence", "trust", "--out", file, "--server", base}, &out, &errb, noEnv, pclaw.Options{}); code != 0 {
		t.Fatalf("pclaw evidence trust: %d %s %s", code, out.String(), errb.String())
	}
	return file
}

// verifyOffline runs `pclaw verify [kind] FILE --trust TRUST --json [flags]`
// with an HTTP client that fails the test on any request, and returns the
// report; it fails the test when the exit code and the report disagree.
func verifyOffline(t *testing.T, trust, kind, file string, flags ...string) *bundle.Report {
	t.Helper()
	args := []string{"verify"}
	if kind != "" {
		args = append(args, kind)
	}
	args = append(append(args, file, "--trust", trust, "--json"), flags...)
	var out, errb bytes.Buffer
	code := pclaw.Run(context.Background(), args, &out, &errb, noEnv, pclaw.Options{HTTPClient: &http.Client{Transport: offline{t}}})
	var r bundle.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("pclaw %v: %d %q %q", args, code, out.String(), errb.String())
	}
	if (code == 0) == r.Failed() {
		t.Fatalf("pclaw %v exit %d for a %s report", args, code, r.Result)
	}
	return &r
}

// TestE2E_M13_ExitJourney is the M13 exit journey on the local stack
// (G0 M13 exit criteria): the L3 journey and the M13 pieces that run
// without hosted infrastructure.
//
//  1. An organization is created (dev seed, as `org create` does), on an
//     active plan (the billing extension's event); its gateway enrolls with
//     its one-time token and gets its certificate over mTLS (HR-181), and
//     its agent's workload is enrolled.
//  2. Its admin signs in (`pclaw login`) and an approver signs in in a
//     browser and registers a security key.
//  3. An agent's refund is decided through the gateway (ALLOW, ACCEPTED);
//     its receipts are checkpointed, exported and verified offline against
//     the keys pinned on first use (HR-196).
//  4. Readiness refuses a pending schema and recovers (HR-370); the admin's
//     usage meters are visible (HR-377); a flooding browser session is
//     rate limited with Retry-After (HR-375).
//  5. A support access request is approved by the org's admin with a
//     security key, used read-only, revoked, and refused after (HR-385..388).
//  6. A tenant export is downloaded by the org's admin and verifies offline
//     (HR-390, HR-399).
//  7. The org is deleted after its cancellation window on an accelerated
//     clock, once the operator acknowledged the security-event copy; its
//     gateway fails closed, and the signed deletion record verifies offline
//     (HR-390, HR-392, HR-383).
//
// The lapse reminders and the day-90 deletion on an accelerated clock are
// TestHR393_*; a break-glass activation is TestHR389_*.
func TestE2E_M13_ExitJourney(t *testing.T) {
	p := inProcessIdP(t)
	const perCredential = 40
	s := start(t, options{budget: "1000.00", people: &p, billing: true, apiPerCredential: perCredential})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	org := s.org.String()

	// 1. The org, its plan, its gateway over mTLS and its agent.
	var certs, agents int
	s.query(t, "SELECT count(*) FROM pc.gateway_certs WHERE org_id = $1 AND revoked_at IS NULL", []any{s.org}, &certs)
	s.query(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1", []any{s.org}, &agents)
	if certs < 1 || agents < 1 {
		t.Fatalf("org %s: %d gateway certificates, %d agents", org, certs, agents)
	}
	if plan := s.row(t, "SELECT status FROM pc.org_entitlements WHERE org_id = $1", s.org); plan != "ACTIVE" {
		t.Fatalf("plan %q, want ACTIVE", plan)
	}

	// 2. The admin and an approver with a security key.
	approver(t, s, people)

	// 3. A decided action, and its evidence verified offline.
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("refund: %d %+v", code, r)
	}
	txn, err := ids.ParseUUID(r.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	pr := s.proof(t)
	pr.checkpointed(t, txn)
	auditor := s.person(t, "exit-auditor", td.RoleAuditor).ctx
	file, x := pr.export(t, auditor, "refund.json", evapp.Selection{Transactions: []ids.UUID{txn}}, 0)
	if x.Receipts < 2 {
		t.Fatalf("export: %d receipts", x.Receipts)
	}
	rep := verifyOffline(t, pinTrust(t, s.apiURL), "", file)
	if rep.Failed() || !all(rep, "receipt.signature", bundle.Passed) || !all(rep, "entry.inclusion", bundle.Passed) {
		t.Fatalf("pclaw verify: %+v", rep.Checks)
	}

	// 4. Readiness, usage and the API rate limit.
	local := m13Client{base: s.apiURL, c: &http.Client{Timeout: 10 * time.Second}}
	local.journeyReady(t)
	latest, err := db.LatestMigration()
	if err != nil {
		t.Fatal(err)
	}
	s.db.AdminExec(t, "UPDATE pc.schema_info SET version = $1", latest-1)
	if code, body := local.readyz(t); code != http.StatusServiceUnavailable || !strings.Contains(body, `"schema":"fail"`) {
		t.Fatalf("/readyz on a pending schema = %d %s", code, body)
	}
	s.db.AdminExec(t, "UPDATE pc.schema_info SET version = $1", latest)
	local.journeyReady(t)

	um := usage.New(s.pool, nil)
	if err := um.Meter(context.Background(), s.org); err != nil {
		t.Fatalf("metering: %v", err)
	}
	admin := newBrowser(people)
	admin.signIn(t, org, "alice", "alice@example.test", false)
	console := m13Client{base: s.apiURL, c: admin.c}
	console.journeyUsage(t)

	flood := newBrowser(people)
	flood.signIn(t, org, "alice", "alice@example.test", false)
	limited := m13Client{base: s.apiURL, c: flood.c}
	var refused bool
	for i := range perCredential + 5 {
		code, body, h := limited.connect(t, pantherclawv1connect.AccessServiceWhoAmIProcedure, "{}")
		if code == http.StatusOK {
			continue
		}
		if code != http.StatusTooManyRequests || !strings.Contains(body, "RATE_LIMITED") || h.Get("Retry-After") == "" {
			t.Fatalf("call %d: %d %s (Retry-After %q)", i+1, code, body, h.Get("Retry-After"))
		}
		if i < perCredential-1 {
			t.Fatalf("rate limited after %d calls, limit %d", i, perCredential)
		}
		refused = true
		break
	}
	if !refused {
		t.Fatalf("%d calls a minute from one session were never limited", perCredential+5)
	}
	console.journeyUsage(t) // another credential of the org is not limited

	// 5. Support access: approved, read-only, revoked.
	m13SupportAccess(t, s)

	// 6. A tenant export verifies offline.
	trust := pinTrust(t, s.apiURL)
	svc := &datarequests.Service{Pool: s.pool, Deleter: s.db.Pool(t, s.db.Deleter), Keys: pr.reg, Jobs: pr.jobs, Bundles: evapp.New(s.pool, pr.origin), BackupRetentionDays: 60}
	exp := rangeExportFixture(t, s, svc, s.org)
	part, err := svc.Download(exp.admin, exp.id, 1)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	var manifest string
	s.db.AdminQueryRow(t, "SELECT manifest FROM pc.data_requests WHERE org_id = $1 AND id = $2", []any{s.org, exp.id}, &manifest)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.jws"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "part-001.zip"), part.Content, 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := verifyOffline(t, trust, "export", filepath.Join(dir, "manifest.jws"), "--parts", dir); rep.Failed() {
		t.Fatalf("pclaw verify export: %+v", rep.Checks)
	}

	// 7. Deletion after the window, on an accelerated clock.
	m13DeleteOrg(t, s, svc, trust)
}

// m13SupportAccess: hosted support staff ask for read access to s's org;
// the org's admin approves with a fresh security-key step-up; the staff
// member's session reads but holds no write or admin permission; the admin
// revokes the grant and the session is refused at once (HR-385..388). The
// service runs as the app role under FORCE RLS with the real audit writer,
// as the server's support wiring does.
func m13SupportAccess(t *testing.T, s *stack) {
	t.Helper()
	ctx := context.Background()
	staffOrg := ids.New[ids.Org]()
	account, staff, admin, staffKey, adminKey := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	s.db.AdminExec(t, "INSERT INTO pc.orgs(id,name) VALUES($1,'exit staff')", staffOrg)
	s.db.AdminExec(t, "INSERT INTO pc.accounts(id,issuer,subject,email) VALUES($1,'https://staff.test',$2,'staff@staff.test')", account, account.String())
	for i, u := range []struct {
		org       ids.OrgID
		user, key ids.UUID
		account   *ids.UUID
		subject   string
	}{{staffOrg, staff, staffKey, &account, account.String()}, {s.org, admin, adminKey, nil, admin.String()}} {
		s.db.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email,account_id) VALUES($1,$2,'https://staff.test',$3,'person@staff.test',$4)", u.org, u.user, u.subject, u.account)
		s.db.AdminExec(t, `INSERT INTO pc.webauthn_credentials(org_id,id,user_id,credential_id,public_key,alg,backup_eligible,backup_state,attestation_fmt,name)
			VALUES($1,$2,$3,$4,$5,-7,false,false,'none','exit key')`, u.org, u.key, u.user, u.key[:], bytes.Repeat([]byte{byte(i + 7)}, 32))
		s.db.AdminExec(t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','exit')", u.org, ids.NewV7(), u.user)
	}
	person := func(org ids.OrgID, user ids.UUID) tapp.Caller {
		return tapp.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
			Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}}, Credential: tapp.CredBrowserSession, Session: ids.NewV7()}
	}
	adminCtx := tapp.WithCaller(ctx, person(s.org, admin))
	fresh := func(key ids.UUID) *stepup.StepUp { return &stepup.StepUp{Credential: key, At: time.Now()} }
	svc := support.New(s.pool, support.Config{StaffOrg: staffOrg, Staff: []support.Identity{{Issuer: "https://staff.test", Subject: account.String()}}}, rangeSupportPlans{}, nil, nil)
	stf := support.Staff{Caller: person(staffOrg, staff), StepUp: fresh(staffKey)}
	req, err := svc.Request(ctx, stf, support.RequestInput{Org: s.org, Task: "Exit journey: why was the refund held", Hours: 1})
	if err != nil {
		t.Fatalf("support request: %v", err)
	}
	_, grant, err := svc.Decide(adminCtx, req.ID, true, fresh(adminKey))
	if err != nil || grant == nil {
		t.Fatalf("approve: %v", err)
	}
	opened, err := svc.Open(ctx, stf, s.org, req.ID)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	c, err := svc.Authenticate(ctx, opened.Secret, pantherclawv1connect.AgentServiceListAgentsProcedure)
	if err != nil {
		t.Fatalf("approved session: %v", err)
	}
	if err := c.Require(td.PermAgentRead, td.OrgPath(s.org)); err != nil {
		t.Fatalf("the read-only session cannot read agents: %v", err)
	}
	for _, write := range []td.Permission{td.PermRoleBind, td.PermDataExport, td.PermOrgDelete} {
		if c.CanAnywhere(write) {
			t.Fatalf("the support session holds %s", write)
		}
	}
	var calls int
	s.query(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.support.call'", []any{s.org}, &calls)
	if calls < 1 {
		t.Fatal("the support call is not in the org's audit ledger")
	}
	if _, err := svc.Revoke(adminCtx, grant.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Authenticate(ctx, opened.Secret, pantherclawv1connect.AgentServiceListAgentsProcedure); !errors.Is(err, support.ErrUnauthenticated) {
		t.Fatalf("revoked session: %v, want UNAUTHENTICATED", err)
	}
}

var exportedThrough = regexp.MustCompile(`through sequence (\d+)`)

// m13DeleteOrg deletes s's org after its cancellation window ended (the
// request is 7 days old and its window ended: the accelerated clock). Erasure first
// waits for the operator's acknowledgement of the security-event copy; the
// operator exports the platform security log and acknowledges it with the
// server's own commands; then erasure completes, the gateway fails closed
// and the signed deletion record verifies offline.
func m13DeleteOrg(t *testing.T, s *stack, svc *datarequests.Service, trust string) {
	t.Helper()
	ctx := context.Background()
	id, user := ids.NewV7(), ids.NewV7()
	s.db.AdminExec(t, "INSERT INTO pc.users(org_id,id,issuer,subject,email) VALUES($1,$2,'https://idp.test',$3,'deleter@example.test')", s.org, user, user.String())
	s.db.AdminExec(t, `INSERT INTO pc.data_requests(org_id,id,kind,state,created_by,reason,window_end,admin_accounts,created_at)
		VALUES($1,$2,'DELETION','PENDING',$3,'requested',now() - interval '1 minute','{}',now() - interval '7 days 1 minute')`, s.org, id, user)
	if err := svc.DeleteOrg(ctx, s.org, id); !errors.Is(err, datarequests.ErrAwaitingSecurityCopy) {
		t.Fatalf("erasure before the security-event copy: %v, want DELETION_AWAITING_SECURITY_COPY", err)
	}
	if code := s.gwRefuses(t); code == http.StatusOK {
		t.Fatal("the gateway of a DELETED org still dispatches")
	}

	// The operator's external copy of the platform security log, then the ACK.
	deadline := time.Now().Add(time.Minute)
	var through int64
	for through == 0 {
		if _, err := ledger.ChainOrg(ctx, s.pool, ids.PlatformOrg, 10000); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "security.ndjson")
		var stdout, errb bytes.Buffer
		if code := server.Run(ctx, []string{"security-log", "export", "--org", ids.PlatformOrg.String(), "--out", out, "--config", s.serverCfg}, &stdout, &errb, noEnv); code != 0 {
			t.Fatalf("security-log export: %d %s", code, errb.String())
		}
		if m := exportedThrough.FindStringSubmatch(stdout.String()); m != nil {
			through, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if through == 0 && time.Now().After(deadline) {
			t.Fatalf("no platform security event exported within a minute: %s", stdout.String())
		}
		if through == 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	var stdout, errb bytes.Buffer
	if code := server.Run(ctx, []string{"security-log", "ack", "--org", ids.PlatformOrg.String(), "--through", fmt.Sprint(through), "--confirm", "--config", s.serverCfg}, &stdout, &errb, noEnv); code != 0 {
		t.Fatalf("security-log ack: %d %s", code, errb.String())
	}
	if err := svc.DeleteOrg(ctx, s.org, id); err != nil {
		t.Fatalf("erasure: %v", err)
	}
	var left int
	s.db.AdminQueryRow(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1", []any{s.org}, &left)
	if left != 0 {
		t.Fatalf("%d agents left after the deletion", left)
	}
	if code := s.gwRefuses(t); code == http.StatusOK {
		t.Fatal("the gateway of a deleted org dispatches")
	}
	var signed string
	s.db.AdminQueryRow(t, "SELECT signed_record FROM pc.deletion_records WHERE deleted_org_id = $1 ORDER BY id DESC LIMIT 1", []any{s.org.UUID()}, &signed)
	file := filepath.Join(t.TempDir(), "deletion.jws")
	if err := os.WriteFile(file, []byte(signed), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := verifyOffline(t, trust, "deletion", file); rep.Failed() {
		t.Fatalf("pclaw verify deletion: %+v", rep.Checks)
	}
}

// gwRefuses waits until the gateway has noticed its org is no longer
// active (its containment view fails closed, at most 10 s), then sends a
// refund and returns the gateway's status.
func (s *stack) gwRefuses(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.gw.Contained() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the gateway still dispatches 10 s after its org was deleted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	code, _, err := s.tryRefund(ids.NewV7(), "30.00")
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// TestE2E_M13_StagingJourney runs the journey's HTTP steps against hosted
// staging (docs/runbooks/m13-exit.md). It is skipped unless
// PC_E2E_STAGING_URL names the deployment (https only). It reads
// PC_E2E_STAGING_API_KEY_FILE, an API key of a service account of the
// journey's test org with entitlements.read, and optionally the files the
// founder saved during the manual steps: PC_E2E_STAGING_BUNDLE (an evidence
// bundle of the decided action, `pclaw evidence bundle`),
// PC_E2E_STAGING_EXPORT (a downloaded tenant export's manifest, its parts
// beside it) and PC_E2E_STAGING_DELETION (a deletion record). Each is
// verified offline against the evidence keys pinned from staging. It never
// changes or deletes anything on staging.
func TestE2E_M13_StagingJourney(t *testing.T) {
	base := os.Getenv("PC_E2E_STAGING_URL")
	if base == "" {
		t.Skip("PC_E2E_STAGING_URL is not set: the hosted journey runs only against staging (docs/runbooks/m13-exit.md)")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		t.Fatalf("PC_E2E_STAGING_URL must be an https origin, got %q", base)
	}
	base = strings.TrimSuffix(base, "/")
	keyFile := os.Getenv("PC_E2E_STAGING_API_KEY_FILE")
	if keyFile == "" {
		t.Fatal("PC_E2E_STAGING_API_KEY_FILE is required with PC_E2E_STAGING_URL")
	}
	key, err := os.ReadFile(keyFile) //nolint:gosec // G304: the operator names the file
	if err != nil {
		t.Fatal(err)
	}
	staging := m13Client{base: base, c: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, bearer: strings.TrimSpace(string(key))}

	staging.journeyReady(t)
	code, body, _ := staging.connect(t, pantherclawv1connect.AccessServiceWhoAmIProcedure, "{}")
	if code != http.StatusOK {
		t.Fatalf("WhoAmI = %d %s", code, body)
	}
	staging.journeyUsage(t)
	trust := pinTrust(t, base)
	if f := os.Getenv("PC_E2E_STAGING_BUNDLE"); f != "" {
		if rep := verifyOffline(t, trust, "", f); rep.Failed() {
			t.Fatalf("pclaw verify %s: %+v", f, rep.Checks)
		}
	}
	if f := os.Getenv("PC_E2E_STAGING_EXPORT"); f != "" {
		if rep := verifyOffline(t, trust, "export", f, "--parts", filepath.Dir(f)); rep.Failed() {
			t.Fatalf("pclaw verify export %s: %+v", f, rep.Checks)
		}
	}
	if f := os.Getenv("PC_E2E_STAGING_DELETION"); f != "" {
		if rep := verifyOffline(t, trust, "deletion", f); rep.Failed() {
			t.Fatalf("pclaw verify deletion %s: %+v", f, rep.Checks)
		}
	}
}
