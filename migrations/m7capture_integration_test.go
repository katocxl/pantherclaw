// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// These tests check restricted payload capture (G0 M7 slice B9, migration
// 00073, HR-199) through the server's recorder and use cases over a real
// schema. Names are prefixed m7c.

const (
	m7cRequest  = `{"amount":"30.00","charge":"ch_secretive_customer_1","currency":"USD"}`
	m7cResponse = `{"id":"re_1","status":"succeeded","customer":"Jane Example"}`
)

type m7cNotes struct {
	mu   sync.Mutex
	sent []napp.Message
}

func (n *m7cNotes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

type m7cFixture struct {
	m7Fixture
	d        *dbtest.DB
	conn     ids.UUID
	recorder *capture.Recorder
	svc      *capture.Service
	notes    *m7cNotes
	logs     *bytes.Buffer
	admin    string
	auditor  string
}

func newM7cFixture(t *testing.T) *m7cFixture {
	t.Helper()
	d := dbtest.New(t)
	app := d.AppPool(t)
	path := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(path); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	env := pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(app, kp), time.Minute, clock.System{}))
	f := &m7cFixture{m7Fixture: newM7Fixture(t, app), d: d, notes: &m7cNotes{}, logs: &bytes.Buffer{}, admin: m5ID(), auditor: m5ID()}
	f.conn, err = ids.ParseUUID(f.connection)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.recorder = &capture.Recorder{Pool: app, Env: env, Log: log}
	f.svc = &capture.Service{Pool: app, Env: env, Notify: f.notes}
	for role, u := range map[td.RoleName]string{td.RoleOrgAdmin: f.admin, td.RoleAuditor: f.auditor} {
		f.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", f.org, u, string(role))
		f.mustExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			f.org, m5ID(), string(role), u)
	}
	return f
}

// as returns a context with a caller of the fixture's org.
func (f *m7cFixture) as(t *testing.T, kind td.PrincipalKind, id string, cred tenancy.Credential, b ...td.Binding) context.Context {
	t.Helper()
	u, err := ids.ParseUUID(id)
	if err != nil {
		t.Fatal(err)
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: kind, ID: u}, Bindings: b}, Credential: cred,
	})
}

func (f *m7cFixture) orgRole(r td.RoleName) td.Binding {
	return td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}
}

func (f *m7cFixture) records(t *testing.T) context.Context {
	return f.as(t, td.KindUser, f.user, tenancy.CredAccessToken, f.orgRole(td.RoleRecordsManager))
}

// dispatch records a dispatched refund through the fixture's connection in
// mode with outcome and returns its transaction and permit.
func (f *m7cFixture) dispatch(t *testing.T, mode, outcome string) (ids.UUID, ids.UUID) {
	t.Helper()
	txn, permit := ids.NewV7(), ids.NewV7()
	f.mustExec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, mode, connection_id) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'ALLOWED', 'gw', $6, $7)`,
		f.org, txn, f.run, m5ID(), m5Secret(30), mode, f.connection)
	f.mustExec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, expires_at, dispatching_at,
		finished_at, mode, connection_id) VALUES ($1, $2, $3, $4, 1, 'DISPATCHED', now() + interval '5 seconds', now(), now(), $5, $6)`,
		f.org, permit, txn, f.gateway, mode, f.connection)
	f.mustExec(t, `INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome) VALUES ($1, $2, $3, $4, $5)`,
		f.org, m5ID(), permit, txn, outcome)
	return txn, permit
}

func (f *m7cFixture) profile(t *testing.T, r capture.ProfileRequest) capture.Profile {
	t.Helper()
	if r.Purpose == "" {
		r = capture.ProfileRequest{
			Purpose: "dispute investigation", Connections: []ids.UUID{f.conn}, Operations: []string{"payments.refund.create"},
			Request: true, Response: true, ByteCap: 1024, RetentionDays: 7, ExpiresInDays: 30,
		}
	}
	p, err := f.svc.CreateProfile(f.records(t), r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func bodies(p ids.UUID) []capture.Body {
	return []capture.Body{
		{Profile: p, Direction: capture.Request, Content: []byte(m7cRequest), Size: int64(len(m7cRequest))},
		{Profile: p, Direction: capture.Response, Content: []byte(m7cResponse), Size: int64(len(m7cResponse))},
	}
}

func (f *m7cFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	f.d.AdminQueryRow(t, sql, args, &n)
	return n
}

// TestHR199_TheServerKeepsOnlyWhatAnActiveProfileCovers: a capture is kept
// only for an attempt the reporting gateway dispatched in enforce mode,
// under an active profile covering its connection, operation and
// direction, cut to the profile's cap, sealed per row, once; nothing of
// its content reaches the logs.
func TestHR199_TheServerKeepsOnlyWhatAnActiveProfileCovers(t *testing.T) {
	f := newM7cFixture(t)
	ctx := context.Background()
	p := f.profile(t, capture.ProfileRequest{})
	record := func(permit ids.UUID, gateway string, b []capture.Body) int {
		t.Helper()
		n, err := f.recorder.Record(ctx, f.org, gateway, permit, b)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	_, monitor := f.dispatch(t, "monitor", "accepted")
	_, delegated := f.dispatch(t, "enforce", "delegated")
	_, other := f.dispatch(t, "enforce", "accepted")
	requestOnly := f.profile(t, capture.ProfileRequest{
		Purpose: "requests", Connections: []ids.UUID{f.conn}, Operations: []string{"payments.refund.create"}, Request: true,
		ByteCap: 1024, RetentionDays: 7, ExpiresInDays: 30,
	})
	otherOp := f.profile(t, capture.ProfileRequest{
		Purpose: "charges", Connections: []ids.UUID{f.conn}, Operations: []string{"payments.charge.create"}, Request: true,
		Response: true, ByteCap: 1024, RetentionDays: 7, ExpiresInDays: 30,
	})
	for name, n := range map[string]int{
		"no profile":                 record(other, f.gateway, bodies(ids.NewV7())),
		"another gateway's attempt":  record(other, m5ID(), bodies(p.ID)),
		"a monitor-mode dispatch":    record(monitor, f.gateway, bodies(p.ID)),
		"a delegated outcome":        record(delegated, f.gateway, bodies(p.ID)),
		"an unknown permit":          record(ids.NewV7(), f.gateway, bodies(p.ID)),
		"another operation's":        record(other, f.gateway, bodies(otherOp.ID)),
		"a response under a request": record(other, f.gateway, bodies(requestOnly.ID)[1:]),
	} {
		if n != 0 {
			t.Errorf("%s: kept %d captures", name, n)
		}
	}
	if _, err := f.svc.DisableProfile(f.records(t), requestOnly.ID); err != nil {
		t.Fatal(err)
	}
	if n := record(other, f.gateway, bodies(requestOnly.ID)[:1]); n != 0 {
		t.Errorf("kept %d under a disabled profile", n)
	}

	txn, permit := f.dispatch(t, "enforce", "accepted")
	big := bytes.Repeat([]byte("x"), 2000)
	if n := record(permit, f.gateway, []capture.Body{bodies(p.ID)[0], {Profile: p.ID, Direction: capture.Response, Content: big, Size: 5000}}); n != 2 {
		t.Fatalf("kept %d captures, want 2", n)
	}
	if n := record(permit, f.gateway, bodies(p.ID)); n != 0 {
		t.Fatalf("a repeated report kept %d more", n)
	}
	var size, sealedLen int
	var truncated bool
	f.d.AdminQueryRow(t, `SELECT size, truncated, octet_length(content) FROM pc.payload_captures WHERE transaction_id = $1 AND direction = 'response'`,
		[]any{txn}, &size, &truncated, &sealedLen)
	if size != 5000 || !truncated || sealedLen > 1024+33 {
		t.Fatalf("response capture: size %d truncated %v sealed %d bytes", size, truncated, sealedLen)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.payload_captures WHERE position(convert_to('secretive_customer', 'UTF8') in content) > 0`); n != 0 {
		t.Fatal("a capture is stored in the clear")
	}
	if n := f.count(t, `SELECT count(*) FROM pc.payload_captures WHERE remove_at = created_at + interval '7 days' AND transaction_id = $1`, txn); n != 2 {
		t.Fatalf("%d captures kept for the profile's retention", n)
	}
	for _, s := range []string{"secretive_customer", "Jane Example", "xxxxxxxx"} {
		if strings.Contains(f.logs.String(), s) {
			t.Fatalf("the logs hold capture content %q:\n%s", s, f.logs.String())
		}
	}

	// A sealed body moved to another row does not open (HR-062).
	r, err := f.svc.ReadCapture(f.as(t, td.KindUser, f.auditor, tenancy.CredAccessToken, f.orgRole(td.RoleAuditor)), txn, capture.Request, "check the moved row")
	if err != nil || string(r.Content) != m7cRequest {
		t.Fatalf("read = %+v, %v", r, err)
	}
	f.d.AdminExec(t, `UPDATE pc.payload_captures SET content = (SELECT content FROM pc.payload_captures WHERE transaction_id = $1
		AND direction = 'response') WHERE transaction_id = $1 AND direction = 'request'`, txn)
	if _, err := f.svc.ReadCapture(f.as(t, td.KindUser, f.auditor, tenancy.CredAccessToken, f.orgRole(td.RoleAuditor)), txn,
		capture.Request, "again"); !errors.Is(err, capture.ErrCaptureUnavailable) {
		t.Fatalf("a moved ciphertext opened: %v", err)
	}
}

// TestHR199_ReadsNeedRestrictedAccessAReasonAndAreAuditedFirst: only a
// person holding evidence.read_restricted where the agent lives reads a
// capture, with a reason; the read is in the audit ledger, with who, which
// capture and why, before the content is returned. Org Admins, Records
// Managers, API keys, service accounts and other orgs cannot read.
func TestHR199_ReadsNeedRestrictedAccessAReasonAndAreAuditedFirst(t *testing.T) {
	f := newM7cFixture(t)
	ctx := context.Background()
	p := f.profile(t, capture.ProfileRequest{})
	txn, permit := f.dispatch(t, "enforce", "accepted")
	if n, err := f.recorder.Record(ctx, f.org, f.gateway, permit, bodies(p.ID)); err != nil || n != 2 {
		t.Fatalf("recorded %d, %v", n, err)
	}
	reads := func() int {
		return f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.payload_read'`, f.org)
	}
	refused := map[string]context.Context{
		"an org admin":      f.as(t, td.KindUser, f.admin, tenancy.CredAccessToken, f.orgRole(td.RoleOrgAdmin)),
		"a records manager": f.records(t),
		"an api key":        f.as(t, td.KindServiceAccount, m5ID(), tenancy.CredAPIKey, f.orgRole(td.RoleAuditor)),
		"a service account": f.as(t, td.KindServiceAccount, m5ID(), tenancy.CredAccessToken, f.orgRole(td.RoleAuditor)),
		"an auditor of a team": f.as(t, td.KindUser, f.auditor, tenancy.CredAccessToken,
			td.Binding{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeTeam, ID: ids.NewV7()}}),
	}
	for name, c := range refused {
		r, err := f.svc.ReadCapture(c, txn, capture.Response, "curious")
		if code := pcerr.CodeOf(err); code != pcerr.PermissionDenied || r.Content != nil {
			t.Errorf("%s read a capture: %v (%v)", name, code, err)
		}
	}
	auditor := f.as(t, td.KindUser, f.auditor, tenancy.CredAccessToken, f.orgRole(td.RoleAuditor))
	if _, err := f.svc.ReadCapture(auditor, txn, capture.Response, ""); !errors.Is(err, capture.ErrReason) {
		t.Fatalf("a read without a reason: %v", err)
	}
	if _, err := f.svc.ReadCapture(auditor, txn, capture.Response, strings.Repeat("é", 300)); !errors.Is(err, capture.ErrReason) {
		t.Fatalf("a reason over 500 bytes: %v", err)
	}
	if _, err := f.svc.ReadCapture(auditor, ids.NewV7(), capture.Response, "r"); !errors.Is(err, capture.ErrCaptureNotFound) {
		t.Fatalf("an unknown transaction: %v", err)
	}
	stranger := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
		Org: ids.New[ids.Org](), Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAuditor}},
	}, Credential: tenancy.CredAccessToken})
	if _, err := f.svc.ReadCapture(stranger, txn, capture.Response, "r"); !errors.Is(err, capture.ErrCaptureNotFound) {
		t.Fatalf("another org's capture: %v (want not found, T-037)", err)
	}
	if n := reads(); n != 0 {
		t.Fatalf("%d refused reads were audited as reads", n)
	}
	r, err := f.svc.ReadCapture(auditor, txn, capture.Response, "dispute 2026-117")
	if err != nil || string(r.Content) != m7cResponse || r.Direction != capture.Response || r.Size != len(m7cResponse) {
		t.Fatalf("read = %+v, %v", r, err)
	}
	var body []byte
	f.d.AdminQueryRow(t, `SELECT body FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.payload_read'`, []any{f.org}, &body)
	var ev struct {
		Object struct {
			ID string `json:"id"`
		} `json:"object"`
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(body, &ev); err != nil || ev.Object.ID != r.ID.String() || ev.Details["reason"] != "dispute 2026-117" ||
		ev.Details["transaction"] != txn.String() || strings.Contains(string(body), "Jane") {
		t.Fatalf("audit entry %s (%v)", body, err)
	}
	var actor string
	f.d.AdminQueryRow(t, `SELECT actor_id FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.payload_read'`, []any{f.org}, &actor)
	if actor != f.auditor {
		t.Fatalf("the read is recorded for %s", actor)
	}

	// The explorer shows the transaction and never its captures.
	ev2, err := (&txapp.Explorer{Pool: f.p}).TransactionEvidence(auditor, txn)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := json.Marshal(ev2); err != nil || bytes.Contains(b, []byte("Jane")) || bytes.Contains(b, []byte("secretive")) {
		t.Fatalf("the explorer response holds a capture (%v)", err)
	}
	if n := reads(); n != 1 {
		t.Fatalf("%d reads audited, want 1", n)
	}
}

// TestHR199_ProfilesNeedAPersonWithCaptureManage: only a person holding
// evidence.capture.manage creates and disables profiles, within the limits
// of design decision 10, on the org's own connections; both are audited,
// notified to the org's admins and auditors, and reach the gateway's
// configuration. A profile past its expiry reads as expired.
func TestHR199_ProfilesNeedAPersonWithCaptureManage(t *testing.T) {
	f := newM7cFixture(t)
	ok := capture.ProfileRequest{
		Purpose: "dispute investigation", Connections: []ids.UUID{f.conn}, Operations: []string{"payments.refund.create"},
		Request: true, ByteCap: 65536, RetentionDays: 30, ExpiresInDays: 90,
	}
	for name, c := range map[string]context.Context{
		"an org admin":      f.as(t, td.KindUser, f.admin, tenancy.CredAccessToken, f.orgRole(td.RoleOrgAdmin)),
		"an auditor":        f.as(t, td.KindUser, f.auditor, tenancy.CredAccessToken, f.orgRole(td.RoleAuditor)),
		"an api key":        f.as(t, td.KindServiceAccount, m5ID(), tenancy.CredAPIKey, f.orgRole(td.RoleRecordsManager)),
		"a service account": f.as(t, td.KindServiceAccount, m5ID(), tenancy.CredAccessToken, f.orgRole(td.RoleRecordsManager)),
	} {
		if _, err := f.svc.CreateProfile(c, ok); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s created a profile: %v", name, err)
		}
	}
	bad := map[string]func(*capture.ProfileRequest){
		"no purpose":           func(r *capture.ProfileRequest) { r.Purpose = "" },
		"no body":              func(r *capture.ProfileRequest) { r.Request = false },
		"a cap over 64 KiB":    func(r *capture.ProfileRequest) { r.ByteCap = 65537 },
		"31 days of retention": func(r *capture.ProfileRequest) { r.RetentionDays = 31 },
		"an expiry of 91 days": func(r *capture.ProfileRequest) { r.ExpiresInDays = 91 },
		"no operation":         func(r *capture.ProfileRequest) { r.Operations = nil },
		"a bad operation":      func(r *capture.ProfileRequest) { r.Operations = []string{"Payments Refund"} },
	}
	for name, mutate := range bad {
		r := ok
		mutate(&r)
		if _, err := f.svc.CreateProfile(f.records(t), r); !errors.Is(err, capture.ErrProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	foreign := ok
	foreign.Connections = []ids.UUID{ids.NewV7()}
	if _, err := f.svc.CreateProfile(f.records(t), foreign); !errors.Is(err, capture.ErrConnection) {
		t.Fatalf("another org's connection: %v", err)
	}
	version := func() int {
		return f.count(t, `SELECT config_version FROM pc.gateways WHERE id = $1`, f.gateway)
	}
	before := version()
	p := f.profile(t, ok)
	if version() <= before {
		t.Fatal("the gateway's configuration did not change")
	}
	gw, _ := ids.ParseUUID(f.gateway)
	served := func() []dbq.GatewayCaptureProfilesRow {
		t.Helper()
		var rows []dbq.GatewayCaptureProfilesRow
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			rows, err = dbq.New(tx).GatewayCaptureProfiles(ctx, f.org, gw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if rows := served(); len(rows) != 1 || rows[0].ID != p.ID || rows[0].ByteCap != 65536 {
		t.Fatalf("the gateway's profiles = %+v", rows)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.capture_profile_created'`, f.org); n != 1 {
		t.Fatalf("%d creations audited", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND position('dispute' in convert_from(body, 'UTF8')) > 0`, f.org); n != 0 {
		t.Fatal("the purpose reached the audit ledger body")
	}
	before = version()
	if d, err := f.svc.DisableProfile(f.records(t), p.ID); err != nil || d.EffectiveState != capture.StateDisabled {
		t.Fatalf("disable = %+v, %v", d, err)
	}
	if _, err := f.svc.DisableProfile(f.records(t), p.ID); !errors.Is(err, capture.ErrProfileNotActive) {
		t.Fatalf("a second disable: %v", err)
	}
	if _, err := f.svc.DisableProfile(f.records(t), ids.NewV7()); !errors.Is(err, capture.ErrProfileNotFound) {
		t.Fatalf("an unknown profile: %v", err)
	}
	if version() <= before || len(served()) != 0 {
		t.Fatal("a disabled profile still reaches the gateway")
	}
	f.notes.mu.Lock()
	sent := slices.Clone(f.notes.sent)
	f.notes.mu.Unlock()
	types := []string{}
	for _, m := range sent {
		types = append(types, m.Type)
		admin, _ := ids.ParseUUID(f.admin)
		auditor, _ := ids.ParseUUID(f.auditor)
		if !slices.Contains(m.Personal, admin) || !slices.Contains(m.Personal, auditor) {
			t.Errorf("%s reaches %v", m.Type, m.Personal)
		}
	}
	if !slices.Contains(types, "evidence.capture_profile_created") || !slices.Contains(types, "evidence.capture_profile_disabled") {
		t.Fatalf("notifications %v", types)
	}

	// Expiry: a profile past it reads as expired, reaches no gateway, and
	// the retention job marks it.
	q := f.profile(t, ok)
	f.d.AdminExec(t, `UPDATE pc.capture_profiles SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1`, q.ID)
	page, err := f.svc.ListProfiles(f.records(t), capture.StateExpired, 0, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != q.ID {
		t.Fatalf("expired profiles = %+v, %v", page, err)
	}
	if len(served()) != 0 {
		t.Fatal("an expired profile reaches the gateway")
	}
	r := &retention.Remover{Pool: f.d.Pool(t, f.d.Retention), App: f.p, Log: pclog.Discard()}
	if _, err := r.Run(context.Background(), f.org); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.capture_profiles WHERE id = $1 AND state = 'EXPIRED'`, q.ID); n != 1 {
		t.Fatal("the job did not mark the profile expired")
	}
}

// TestHR199_CapturesGoAfterTheirRetentionUnlessHeld: the retention job
// deletes a capture once its profile's retention ends, and keeps one a
// legal hold covers.
func TestHR199_CapturesGoAfterTheirRetentionUnlessHeld(t *testing.T) {
	f := newM7cFixture(t)
	ctx := context.Background()
	p := f.profile(t, capture.ProfileRequest{})
	held, permit := f.dispatch(t, "enforce", "accepted")
	if _, err := f.recorder.Record(ctx, f.org, f.gateway, permit, bodies(p.ID)); err != nil {
		t.Fatal(err)
	}
	free, permit2 := f.dispatch(t, "enforce", "accepted")
	if _, err := f.recorder.Record(ctx, f.org, f.gateway, permit2, bodies(p.ID)); err != nil {
		t.Fatal(err)
	}
	f.mustExec(t, m7rHold, f.org, m5ID(), "transaction", held, nil, nil, f.user)
	r := &retention.Remover{Pool: f.d.Pool(t, f.d.Retention), App: f.p, Log: pclog.Discard(), Shift: 6 * 24 * time.Hour}
	if res, err := r.Run(ctx, f.org); err != nil || res.Total() != 0 {
		t.Fatalf("removed %d before the profile's 7 days (%v)", res.Total(), err)
	}
	r.Shift = 7*24*time.Hour + time.Minute
	if _, err := r.Run(ctx, f.org); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.payload_captures WHERE transaction_id = $1`, free); n != 0 {
		t.Fatalf("%d captures kept past their retention", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.payload_captures WHERE transaction_id = $1`, held); n != 2 {
		t.Fatalf("%d held captures kept, want 2", n)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.retention_removed'
		AND position('payload_captures' in convert_from(body, 'UTF8')) > 0`, f.org); n != 1 {
		t.Fatalf("%d audited capture removals", n)
	}
}

// TestHR199_CapturesAreSealedEvidenceInSchema: pc_app never changes or
// deletes a capture, the audit role never sees its content, and the
// schema refuses profiles beyond the limits of design decision 10.
func TestHR199_CapturesAreSealedEvidenceInSchema(t *testing.T) {
	f := newM7cFixture(t)
	const profile = `INSERT INTO pc.capture_profiles (org_id, id, purpose, connections, operations, capture_request, capture_response,
		byte_cap, retention_days, expires_at, created_by) VALUES ($1, $2, 'p', ARRAY[$3]::uuid[], ARRAY['payments.refund.create'],
		$4, true, $5, $6, now() + $7::interval, $8)`
	f.want(t, m5Check, "a cap over 64 KiB", profile, f.org, m5ID(), f.connection, true, 65537, 7, "1 day", f.user)
	f.want(t, m5Check, "31 days of retention", profile, f.org, m5ID(), f.connection, true, 1024, 31, "1 day", f.user)
	f.want(t, m5Check, "an expiry after 90 days", profile, f.org, m5ID(), f.connection, true, 1024, 7, "91 days", f.user)
	f.mustExec(t, profile, f.org, m5ID(), f.connection, false, 1024, 7, "90 days", f.user)
	f.want(t, m5Denied, "a profile's purpose changed", "UPDATE pc.capture_profiles SET purpose = 'other'")
	f.want(t, m5Denied, "a profile deleted", "DELETE FROM pc.capture_profiles")
	f.want(t, m5Denied, "a capture changed", "UPDATE pc.payload_captures SET content = content")
	f.want(t, m5Denied, "a capture deleted by the application", "DELETE FROM pc.payload_captures")
	var content, meta bool
	f.d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.payload_captures', 'content', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.payload_captures', 'size', 'SELECT')`, nil, &content, &meta)
	if content || !meta {
		t.Fatalf("pc_audit_ro: content=%v size=%v, want false, true", content, meta)
	}
}
