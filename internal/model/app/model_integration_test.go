// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	testKey    = "sk-ant-integration-test-key"
	secretText = "draft text that must stay out of every audit row"
	schema     = `{"type":"object","additionalProperties":false,"properties":{},"required":[]}`
)

type edition struct{ e billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

type notifier struct{ messages []napp.Message }

func (n *notifier) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.messages = append(n.messages, m)
	return napp.Enqueued{}, nil
}

// provider is the fake model provider; no test reaches a real one.
type provider struct {
	calls atomic.Int32
	last  ports.DraftRequest
	resp  ports.DraftResponse
	err   error
}

func (p *provider) Draft(_ context.Context, r ports.DraftRequest) (ports.DraftResponse, error) {
	p.calls.Add(1)
	p.last = r
	return p.resp, p.err
}

type fixture struct {
	t        *testing.T
	p        *db.Pool
	org      ids.OrgID
	user     ids.UUID
	cred     ids.UUID
	ed       *edition
	notes    *notifier
	provider *provider
	svc      *app.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		t: t, p: d.AppPool(t), org: ids.New[ids.Org](), user: ids.NewV7(), cred: ids.NewV7(),
		ed: &edition{e: billing.Business}, notes: &notifier{},
		provider: &provider{resp: ports.DraftResponse{Output: []byte(`{}`), InputTokens: 100, OutputTokens: 50}},
	}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = &app.Service{
		Pool: f.p, Envelope: pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(f.p, kp), time.Minute, clock.System{})),
		Editions: f.ed, Notify: f.notes, Provider: f.provider,
		Config: app.Config{Enabled: true, CallsPerMinute: 3, TokensPerDay: 1000},
	}
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'model')", f.org)
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	f.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.org, f.cred, f.user, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	return f
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) count(sql string) int {
	f.t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql).Scan(&n)
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (f *fixture) text(sql string) string {
	f.t.Helper()
	var s string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql).Scan(&s)
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

func (f *fixture) as(kind td.PrincipalKind, roles ...td.RoleName) context.Context {
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: kind, ID: f.user}, Bindings: bs},
	})
}

func (f *fixture) admin() context.Context { return f.as(td.KindUser, td.RoleOrgAdmin) }

func (f *fixture) fresh() stepup.StepUp { return stepup.StepUp{Credential: f.cred, At: time.Now()} }

// on stores a key and turns drafting on.
func (f *fixture) on() {
	f.t.Helper()
	if _, err := f.svc.SetKey(f.admin(), testKey, f.fresh()); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.svc.Enable(f.admin(), f.fresh()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) draft() (app.Result, error) {
	return f.svc.Draft(f.admin(), app.Call{
		Task: ports.TaskSearchQuery, Text: secretText, Schema: []byte(schema),
		Catalogue: ports.Catalogue{Entities: []string{"transactions"}},
		Parse:     func([]byte) error { return nil },
	})
}

// Covers: F181, F304
func TestHR541_OffByDefaultBusinessAndOptIn(t *testing.T) {
	f := newFixture(t)
	if _, err := f.draft(); !errors.Is(err, app.ErrOff) {
		t.Fatalf("no settings row: %v", err)
	}
	s, err := f.svc.Get(f.admin())
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled || s.KeySet || !s.Available {
		t.Fatalf("defaults: %+v", s)
	}
	f.ed.e = billing.Team
	if _, err := f.svc.SetKey(f.admin(), testKey, f.fresh()); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("Team SetKey: %v", err)
	}
	if _, err := f.draft(); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("Team draft: %v", err)
	}
	f.ed.e = billing.Business
	if _, err := f.svc.Enable(f.admin(), f.fresh()); !errors.Is(err, app.ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	f.on()
	if _, err := f.draft(); err != nil {
		t.Fatal(err)
	}
	f.svc.Config.Enabled = false
	if _, err := f.draft(); !errors.Is(err, app.ErrPlatformOff) {
		t.Fatalf("platform off: %v", err)
	}
	if _, err := f.svc.SetKey(f.admin(), testKey, f.fresh()); !errors.Is(err, app.ErrPlatformOff) {
		t.Fatalf("platform off SetKey: %v", err)
	}
	f.svc.Config.Enabled = true
	if _, err := f.svc.Disable(f.admin()); err != nil {
		t.Fatal(err)
	}
	before := f.provider.calls.Load()
	if _, err := f.draft(); !errors.Is(err, app.ErrOff) {
		t.Fatalf("org off: %v", err)
	}
	if f.provider.calls.Load() != before {
		t.Fatal("an off switch let a call through")
	}
}

// Covers: F181
func TestHR541_TurningOnNeedsAPersonAndAFreshStepUpAndTellsAdmins(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	bad := map[string]stepup.StepUp{
		"none": {}, "stale": {Credential: f.cred, At: now.Add(-10 * time.Minute)}, "unknown key": {Credential: ids.NewV7(), At: now},
	}
	for name, su := range bad {
		if _, err := f.svc.SetKey(f.admin(), testKey, su); !errors.Is(err, stepup.ErrStepUp) {
			t.Errorf("SetKey %s: %v", name, err)
		}
	}
	if n := f.count("SELECT count(*)::int FROM pc.model_settings WHERE key_ciphertext IS NOT NULL"); n != 0 {
		t.Fatal("a refused SetKey stored a key")
	}
	if len(f.notes.messages) != 0 {
		t.Fatal("a refused change notified")
	}
	if _, err := f.svc.SetKey(f.as(td.KindServiceAccount, td.RoleOrgAdmin), testKey, f.fresh()); !errors.Is(err, app.ErrHuman) {
		t.Fatalf("service account: %v", err)
	}
	if _, err := f.svc.SetKey(f.as(td.KindUser, td.RoleAuditor), testKey, f.fresh()); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("auditor: %v", err)
	}
	f.exec("INSERT INTO pc.role_bindings (org_id, id, user_id, role, scope_type, created_by) VALUES ($1, $2, $3, 'org_admin', 'ORG', 'test')",
		f.org, ids.NewV7(), f.user)
	if _, err := f.svc.SetKey(f.admin(), testKey, f.fresh()); err != nil {
		t.Fatal(err)
	}
	for name, su := range bad {
		if _, err := f.svc.Enable(f.admin(), su); !errors.Is(err, stepup.ErrStepUp) {
			t.Errorf("Enable %s: %v", name, err)
		}
	}
	if _, err := f.svc.Enable(f.admin(), f.fresh()); err != nil {
		t.Fatal(err)
	}
	if len(f.notes.messages) != 2 {
		t.Fatalf("notices: %d", len(f.notes.messages))
	}
	for i, change := range []string{"KEY_SET", "ENABLED"} {
		m := f.notes.messages[i]
		if m.Type != "security.model_drafting_changed" || m.Params["change"] != change || len(m.Personal) != 1 || m.Personal[0] != f.user {
			t.Errorf("notice %d: %+v", i, m)
		}
	}
}

// Covers: F181
func TestHR541_TurningOffAndClearingNeedNoStepUp(t *testing.T) {
	f := newFixture(t)
	f.on()
	notices := len(f.notes.messages)
	f.ed.e = billing.Team // a lapsed plan can still leave
	s, err := f.svc.Disable(f.admin())
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled {
		t.Fatal("still on")
	}
	f.ed.e = billing.Business
	if _, err := f.svc.Enable(f.admin(), f.fresh()); err != nil {
		t.Fatal(err)
	}
	notices++
	s, err = f.svc.ClearKey(f.admin())
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled || s.KeySet {
		t.Fatalf("after clear: %+v", s)
	}
	if n := f.count("SELECT count(*)::int FROM pc.model_settings WHERE key_ciphertext IS NOT NULL OR enabled"); n != 0 {
		t.Fatal("the key or the switch survived clearing")
	}
	if len(f.notes.messages) != notices {
		t.Fatalf("leaving notified: %d", len(f.notes.messages))
	}
	if _, err := f.svc.Disable(f.as(td.KindServiceAccount, td.RoleOrgAdmin)); !errors.Is(err, app.ErrHuman) {
		t.Fatalf("service account: %v", err)
	}
}

// Covers: F181
func TestHR545_EveryCallIsAuditedWithoutItsText(t *testing.T) {
	f := newFixture(t)
	f.on()
	res, err := f.draft()
	if err != nil {
		t.Fatal(err)
	}
	if res.ID.IsZero() {
		t.Fatal("no call id")
	}
	if n := f.count("SELECT count(*)::int FROM pc.ledger_entries WHERE kind = 'audit.model.call'"); n != 1 {
		t.Fatalf("audit rows: %d", n)
	}
	if s := f.text("SELECT outcome FROM pc.model_calls"); s != "OK" {
		t.Fatalf("outcome: %s", s)
	}
	if n := f.count("SELECT (input_tokens + output_tokens)::int FROM pc.model_calls"); n != 150 {
		t.Fatalf("tokens: %d", n)
	}
	if s := f.text("SELECT string_agg(body::text, ' ') FROM pc.ledger_entries WHERE kind = 'audit.model.call'"); strings.Contains(s, secretText) || strings.Contains(s, testKey) {
		t.Fatalf("audit body holds text or the key: %s", s)
	}
	if s := f.text("SELECT row_to_json(c)::text FROM pc.model_calls c"); strings.Contains(s, secretText) {
		t.Fatalf("the call row holds text: %s", s)
	}

	f.provider.err = ports.ErrProviderFailed
	if _, err := f.draft(); !errors.Is(err, ports.ErrProviderFailed) {
		t.Fatalf("failed call: %v", err)
	}
	f.provider.err = nil
	parseErr := ports.ErrInvalidOutput
	if _, err := f.svc.Draft(f.admin(), app.Call{
		Task: ports.TaskSearchQuery, Text: "x", Schema: []byte(schema), Parse: func([]byte) error { return parseErr },
	}); !errors.Is(err, ports.ErrInvalidOutput) {
		t.Fatalf("unparsable output: %v", err)
	}
	if n := f.count("SELECT count(*)::int FROM pc.ledger_entries WHERE kind = 'audit.model.call'"); n != 3 {
		t.Fatalf("audit rows after failures: %d", n)
	}
	if n := f.count("SELECT count(*)::int FROM pc.model_calls WHERE outcome = 'MODEL_OUTPUT_INVALID'"); n != 1 {
		t.Fatal("a refused output was not recorded as refused")
	}
}

// Covers: F181
func TestHR545_TheKeyIsWriteOnlyAndEncrypted(t *testing.T) {
	f := newFixture(t)
	f.on()
	if _, err := f.draft(); err != nil {
		t.Fatal(err)
	}
	if f.provider.last.Key.Reveal() != testKey {
		t.Fatal("the provider did not get the stored key")
	}
	if s, ok := any(f.provider.last.Key).(interface{ String() string }); !ok || strings.Contains(s.String(), testKey) {
		t.Fatal("the key prints")
	}
	if n := f.count("SELECT count(*)::int FROM pc.model_settings WHERE position(convert_to('" + testKey + "', 'UTF8') IN key_ciphertext) > 0"); n != 0 {
		t.Fatal("the key is stored in the clear")
	}
	if _, err := f.svc.Get(f.as(td.KindUser, td.RoleOrgAdmin)); err != nil {
		t.Fatal(err)
	}
	// The ciphertext is bound to its row: another org's copy does not open.
	var blob []byte
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT key_ciphertext FROM pc.model_settings").Scan(&blob)
	}); err != nil {
		t.Fatal(err)
	}
	other := pccrypto.FieldContext{Org: f.org, Table: "model_settings", Column: "key_ciphertext", RowID: ids.New[ids.Org]().String()}
	if _, err := f.svc.Envelope.Decrypt(context.Background(), other, app.SecretPurpose, blob); err == nil {
		t.Fatal("the key opened for another row")
	}
}

// Covers: F181
func TestT234_CapsRefuseBeforeTheProviderAndAreAudited(t *testing.T) {
	f := newFixture(t)
	f.on()
	f.svc.Config.TokensPerDay = 1_000_000
	for i := range 3 {
		if _, err := f.draft(); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	before := f.provider.calls.Load()
	if _, err := f.draft(); !errors.Is(err, app.ErrRateCap) {
		t.Fatalf("rate cap: %v", err)
	}
	if f.provider.calls.Load() != before {
		t.Fatal("a refused call reached the provider")
	}
	if n := f.count("SELECT count(*)::int FROM pc.ledger_entries WHERE kind = 'audit.model.call' AND body::text LIKE '%MODEL_RATE_CAP%'"); n != 1 {
		t.Fatalf("refusal audits: %d", n)
	}
	// Move the calls out of the minute: the day's tokens still count.
	f.exec("UPDATE pc.model_calls SET created_at = now() - interval '2 minutes'")
	f.svc.Config.TokensPerDay = 450
	if _, err := f.draft(); !errors.Is(err, app.ErrBudgetCap) {
		t.Fatalf("budget cap: %v", err)
	}
	if f.provider.calls.Load() != before {
		t.Fatal("an over-budget call reached the provider")
	}
}

// Covers: F181
func TestT234_AnOrganizationCanOnlyLowerTheCaps(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.SetLimits(f.admin(), app.Limits{Model: "claude-opus-5-5", CallsPerMinute: 4}); !errors.Is(err, app.ErrCapTooHigh) {
		t.Fatalf("raised calls: %v", err)
	}
	if _, err := f.svc.SetLimits(f.admin(), app.Limits{Model: "claude-opus-5-5", TokensPerDay: 2000}); !errors.Is(err, app.ErrCapTooHigh) {
		t.Fatalf("raised tokens: %v", err)
	}
	if _, err := f.svc.SetLimits(f.admin(), app.Limits{Model: "not a model"}); !errors.Is(err, app.ErrInvalidModel) {
		t.Fatalf("bad model: %v", err)
	}
	s, err := f.svc.SetLimits(f.admin(), app.Limits{Model: "claude-haiku-5-5", CallsPerMinute: 1, TokensPerDay: 10})
	if err != nil {
		t.Fatal(err)
	}
	if s.CallsPerMinute != 1 || s.TokensPerDay != 10 || s.Model != "claude-haiku-5-5" {
		t.Fatalf("settings: %+v", s)
	}
	f.on()
	if _, err := f.draft(); err != nil {
		t.Fatal(err)
	}
	if f.provider.last.Model != "claude-haiku-5-5" {
		t.Fatalf("model sent: %s", f.provider.last.Model)
	}
	if _, err := f.draft(); !errors.Is(err, app.ErrRateCap) {
		t.Fatalf("lowered cap: %v", err)
	}
}

// Covers: F181
func TestT234_SettingsAreTenantScoped(t *testing.T) {
	f := newFixture(t)
	f.on()
	other := ids.New[ids.Org]()
	var n int
	if err := f.p.InTenantTx(context.Background(), other, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*)::int FROM pc.model_settings").Scan(&n)
	}, db.ReadOnly()); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("another org read %d rows", n)
	}
}
