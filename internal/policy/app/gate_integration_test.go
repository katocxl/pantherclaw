// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The publish gate's tests (G0 M11.1 design decisions 1, 6, 9 and 11):
// HR-230 (only a validated, tested version of exactly its content is
// published), HR-231 (a loosening needs security keys from distinct people
// holding policy.publish), HR-236 (emergency rules survive a rollback) and
// T-100 (one person weakening the policy alone).

var digestsNow = [32]byte{1, 2, 3}

// gate stands in for S1a's validator and test runner with switchable
// verdicts; the gate under test is the real one.
type gate struct {
	mu                  sync.Mutex
	valid, pass         bool
	validated, testRuns int
}

func (g *gate) Validate(context.Context, ids.OrgID, *domain.Bundle) (domain.ValidationResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.validated++
	r := domain.ValidationResult{Passed: g.valid, DefinitionsDigest: digestsNow, CatalogDigest: digestsNow}
	if !g.valid {
		r.Findings = []domain.Finding{{Code: "CONFLICT", Severity: "ERROR", Rules: []string{"deny-large"}, Detail: "x"}}
	}
	return r, nil
}

func (g *gate) Run(context.Context, ids.OrgID, *domain.Bundle) (domain.TestResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.testRuns++
	r := domain.TestResult{Passed: g.pass, Mutants: 2, DefinitionsDigest: digestsNow, CatalogDigest: digestsNow}
	if !g.pass {
		r.Survivors = 1
		r.Surviving = []domain.MutantResult{{Rule: "deny-large", Mutation: "> to >="}}
	}
	return r, nil
}

type catalog struct{}

func (catalog) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return map[string]fdomain.Type{}, nil
}

type definitions struct{ ds []*defs.Definition }

func (d definitions) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) { return d.ds, nil }

type notes struct {
	mu    sync.Mutex
	types []string
	to    [][]ids.UUID
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.types, n.to = append(n.types, m.Type), append(n.to, m.Personal)
	return napp.Enqueued{}, nil
}

type env struct {
	t       *testing.T
	d       *dbtest.DB
	pool    *db.Pool
	org     ids.OrgID
	store   *pgstore.Store
	gate    *gate
	notes   *notes
	v       *app.Versions
	digests [32]byte
	hooked  [][2]ids.UUID
	hookErr error
}

type person struct {
	id, key, session ids.UUID
	// ctx is the person on the policy changes page; cli is their pclaw
	// session.
	ctx, cli context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	d := dbtest.New(t)
	e := &env{t: t, d: d, pool: d.AppPool(t), org: ids.New[ids.Org](), gate: &gate{valid: true, pass: true}, notes: &notes{},
		digests: digestsNow}
	e.store = &pgstore.Store{Pool: e.pool}
	e.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'gate')", e.org)
	e.v = &app.Versions{
		Store: e.store, Facts: catalog{}, Definitions: definitions{ptrs(pkg.Definitions)}, Authz: grantsapp.SubjectAuthorizer{},
		Limits: celenv.DefaultLimits, Validator: e.gate, Tests: e.gate,
		OnPublished: func(_ context.Context, _ db.TenantTx, org ids.OrgID, version, base ids.UUID) error {
			if org != e.org {
				t.Errorf("hook for org %s", org)
			}
			e.hooked = append(e.hooked, [2]ids.UUID{version, base})
			return e.hookErr
		},
	}
	e.v.Changes = app.NewChanges(e.pool, e.notes, "https://pc.example.test",
		func(context.Context, ids.OrgID) ([32]byte, [32]byte, error) { return e.digests, e.digests, nil })
	e.v.Changes.Register(app.ChangePublish, e.v.ApplyPublish)
	return e
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

// person adds a user with a security key and a browser session, bound at
// the org to roles.
func (e *env) person(name string, roles ...td.RoleName) person {
	e.t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	e.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, p.id, name)
	e.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		e.org, p.key, p.id, secret[:16], secret)
	e.exec(`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, e.org, p.session, p.id, secret)
	var bs []td.Binding
	for _, r := range roles {
		e.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			e.org, ids.NewV7(), string(r), p.id)
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}})
	}
	sub := td.Subject{Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id}, Bindings: bs}
	p.ctx = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredBrowserSession, Session: p.session})
	p.cli = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredAccessToken, Session: ids.NewV7()})
	return p
}

// sign is p's BINDING ceremony over challenge for the request, as the page
// starts it: what VerifyBinding hands the use case after the key answered.
func (e *env) sign(p person, req ids.UUID, challenge [32]byte) app.Assertion {
	e.t.Helper()
	cer := ids.NewV7()
	e.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, policy_change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, e.org, cer, p.session, p.id, challenge[:], req)
	return app.Assertion{Ceremony: cer, Credential: p.key}
}

func (e *env) draft(rules ...domain.Rule) ids.UUID {
	e.t.Helper()
	id, _, err := e.store.CreateVersion(context.Background(), e.org, &domain.Bundle{ID: "org-policy", Rules: rules}, "user:author", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *env) state(id ids.UUID) string {
	e.t.Helper()
	v, err := e.store.Version(context.Background(), e.org, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return v.State
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func denyAbove(id, amount string) domain.Rule {
	return domain.Rule{
		ID: id, Kind: domain.Forbid, Summary: "no refunds above " + amount, Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("` + amount + `", "USD")`, Reason: "REFUND_TOO_LARGE",
	}
}

func emergency(id string) domain.Rule {
	r := denyAbove(id, "10")
	r.Reason, r.Labels = "INCIDENT_FREEZE", map[string]string{"emergency": "true"}
	return r
}

func reason(err error) string { return pcerr.ReasonOf(err) }

func ptrs(ds []defs.Definition) []*defs.Definition {
	out := make([]*defs.Definition, len(ds))
	for i := range ds {
		out[i] = &ds[i]
	}
	return out
}

// TestHR230_NoPortsNoPublication: without a validator or a test runner the
// gate refuses to publish anything (fail closed), and the version stays a
// draft.
func TestHR230_NoPortsNoPublication(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	id := e.draft(denyAbove("deny-large", "1000"))
	for _, strip := range []func(){func() { e.v.Validator = nil }, func() { e.v.Validator, e.v.Tests = e.gate, nil }} {
		strip()
		if _, err := e.v.Publish(alice.ctx, id); !errors.Is(err, app.ErrGateUnavailable) {
			t.Fatalf("publish without a port = %v", err)
		}
	}
	if s := e.state(id); s != app.StateDraft {
		t.Fatalf("state %s", s)
	}
	if n := e.count("SELECT count(*) FROM pc.policy_versions WHERE org_id = $1 AND state = 'PUBLISHED'", e.org); n != 0 {
		t.Fatalf("%d published", n)
	}
}

// TestHR230_ValidationAndTestsAreRerunAndRecorded: the publish call
// validates and tests again; a failure refuses with its report, records
// the run and publishes nothing. The version advances only as far as it
// passed.
func TestHR230_ValidationAndTestsAreRerunAndRecorded(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	id := e.draft(denyAbove("deny-large", "1000"))

	e.gate.valid = false
	_, err := e.v.Publish(alice.ctx, id)
	var ge *app.GateError
	if !errors.Is(err, app.ErrValidationFailed) || !errors.As(err, &ge) || ge.Validation == nil || len(ge.Validation.Findings) != 1 {
		t.Fatalf("invalid version published: %v", err)
	}
	if s := e.state(id); s != app.StateDraft {
		t.Fatalf("state after a failed validation: %s", s)
	}

	e.gate.valid, e.gate.pass = true, false
	if _, err := e.v.Publish(alice.ctx, id); !errors.Is(err, app.ErrTestsFailed) || !errors.As(err, &ge) || ge.Tests == nil || ge.Tests.Survivors != 1 {
		t.Fatalf("a version with a surviving mutant published: %v", err)
	}
	if s := e.state(id); s != app.StateValidated {
		t.Fatalf("state after failed tests: %s", s)
	}
	if n := e.count("SELECT count(*) FROM pc.policy_validations WHERE org_id = $1 AND version_id = $2", e.org, id); n != 2 {
		t.Fatalf("%d validations recorded", n)
	}
	if n := e.count("SELECT count(*) FROM pc.policy_test_runs WHERE org_id = $1 AND version_id = $2 AND NOT passed", e.org, id); n != 1 {
		t.Fatalf("%d failed test runs recorded", n)
	}

	e.gate.pass = true
	out, err := e.v.Publish(alice.ctx, id)
	if err != nil || out.ChangeRequest != nil || out.Version.State != app.StatePublished {
		t.Fatalf("a first policy (tighter than none) = %+v, %v", out, err)
	}
	if len(e.hooked) != 1 || e.hooked[0] != [2]ids.UUID{id, {}} {
		t.Fatalf("hook calls %v", e.hooked)
	}
	if e.gate.validated != 3 || e.gate.testRuns != 2 {
		t.Fatalf("validated %d, tested %d", e.gate.validated, e.gate.testRuns)
	}
}

// TestHR230_PublicationNeedsAPassingRunOfItsContent: the store's one
// publication path is the conditional UPDATE: a version that is not
// TESTED, a failed run, another version's run or another digest publish
// nothing; pc_app can neither change a content digest nor mark a version
// TESTED without one; a version from before the gate is never published.
func TestHR230_PublicationNeedsAPassingRunOfItsContent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, b := e.draft(denyAbove("deny-large", "1000")), e.draft(denyAbove("deny-large", "2000"))
	va, _ := e.store.Version(ctx, e.org, a)
	var digest [32]byte
	copy(digest[:], va.ContentDigest)
	publish := func(id ids.UUID, run ids.UUID, d [32]byte) error {
		return e.store.PublishTested(ctx, e.org, app.PublishRequest{Version: id, Digest: d, TestRun: run, PublishedBy: "user:x"})
	}
	if err := publish(a, ids.NewV7(), digest); !errors.Is(err, pgstore.ErrNotDraft) {
		t.Fatalf("a DRAFT was published: %v", err)
	}
	if _, err := e.store.RecordValidation(ctx, e.org, a, digest, domain.ValidationResult{Passed: true}, "x"); err != nil {
		t.Fatal(err)
	}
	failed, err := e.store.RecordTestRun(ctx, e.org, a, digest, domain.TestResult{Passed: false}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s := e.state(a); s != app.StateValidated {
		t.Fatalf("a failed run advanced the version to %s", s)
	}
	vb, _ := e.store.Version(ctx, e.org, b)
	var other32 [32]byte
	copy(other32[:], vb.ContentDigest)
	if _, err := e.store.RecordValidation(ctx, e.org, b, other32, domain.ValidationResult{Passed: true}, "x"); err != nil {
		t.Fatal(err)
	}
	other, err := e.store.RecordTestRun(ctx, e.org, b, other32, domain.TestResult{Passed: true}, "x")
	if err != nil {
		t.Fatal(err)
	}
	// a passes now, with a run recorded for the wrong content: it advances
	// only for its own digest.
	if _, err := e.store.RecordTestRun(ctx, e.org, a, other32, domain.TestResult{Passed: true}, "x"); err != nil {
		t.Fatal(err)
	}
	if s := e.state(a); s != app.StateValidated {
		t.Fatalf("a run of other content advanced the version to %s", s)
	}
	good, err := e.store.RecordTestRun(ctx, e.org, a, digest, domain.TestResult{Passed: true}, "x")
	if err != nil {
		t.Fatal(err)
	}
	for name, try := range map[string]func() error{
		"a failed run":            func() error { return publish(a, failed, digest) },
		"another version's run":   func() error { return publish(a, other, digest) },
		"another content digest":  func() error { return publish(a, good, other32) },
		"a run of another digest": func() error { return publish(b, good, other32) },
	} {
		if err := try(); !errors.Is(err, pgstore.ErrNotDraft) {
			t.Fatalf("%s published: %v", name, err)
		}
	}
	if err := publish(a, good, digest); err != nil {
		t.Fatalf("the passing run of the content: %v", err)
	}

	// pc_app never rewrites content or skips the digest.
	err = e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.policy_versions SET content_digest = $1 WHERE org_id = $2 AND id = $3", other32[:], e.org, b)
		return err
	})
	if err == nil {
		t.Fatal("pc_app rewrote a content digest")
	}
	legacy := ids.NewV7()
	e.d.AdminExec(t, `INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, created_by)
		SELECT org_id, $2, policy_id, 99, bundle, 'legacy' FROM pc.policy_versions WHERE org_id = $1 AND id = $3`, e.org, legacy, b)
	err = e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.policy_versions SET state = 'TESTED' WHERE org_id = $1 AND id = $2", e.org, legacy)
		return err
	})
	if err == nil {
		t.Fatal("a version without a content digest became TESTED")
	}
	alice := e.person("alice", td.RolePolicyPublisher)
	if _, err := e.v.Publish(alice.ctx, legacy); !errors.Is(err, app.ErrLegacyVersion) {
		t.Fatalf("a pre-gate version: %v", err)
	}
}

// TestHR230_HookRollsThePublicationBack: an OnPublished error leaves the
// previous version published.
func TestHR230_HookRollsThePublicationBack(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	id := e.draft(denyAbove("deny-large", "1000"))
	e.hookErr = errors.New("rollout record failed")
	if _, err := e.v.Publish(alice.ctx, id); err == nil {
		t.Fatal("published although the hook failed")
	}
	if s := e.state(id); s != app.StateTested {
		t.Fatalf("state %s", s)
	}
}

// loosen publishes a first version as alice and asks for a looser one.
func (e *env) loosen(alice person) (v1, v2 ids.UUID, req app.ChangeRequest) {
	e.t.Helper()
	v1 = e.draft(denyAbove("deny-large", "1000"))
	if out, err := e.v.Publish(alice.ctx, v1); err != nil || out.Version.State != app.StatePublished {
		e.t.Fatalf("v1 = %+v, %v", out, err)
	}
	v2 = e.draft(denyAbove("deny-large", "5000"))
	out, err := e.v.Publish(alice.ctx, v2)
	if err != nil || out.ChangeRequest == nil || out.Version.State != app.StateTested || !out.Diff.Loosens() {
		e.t.Fatalf("a looser version = %+v, %v", out, err)
	}
	return v1, v2, *out.ChangeRequest
}

// TestHR231_LooseningNeedsTwoPeopleWithTwoKeys (T-100): with two people
// holding policy.publish, a loosening waits until both confirm, each with
// their own key on the page; the requester confirming twice, a second key
// claimed twice, a policy author, a pclaw session and a ceremony over
// another binding never count.
func TestHR231_LooseningNeedsTwoPeopleWithTwoKeys(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.person("alice", td.RolePolicyPublisher), e.person("bob", td.RolePolicyPublisher)
	carol := e.person("carol", td.RolePolicyAuthor)
	v1, v2, req := e.loosen(alice)
	if req.Required != 2 || req.State != app.ChangePending || req.Kind != app.ChangePublish || req.Base != v1 || req.Subject != v2 {
		t.Fatalf("request %+v", req)
	}
	if len(e.notes.types) != 1 || e.notes.types[0] != "policy.change_requested" || len(e.notes.to[0]) != 2 {
		t.Fatalf("notified %v %v", e.notes.types, e.notes.to)
	}

	if _, err := e.v.Changes.Confirm(alice.cli, req.ID, e.sign(alice, req.ID, req.Binding)); !errors.Is(err, app.ErrBrowserSession) {
		t.Fatalf("a pclaw session confirmed: %v", err)
	}
	if _, err := e.v.Changes.Confirm(carol.ctx, req.ID, e.sign(carol, req.ID, req.Binding)); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("a policy author confirmed: %v", err)
	}
	if _, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, [32]byte{9})); !errors.Is(err, app.ErrChangeAssertion) {
		t.Fatalf("a key over another binding confirmed: %v", err)
	}
	got, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, req.Binding))
	if err != nil || got.State != app.ChangePending || len(got.Confirmations) != 1 {
		t.Fatalf("first confirmation = %+v, %v", got, err)
	}
	if s := e.state(v2); s != app.StateTested {
		t.Fatalf("one confirmation published the loosening: %s", s)
	}
	if _, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, req.Binding)); !errors.Is(err, app.ErrSamePerson) {
		t.Fatalf("the same person confirmed twice: %v", err)
	}
	stolen := e.sign(bob, req.ID, req.Binding)
	stolen.Credential = alice.key
	if _, err := e.v.Changes.Confirm(bob.ctx, req.ID, stolen); !errors.Is(err, app.ErrSameKey) {
		t.Fatalf("the same key confirmed twice: %v", err)
	}
	got, err = e.v.Changes.Confirm(bob.ctx, req.ID, e.sign(bob, req.ID, req.Binding))
	if err != nil || got.State != app.ChangeApproved || len(got.Confirmations) != 2 {
		t.Fatalf("second confirmation = %+v, %v", got, err)
	}
	if e.state(v2) != app.StatePublished || e.state(v1) != app.StateSuperseded {
		t.Fatalf("after approval: v1 %s, v2 %s", e.state(v1), e.state(v2))
	}
	if last := e.hooked[len(e.hooked)-1]; last != [2]ids.UUID{v2, v1} {
		t.Fatalf("hook %v", last)
	}
	if _, err := e.v.Changes.Confirm(carol.ctx, req.ID, e.sign(carol, req.ID, req.Binding)); err == nil {
		t.Fatal("an approved request was confirmed again")
	}
}

// TestHR231_OnePublisherConfirmsWithAKey: in an org with one person
// holding policy.publish, the publisher's own key is the one confirmation;
// without it nothing is published.
func TestHR231_OnePublisherConfirmsWithAKey(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	_, v2, req := e.loosen(alice)
	if req.Required != 1 {
		t.Fatalf("required %d", req.Required)
	}
	if s := e.state(v2); s != app.StateTested {
		t.Fatalf("published before the key: %s", s)
	}
	if got, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, req.Binding)); err != nil || got.State != app.ChangeApproved {
		t.Fatalf("confirm = %+v, %v", got, err)
	}
	if s := e.state(v2); s != app.StatePublished {
		t.Fatalf("state %s", s)
	}
}

// TestHR231_ChangedBaseOrStaleTestsVoid: a request whose base is no longer
// published, or whose test run no longer matches the org's definitions and
// catalog, is voided on its last confirmation instead of applied.
func TestHR231_ChangedBaseOrStaleTestsVoid(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	v1, v2, req := e.loosen(alice)
	v3 := e.draft(denyAbove("deny-large", "1000"), denyAbove("deny-huge", "900"))
	if out, err := e.v.Publish(alice.ctx, v3); err != nil || out.Version.State != app.StatePublished {
		t.Fatalf("a tighter version = %+v, %v", out, err)
	}
	got, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, req.Binding))
	if !errors.Is(err, app.ErrChangeVoided) || got.State != app.ChangeVoided || got.DecidedReason != app.VoidBaseChanged {
		t.Fatalf("base changed = %+v, %v", got, err)
	}
	if e.state(v2) != app.StateTested || e.state(v3) != app.StatePublished || e.state(v1) != app.StateSuperseded {
		t.Fatal("a voided request changed the published version")
	}

	out, err := e.v.Publish(alice.ctx, v2)
	if err != nil || out.ChangeRequest == nil {
		t.Fatalf("ask again = %+v, %v", out, err)
	}
	e.digests = [32]byte{7}
	got, err = e.v.Changes.Confirm(alice.ctx, out.ChangeRequest.ID, e.sign(alice, out.ChangeRequest.ID, out.ChangeRequest.Binding))
	if !errors.Is(err, app.ErrChangeVoided) || got.DecidedReason != app.VoidStaleTests {
		t.Fatalf("stale tests = %+v, %v", got, err)
	}
	if s := e.state(v2); s != app.StateTested {
		t.Fatalf("state %s", s)
	}
}

// TestHR231_ExpiryAndDecline: a request expires 24 hours after it was made
// by the database clock, and a person who may confirm it may decline it;
// neither publishes anything.
func TestHR231_ExpiryAndDecline(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	_, v2, req := e.loosen(alice)
	e.d.AdminExec(t, `UPDATE pc.policy_change_requests SET created_at = now() - interval '25 hours',
		expires_at = now() - interval '1 hour' WHERE id = $1`, req.ID)
	if got, _ := e.v.Changes.Get(alice.ctx, req.ID); got.State != app.ChangeExpired {
		t.Fatalf("read after expiry: %s", got.State)
	}
	if _, err := e.v.Changes.Confirm(alice.ctx, req.ID, e.sign(alice, req.ID, req.Binding)); !errors.Is(err, app.ErrChangeExpired) {
		t.Fatalf("an expired request was confirmed: %v", err)
	}
	if n := e.count("SELECT count(*) FROM pc.policy_change_requests WHERE org_id = $1 AND id = $2 AND state = 'EXPIRED'", e.org, req.ID); n != 1 {
		t.Fatal("the expiry was not recorded")
	}

	out, err := e.v.Publish(alice.ctx, v2)
	if err != nil || out.ChangeRequest == nil || out.ChangeRequest.ID == req.ID {
		t.Fatalf("ask again = %+v, %v", out, err)
	}
	if _, err := e.v.Changes.Decline(alice.ctx, out.ChangeRequest.ID, ""); !errors.Is(err, app.ErrDeclineReason) {
		t.Fatalf("decline without a reason: %v", err)
	}
	if got, err := e.v.Changes.Decline(alice.ctx, out.ChangeRequest.ID, "not now"); err != nil || got.State != app.ChangeDeclined {
		t.Fatalf("decline = %+v, %v", got, err)
	}
	if s := e.state(v2); s != app.StateTested {
		t.Fatalf("state %s", s)
	}
}

// TestHR231_PublishingIsHumanOnly: a service account never publishes or
// asks for a change.
func TestHR231_PublishingIsHumanOnly(t *testing.T) {
	e := newEnv(t)
	id := e.draft(denyAbove("deny-large", "1000"))
	sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RolePolicyPublisher, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAPIKey})
	if _, err := e.v.Publish(sa, id); err == nil {
		t.Fatal("a service account published")
	}
	if s := e.state(id); s != app.StateDraft {
		t.Fatalf("state %s", s)
	}
}

// TestHR236_RollbackCarriesEmergencyRules: a rollback publishes the target
// version's rules plus every emergency rule of the published version, and
// says which it carried.
func TestHR236_RollbackCarriesEmergencyRules(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	v1 := e.draft(denyAbove("deny-large", "1000"))
	if _, err := e.v.Publish(alice.ctx, v1); err != nil {
		t.Fatal(err)
	}
	v2 := e.draft(denyAbove("deny-large", "1000"), emergency("freeze"))
	if out, err := e.v.Publish(alice.ctx, v2); err != nil || out.Version.State != app.StatePublished {
		t.Fatalf("an emergency rule (tighter) = %+v, %v", out, err)
	}
	out, err := e.v.Rollback(alice.ctx, v1, nil)
	if err != nil || !slices.Equal(out.Carried, []string{"freeze"}) {
		t.Fatalf("rollback = %+v, %v", out, err)
	}
	if out.Version.State != app.StatePublished || out.ChangeRequest != nil {
		t.Fatalf("a rollback that keeps every rule: %+v", out)
	}
	b, err := e.store.Published(context.Background(), e.org)
	if err != nil || !slices.ContainsFunc(b.Rules, func(r domain.Rule) bool { return r.ID == "freeze" }) {
		t.Fatalf("published after rollback %+v, %v", b, err)
	}
}

// TestHR236_DroppingAnEmergencyRuleNeedsIncidentRespond: a version that
// drops or changes an emergency rule of the published version needs the
// publisher to hold incident.respond, and then waits for confirmations
// like any loosening.
func TestHR236_DroppingAnEmergencyRuleNeedsIncidentRespond(t *testing.T) {
	e := newEnv(t)
	alice := e.person("alice", td.RolePolicyPublisher)
	dana := e.person("dana", td.RolePolicyPublisher, td.RoleSecurityAdmin)
	v1 := e.draft(denyAbove("deny-large", "1000"), emergency("freeze"))
	if _, err := e.v.Publish(alice.ctx, v1); err != nil {
		t.Fatal(err)
	}
	v2 := e.draft(denyAbove("deny-large", "1000"))
	if _, err := e.v.Publish(alice.ctx, v2); !errors.Is(err, app.ErrEmergencyRule) {
		t.Fatalf("dropping an emergency rule without incident.respond: %v", err)
	}
	out, err := e.v.Publish(dana.ctx, v2)
	if err != nil || out.ChangeRequest == nil || out.Version.State != app.StateTested {
		t.Fatalf("dropping it with incident.respond = %+v, %v", out, err)
	}
	if reason(err) != "" {
		t.Fatal(err)
	}
}
