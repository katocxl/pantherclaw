// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/hub/adapters/drafts"
	"github.com/katocxl/pantherclaw/internal/hub/adapters/pghub"
	"github.com/katocxl/pantherclaw/internal/hub/app"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Covers: F842, F843, F844, F845

type edition struct{ e billing.Edition }

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = e.e
	return x, nil
}

type catalog struct{}

func (catalog) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return map[string]fdomain.Type{}, nil
}

type definitions struct{ ds []*defs.Definition }

func (d definitions) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) {
	return d.ds, nil
}

type world struct {
	t       *testing.T
	pool    *db.Pool
	org     ids.OrgID
	person  ids.UUID
	svc     *app.Service
	signer  *jws.Signer
	pkgRaw  []byte
	targets string
	base    ids.UUID // the published policy version
}

const shellRule = `{"id":"hub-no-rm","per":"org","kind":"FORBID","summary":"no rm in {{environment}}",
	"operations":["shell.command.run"],"environments":["{{environment_id}}"],"when":"action.params.command.startsWith('rm')","reason":"NO_RM"}`

const customRule = `id: org.hub_watch
version: "1"
title: Kill switch watch
description: Tells the team when the kill switch is engaged.
severity: HIGH
attention: INCIDENT
basis: OBSERVED
edition: business
on: [audit.security.kill_switch_engaged]
tests:
  - name: engaged
    fires: true
    events:
      - {kind: audit.security.kill_switch_engaged}
  - name: restored
    fires: false
    events:
      - {kind: audit.security.kill_switch_restored}
`

func definition() string {
	return fmt.Sprintf(`apiVersion: automations.pantherclaw.dev/v1
kind: Automation
purpose: Say hello.
work_kind: AGENT_WORK
review_by: %q
when:
  manual:
    params: {}
authority:
  principal: self
  ceiling:
    agents: [0192f000-0000-7000-8000-000000000003]
    bounds:
      operations: [shell.command.run]
    per_grant:
      ttl: 1h
    per_day:
      grants: 5
      runs: 5
do:
  - id: launch
    step: launch_run
    with:
      agent: 0192f000-0000-7000-8000-000000000003
      task_ref: "hello"
finish_when:
  - step: launch
    condition: RUN_STARTED
limits:
  deadline: 1d
`, time.Now().UTC().AddDate(0, 0, 30).Format(time.DateOnly))
}

func newWorld(t *testing.T, ed billing.Edition) *world {
	t.Helper()
	ctx := context.Background()
	p := dbtest.New(t).AppPool(t)
	w := &world{t: t, pool: p, org: ids.New[ids.Org](), person: ids.NewV7()}
	w.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.person)
	w.exec("INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'production', 'Production', 'PRODUCTION')", w.org, ids.NewV7())

	raw, err := os.ReadFile("../../../packages/pc-shell/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	ds := make([]*defs.Definition, len(pkg.Definitions))
	for i := range pkg.Definitions {
		ds[i] = &pkg.Definitions[i]
	}
	priv, kid, err := rootkey.Generate(rootkey.PurposePackages)
	if err != nil {
		t.Fatal(err)
	}
	pkgSigner, err := jws.NewSigner(kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	w.pkgRaw = raw
	if w.targets, err = trust.Sign(trust.Targets{
		Version: 1, Expires: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Targets: map[string]trust.Target{trust.Key(pkg.Name, pkg.Version): {Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}}},
	}, pkgSigner); err != nil {
		t.Fatal(err)
	}
	hubPriv, hubKid, err := rootkey.Generate(rootkey.PurposeDevHub)
	if err != nil {
		t.Fatal(err)
	}
	if w.signer, err = jws.NewSigner(hubKid, hubPriv); err != nil {
		t.Fatal(err)
	}
	store := &pgstore.Store{Pool: p}
	w.base = policytest.Publish(ctx, t, p, w.org, &pdomain.Bundle{ID: "org", Version: 1, Rules: []pdomain.Rule{{
		ID: "no-root", Kind: pdomain.Forbid, Summary: "no sudo", Operations: []string{"shell.command.run"},
		When: "action.params.command.startsWith('sudo')", Reason: "NO_SUDO",
	}}})
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	dstore := &defspg.Store{Pool: p}
	w.svc = &app.Service{
		Store: &pghub.Store{Pool: p}, Roots: domain.Roots{w.signer.KeyID(): w.signer.Public()}, Clock: clock.System{},
		Policies: drafts.Policies{Pool: p, Versions: &policyapp.Versions{
			Store: store, Facts: catalog{}, Definitions: definitions{ds}, Authz: grantsapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits,
		}},
		Detections:  drafts.Detections{Rules: &reflexapp.Detections{Pool: p, Env: env, Ents: edition{ed}}},
		Automations: drafts.Automations{Pool: p, Svc: &autoapp.Service{Pool: p, Clock: clock.System{}, Editions: edition{ed}}},
		Packages: drafts.Packages{Admin: &defsapp.Admin{
			Importer: &defsapp.Importer{Roots: trust.Roots{pkgSigner.KeyID(): pkgSigner.Public()}, Repo: dstore, Keys: dstore, Clock: clock.System{}},
			Reads:    dstore, Authz: grantsapp.SubjectAuthorizer{}, Ents: edition{ed},
		}},
	}
	return w
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

func (w *world) count(sql string, args ...any) int {
	w.t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		w.t.Fatal(err)
	}
	return n
}

func (w *world) as(cred tapp.Credential, kind td.PrincipalKind, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}})
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: kind, ID: w.person}, Bindings: bs},
		Credential: cred,
	})
}

// admin holds everything an install can need.
func (w *world) admin() context.Context {
	return w.as(tapp.CredBrowserSession, td.KindUser, td.RoleOrgAdmin, td.RolePolicyAuthor, td.RoleSecurityAdmin, td.RoleAutomationAuthor)
}

func (w *world) item(name, version string, kind domain.Kind, body any) ([]byte, domain.Entry) {
	w.t.Helper()
	b, err := json.Marshal(body, json.Deterministic(true))
	if err != nil {
		w.t.Fatal(err)
	}
	raw, err := json.Marshal(domain.Item{Spec: domain.ItemSpec, Name: name, Version: version, Kind: kind, Body: jsontext.Value(b)}, json.Deterministic(true))
	if err != nil {
		w.t.Fatal(err)
	}
	return raw, domain.Entry{
		Name: name, Version: version, Kind: kind, SHA256: domain.Digest(raw), Size: int64(len(raw)), Title: "A title", Summary: "A summary",
	}
}

func (w *world) index(version uint64, entries ...domain.Entry) string {
	w.t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	doc, err := domain.Sign(domain.Index{
		Version: version, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.AddDate(0, 0, 30).Format(time.RFC3339), Items: entries,
	}, w.signer)
	if err != nil {
		w.t.Fatal(err)
	}
	return doc
}

func reason(err error) string {
	var e *pcerr.Error
	if errors.As(err, &e) {
		return e.Reason()
	}
	return ""
}

func wantReason(t *testing.T, what string, err error, want string) {
	t.Helper()
	if reason(err) != want {
		t.Fatalf("%s: %v, want %s", what, err, want)
	}
}

// TestHR561_InstallIsInert installs each kind and proves it only drafts: the
// published policy stays, the rule, automation and package are not live, and
// no second copy is made by installing the same digest again.
func TestHR561_InstallIsInert(t *testing.T) {
	w := newWorld(t, billing.Business)
	ctx := w.admin()
	var policyBody domain.PolicyTemplateBody
	if err := json.Unmarshal([]byte(`{"placeholders":{"environment":{"kind":"environment","pattern":"^[a-z-]+$"},
		"environment_id":{"kind":"environment_id","pattern":"^[0-9a-f-]+$"}},"rules":[`+shellRule+`]}`), &policyBody); err != nil {
		t.Fatal(err)
	}
	policy, pe := w.item("pc.coding.no-rm", "1.0.0", domain.KindPolicyTemplate, policyBody)
	rule, re := w.item("pc.detect.watch", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: customRule})
	auto, ae := w.item("pc.auto.hello", "1.0.0", domain.KindAutomation, domain.AutomationBody{
		AutomationName: "hello", Purpose: "Say hello.", WorkKind: "AGENT_WORK", Definition: definition(),
	})
	pkgItem, pke := w.item("pc.shell", manifestVersion(t, w.pkgRaw), domain.KindToolPackage, domain.ToolPackageBody{PackageYAML: string(w.pkgRaw), TargetsJWS: w.targets})
	doc := w.index(1, pe, re, ae, pke)
	params := map[string]string{"environment": "production"}
	grants := w.count("SELECT count(*) FROM pc.grants")

	res, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: policy, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	if res.Install.Status != app.StatusInstalled || res.Install.ResultKind != app.ResultPolicyVersion {
		t.Fatalf("policy install %+v", res.Install)
	}
	if n := w.count("SELECT count(*) FROM pc.policy_versions WHERE id = $1 AND state = 'DRAFT'", res.Install.ResultRef); n != 1 {
		t.Fatalf("draft policy versions: %d", n)
	}
	pub, err := (&pgstore.Store{Pool: w.pool}).PublishedVersion(ctx, w.org)
	if err != nil || pub == nil || pub.ID != w.base {
		t.Fatalf("published after install: %v %v", pub, err)
	}
	// The template's rule joins the published one in the draft.
	if n := w.count("SELECT count(*) FROM pc.policy_versions WHERE id = $1 AND convert_from(bundle, 'UTF8') LIKE '%no-root%' AND convert_from(bundle, 'UTF8') LIKE '%hub-no-rm%'", res.Install.ResultRef); n != 1 {
		t.Fatalf("draft bundle: %d", n)
	}

	res, err = w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: rule})
	if err != nil {
		t.Fatal(err)
	}
	if n := w.count("SELECT count(*) FROM pc.custom_detection_rules WHERE id = $1 AND state = 'DRAFT'", res.Install.ResultRef); n != 1 {
		t.Fatalf("draft rules: %d", n)
	}

	res, err = w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: auto})
	if err != nil {
		t.Fatal(err)
	}
	if n := w.count("SELECT count(*) FROM pc.automations WHERE id = $1 AND state = 'DRAFT'", res.Install.ResultRef); n != 1 {
		t.Fatalf("draft automations: %d", n)
	}
	if n := w.count("SELECT count(*) FROM pc.automation_versions WHERE automation_id = $1 AND state = 'DRAFT'", res.Install.ResultRef); n != 1 {
		t.Fatalf("draft automation versions: %d", n)
	}

	res, err = w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: pkgItem})
	if err != nil {
		t.Fatal(err)
	}
	if res.Install.ResultKind != app.ResultPackageVersion {
		t.Fatalf("package install %+v", res.Install)
	}
	if n := w.count("SELECT count(*) FROM pc.package_versions WHERE state = 'ACTIVE'"); n != 0 {
		t.Fatalf("active packages: %d", n)
	}
	if n := w.count("SELECT count(*) FROM pc.package_versions WHERE state = 'REVIEWED'"); n != 1 {
		t.Fatalf("reviewed packages: %d", n)
	}
	if w.count("SELECT count(*) FROM pc.grants") != grants {
		t.Fatal("an install issued a grant")
	}

	// The same digest again is idempotent.
	before := w.count("SELECT count(*) FROM pc.custom_detection_rules")
	again, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: rule})
	if err != nil || !again.Already {
		t.Fatalf("again: %+v %v", again, err)
	}
	if w.count("SELECT count(*) FROM pc.custom_detection_rules") != before {
		t.Fatal("reinstalling made a second rule")
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.hub.item_installed'"); n != 4 {
		t.Fatalf("audit entries: %d", n)
	}
	list, err := w.svc.List(ctx, 10, nil)
	if err != nil || len(list) != 4 {
		t.Fatalf("list: %d %v", len(list), err)
	}
}

func manifestVersion(t *testing.T, raw []byte) string {
	t.Helper()
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p.Version
}

// TestHR561_EachKindKeepsItsOwnGate: hub.install alone creates nothing, and a
// detection rule keeps its Business gate on a Community org, ending FAILED.
// Installing again once allowed retries.
func TestHR561_EachKindKeepsItsOwnGate(t *testing.T) {
	w := newWorld(t, billing.Community)
	rule, re := w.item("pc.detect.watch", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: customRule})
	doc := w.index(1, re)
	ctx := w.as(tapp.CredBrowserSession, td.KindUser, td.RoleSecurityAdmin)
	if _, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: rule}); !errors.Is(err, reflexapp.ErrEdition) {
		t.Fatalf("Community: %v", err)
	}
	if n := w.count("SELECT count(*) FROM pc.hub_installs WHERE status = 'FAILED'"); n != 1 {
		t.Fatalf("failed installs: %d", n)
	}
	if n := w.count("SELECT count(*) FROM pc.custom_detection_rules"); n != 0 {
		t.Fatalf("rules: %d", n)
	}
	// A Business licence later: the retry goes through.
	det := w.svc.Detections.(drafts.Detections)
	det.Rules.Ents = edition{billing.Business}
	res, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: rule})
	if err != nil || res.Install.Status != app.StatusInstalled {
		t.Fatalf("retry: %+v %v", res, err)
	}
	// An Automation Author holds hub.install, not detection.manage.
	other, oe := w.item("pc.detect.other", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: strings.ReplaceAll(customRule, "org.hub_watch", "org.hub_other")})
	doc = w.index(2, re, oe)
	if _, err := w.svc.Install(w.as(tapp.CredBrowserSession, td.KindUser, td.RoleAutomationAuthor), app.Input{IndexJWS: doc, Item: other}); err == nil {
		t.Fatal("hub.install alone made a detection rule")
	}
}

func TestInstallIsForAPersonWithThePermission(t *testing.T) {
	w := newWorld(t, billing.Business)
	rule, re := w.item("pc.detect.watch", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: customRule})
	in := app.Input{IndexJWS: w.index(1, re), Item: rule}
	wantReason(t, "API key", second(w.svc.Install(w.as(tapp.CredAPIKey, td.KindUser, td.RoleSecurityAdmin), in)), "HUMAN_ONLY")
	wantReason(t, "service account", second(w.svc.Install(w.as(tapp.CredAPIKey, td.KindServiceAccount, td.RoleOrgAdmin), in)), "HUMAN_ONLY")
	if _, err := w.svc.Install(w.as(tapp.CredBrowserSession, td.KindUser, td.RoleViewer), in); err == nil {
		t.Fatal("a Viewer installed")
	}
	if n := w.count("SELECT count(*) FROM pc.hub_installs"); n != 0 {
		t.Fatalf("installs: %d", n)
	}
}

func second[T any](_ T, err error) error { return err }

// TestT242_MaliciousIndexOrMirror: what a hostile mirror can serve is refused
// by the server itself, and nothing is written.
func TestT242_MaliciousIndexOrMirror(t *testing.T) {
	w := newWorld(t, billing.Business)
	ctx := w.admin()
	rule, re := w.item("pc.detect.watch", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: customRule})
	doc := w.index(1, re)

	tampered := append([]byte(nil), rule...)
	tampered[len(tampered)-5] ^= 1
	wantReason(t, "tampered item", second(w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: tampered})), "HUB_DIGEST")

	// A key nobody trusts, and an index forged for the tampered bytes.
	priv, kid, err := rootkey.Generate(rootkey.PurposeHub)
	if err != nil {
		t.Fatal(err)
	}
	evil, _ := jws.NewSigner(kid, priv)
	now := time.Now().UTC().Truncate(time.Second)
	forged, err := domain.Sign(domain.Index{Version: 9, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Items: []domain.Entry{re}}, evil)
	if err != nil {
		t.Fatal(err)
	}
	wantReason(t, "unknown key", second(w.svc.Install(ctx, app.Input{IndexJWS: forged, Item: rule})), "HUB_SIGNATURE")

	// A package targets document is no index (HR-560).
	wantReason(t, "targets as index", second(w.svc.Install(ctx, app.Input{IndexJWS: w.targets, Item: rule})), "HUB_SIGNATURE")

	// An expired index.
	w.svc.Clock = clock.NewFake(now.AddDate(0, 0, 31))
	wantReason(t, "expired", second(w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: rule})), "HUB_EXPIRED")
	w.svc.Clock = clock.System{}

	// No roots at all.
	roots := w.svc.Roots
	w.svc.Roots = nil
	wantReason(t, "no root", second(w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: rule})), "HUB_NO_ROOT")
	w.svc.Roots = roots

	// A closed kind: a range scenario is local only.
	cx, ce := w.item("pc.range.cx", "1.0.0", domain.KindRangeScenario, domain.RangeScenarioBody{FileName: "CX-90001-a.yaml", Scenario: "id: CX-90001"})
	wantReason(t, "scenario", second(w.svc.Install(ctx, app.Input{IndexJWS: w.index(1, ce), Item: cx})), "KIND_LOCAL_ONLY")

	// A tool package whose content is not what the index names.
	mis, me := w.item("pc.not-shell", "1.0.0", domain.KindToolPackage, domain.ToolPackageBody{PackageYAML: string(w.pkgRaw), TargetsJWS: w.targets})
	wantReason(t, "package under another name", second(w.svc.Install(ctx, app.Input{IndexJWS: w.index(1, me), Item: mis})), "HUB_ITEM_INVALID")

	if n := w.count("SELECT count(*) FROM pc.hub_installs"); n != 0 {
		t.Fatalf("installs: %d", n)
	}
	if n := w.count("SELECT count(*) FROM pc.hub_state"); n != 0 {
		t.Fatalf("state: %d", n)
	}
}

// TestT243_RollbackToABadVersion: anti-rollback is per org: once an org
// accepted version 5, version 4 and another version 5 are refused, a later
// one goes through, and another org is not affected.
func TestT243_RollbackToABadVersion(t *testing.T) {
	w := newWorld(t, billing.Business)
	ctx := w.admin()
	a, ae := w.item("pc.detect.a", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: strings.ReplaceAll(customRule, "org.hub_watch", "org.hub_a")})
	b, be := w.item("pc.detect.b", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: strings.ReplaceAll(customRule, "org.hub_watch", "org.hub_b")})
	if _, err := w.svc.Install(ctx, app.Input{IndexJWS: w.index(5, ae), Item: a}); err != nil {
		t.Fatal(err)
	}
	wantReason(t, "older", second(w.svc.Install(ctx, app.Input{IndexJWS: w.index(4, be), Item: b})), "HUB_ROLLBACK")
	wantReason(t, "equivocation", second(w.svc.Install(ctx, app.Input{IndexJWS: w.index(5, ae, be), Item: b})), "HUB_ROLLBACK")
	if _, err := w.svc.Install(ctx, app.Input{IndexJWS: w.index(6, ae, be), Item: b}); err != nil {
		t.Fatal(err)
	}
	st, err := w.svc.State(ctx)
	if err != nil || st == nil || st.Version != 6 {
		t.Fatalf("state %+v %v", st, err)
	}
	// Another digest under an installed name and version.
	changed, ce := w.item("pc.detect.a", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: strings.ReplaceAll(customRule, "org.hub_watch", "org.hub_c")})
	wantReason(t, "same version, new digest", second(w.svc.Install(ctx, app.Input{IndexJWS: w.index(7, ce), Item: changed})), "HUB_DIGEST")

	// Per org: another org starts from nothing and reads none of this.
	other := ids.New[ids.Org]()
	w.exec2(other, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other)
	octx := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{
			Org: other, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: other.UUID()}}},
		},
		Credential: tapp.CredBrowserSession,
	})
	if st, err := w.svc.State(octx); err != nil || st != nil {
		t.Fatalf("other org state %+v %v", st, err)
	}
	if l, err := w.svc.List(octx, 10, nil); err != nil || len(l) != 0 {
		t.Fatalf("other org installs %d %v", len(l), err)
	}
}

func (w *world) exec2(org ids.OrgID, sql string, args ...any) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}
