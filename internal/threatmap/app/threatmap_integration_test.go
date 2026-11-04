// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	pvports "github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/adapters/pgthreatmap"
	tmapp "github.com/katocxl/pantherclaw/internal/threatmap/app"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Edition(e)
	return x, nil
}

// fx is an org with a team, two environments and an agent in the first,
// and a second org with its own agent.
type fx struct {
	t                *testing.T
	d                *dbtest.DB
	p                *db.Pool
	org, other       ids.OrgID
	user, team       ids.UUID
	env, env2, agent ids.UUID
	otherAgent       ids.UUID
}

func newFx(t *testing.T) *fx {
	t.Helper()
	d := dbtest.New(t)
	f := &fx{
		t: t, d: d, p: d.AppPool(t), org: ids.New[ids.Org](), other: ids.New[ids.Org](), user: ids.NewV7(), team: ids.NewV7(),
		env: ids.NewV7(), env2: ids.NewV7(), agent: ids.NewV7(), otherAgent: ids.NewV7(),
	}
	for _, o := range []struct {
		org   ids.OrgID
		agent ids.UUID
	}{{f.org, f.agent}, {f.other, f.otherAgent}} {
		env := ids.NewV7()
		if o.org == f.org {
			env = f.env
		}
		f.execIn(o.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", o.org)
		f.execIn(o.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", o.org, f.user)
		f.execIn(o.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'a', 'A')", o.org, f.team)
		f.execIn(o.org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'a', 'A', 'PRODUCTION')",
			o.org, env, f.team)
		f.execIn(o.org, `INSERT INTO pc.agents (org_id, id, name, state, created_by, team_id, environment_id, owner_user_id, execution_context, claimed_at)
			VALUES ($1, $2, 'bot', 'VERIFIED', 'test', $3, $4, $5, 'service', now())`, o.org, o.agent, f.team, env, f.user)
	}
	f.exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'b', 'B', 'DEVELOPMENT')",
		f.org, f.env2, f.team)
	return f
}

func (f *fx) execIn(org ids.OrgID, sql string, args ...any) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fx) exec(sql string, args ...any) { f.t.Helper(); f.execIn(f.org, sql, args...) }

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (f *fx) svc(e billing.Edition) *tmapp.Service {
	return &tmapp.Service{Pool: f.p, Ents: edition(e), Store: pgthreatmap.Store{}}
}

// as is a caller of the org with role at scope, authenticated by cred.
func (f *fx) as(cred tenancy.Credential, role td.RoleName, scope td.Scope) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Credential: cred, Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}})
}

func (f *fx) orgScope() td.Scope { return td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()} }

// reads runs the four reads FQ1 gates and returns their errors.
func reads(ctx context.Context, s *tmapp.Service) []error {
	_, e1 := s.Frameworks(ctx)
	_, e2 := s.Matrix(ctx, catalog.FrameworkATTACK, tmapp.Scope{})
	_, _, e3 := s.Technique(ctx, catalog.FrameworkATLAS, "AML.T0051", tmapp.Scope{})
	_, _, e4 := s.Gaps(ctx, catalog.FrameworkATTACK, tmapp.Scope{})
	return []error{e1, e2, e3, e4}
}

// TestHR686_ThreatMapReadsByCredential: on Community a person in the
// console (browser or support session) reads the matrix, a technique, the
// gaps and the frameworks; an API key or access token gets EDITION_REQUIRED
// on all four; on Team an API key reads. The Navigator export needs Team
// for every credential, the history Business (G0 M28 D723, founder FQ1 A).
// Covers: F960, F961, F962, F969, F970, F972, HR-686
func TestHR686_ThreatMapReadsByCredential(t *testing.T) {
	f := newFx(t)
	community, team := f.svc(billing.Community), f.svc(billing.Team)
	for _, cred := range []tenancy.Credential{tenancy.CredBrowserSession, tenancy.CredSupportSession} {
		for i, err := range reads(f.as(cred, td.RoleAuditor, f.orgScope()), community) {
			if err != nil {
				t.Errorf("Community %s read %d: %v", cred, i, err)
			}
		}
	}
	for _, cred := range []tenancy.Credential{tenancy.CredAPIKey, tenancy.CredAccessToken, "unknown"} {
		for i, err := range reads(f.as(cred, td.RoleAuditor, f.orgScope()), community) {
			var pe *pcerr.Error
			if !errors.As(err, &pe) || pe.Reason() != "EDITION_REQUIRED" || pe.Message() != tmapp.ErrAPIEdition.Message() {
				t.Errorf("Community %s read %d: %v", cred, i, err)
			}
		}
		for i, err := range reads(f.as(cred, td.RoleAuditor, f.orgScope()), team) {
			if err != nil {
				t.Errorf("Team %s read %d: %v", cred, i, err)
			}
		}
	}
	browser := f.as(tenancy.CredBrowserSession, td.RoleAuditor, f.orgScope())
	if _, _, err := community.Navigator(browser, catalog.FrameworkATTACK, tmapp.Scope{}); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Errorf("Community Navigator: %v", err)
	}
	if b, _, err := team.Navigator(browser, catalog.FrameworkATTACK, tmapp.Scope{}); err != nil || len(b) == 0 {
		t.Errorf("Team Navigator: %v", err)
	}
	if _, _, err := team.Navigator(browser, catalog.FrameworkATLAS, tmapp.Scope{}); !errors.Is(err, tmapp.ErrNavigatorNotAvailable) {
		t.Errorf("Team ATLAS Navigator: %v", err)
	}
	if _, err := team.History(browser, catalog.FrameworkATTACK, ids.UUID{}, 30); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Errorf("Team history: %v", err)
	}
	if _, err := f.svc(billing.Business).History(browser, catalog.FrameworkATTACK, ids.UUID{}, 30); err != nil {
		t.Errorf("Business history: %v", err)
	}
	if _, _, err := team.Technique(browser, catalog.FrameworkATTACK, "T9999", tmapp.Scope{}); !errors.Is(err, tmapp.ErrUnknownTechnique) {
		t.Errorf("unknown technique: %v", err)
	}
	none := f.as(tenancy.CredBrowserSession, td.RoleViewer, f.orgScope())
	if _, err := team.Matrix(none, catalog.FrameworkATTACK, tmapp.Scope{}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("without threatmap.read: %v", err)
	}
}

// TestT303_ThreatMapReadsStayInScope: another org's agent, an environment
// the caller may not read and a nonexistent one answer NotFound alike; an
// environment-scoped caller reads its environment and its agents, and needs
// the org for an unfiltered read (G0 M28 D722).
// Covers: F963, HR-686, T-303
func TestT303_ThreatMapReadsStayInScope(t *testing.T) {
	f := newFx(t)
	s := f.svc(billing.Team)
	admin := f.as(tenancy.CredBrowserSession, td.RoleAuditor, f.orgScope())
	envOnly := f.as(tenancy.CredBrowserSession, td.RoleResponder, td.Scope{Type: td.ScopeEnvironment, ID: f.env})
	for name, c := range map[string]struct {
		ctx  context.Context
		sc   tmapp.Scope
		code pcerr.Code
	}{
		"org reads its agent":             {admin, tmapp.Scope{Agent: f.agent}, ""},
		"org reads its environment":       {admin, tmapp.Scope{Environment: f.env2}, ""},
		"other org's agent":               {admin, tmapp.Scope{Agent: f.otherAgent}, pcerr.NotFound},
		"no such environment":             {admin, tmapp.Scope{Environment: ids.NewV7()}, pcerr.NotFound},
		"environment reads itself":        {envOnly, tmapp.Scope{Environment: f.env}, ""},
		"environment reads its agent":     {envOnly, tmapp.Scope{Agent: f.agent}, ""},
		"environment reads another":       {envOnly, tmapp.Scope{Environment: f.env2}, pcerr.NotFound},
		"environment reads the whole org": {envOnly, tmapp.Scope{}, pcerr.PermissionDenied},
	} {
		_, err := s.Matrix(c.ctx, catalog.FrameworkATTACK, c.sc)
		if c.code == "" && err != nil || c.code != "" && pcerr.CodeOf(err) != c.code {
			t.Errorf("%s: %v, want %q", name, err, c.code)
		}
	}
}

const hubRule = `id: org.hub.external_disclosure_repeat
version: "1"
title: Repeated refused disclosures by an agent
description: One agent had three or more external disclosures refused within an hour.
severity: HIGH
attention: ALERT
basis: INFERRED
atlas: [AML.T0086]
attack: [T1567]
edition: business
on: [receipt.decision]
match: event.decision == "DENY" && event.reason == "EXTERNAL_DISCLOSURE"
window:
  duration: 1h
  group_by: [subjects.agent]
  count: 3
group: agent
tests:
  - name: one refusal
    fires: false
    events:
      - {kind: receipt.decision, decision: DENY, reason: EXTERNAL_DISCLOSURE, subjects: {agent: a1}}
`

// customRule stores content as a new version of its rule, published when
// publish, and returns the row id.
func (f *fx) customRule(content string, publish bool) ids.UUID {
	f.t.Helper()
	var id ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sum := sha256.Sum256([]byte(content))
		row, err := q.InsertCustomRule(ctx, dbq.InsertCustomRuleParams{
			OrgID: f.org, ID: ids.NewV7(), RuleID: "org.hub.external_disclosure_repeat", Content: content, ContentDigest: sum[:], CreatedBy: f.user,
		})
		if err != nil {
			return err
		}
		id = row.ID
		if !publish {
			return nil
		}
		e, err := audit.Record(ctx, tx, audit.Event{
			Name: "detection.custom_rule_published", Actor: evdomain.Actor{Type: "user", ID: f.user.String()}, Outcome: audit.Success,
		})
		if err != nil {
			return err
		}
		_, err = q.PublishCustomRule(ctx, dbq.PublishCustomRuleParams{OrgID: f.org, ID: id, PublishedBy: &f.user, LedgerEntryID: &e.ID})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) detect(t *testing.T, s *tmapp.Service, id string) domain.Technique {
	t.Helper()
	_, tech, err := s.Technique(f.as(tenancy.CredBrowserSession, td.RoleAuditor, f.orgScope()), catalog.FrameworkATTACK, id, tmapp.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	return tech
}

func row(t domain.Technique, rule string) (domain.RuleRow, bool) {
	i := slices.IndexFunc(t.Detect.Rules, func(r domain.RuleRow) bool { return r.RuleID == rule })
	if i < 0 {
		return domain.RuleRow{}, false
	}
	return t.Detect.Rules[i], true
}

// TestT301_OnlyTheHubInstallsOwnVersionIsEvidence: a custom rule a Hub
// install made counts as PantherClaw's while its published version is the
// one the install made; once the org publishes a version of its own, the
// rule is the org's statement, never evidence (G0 M28 D716, HR-685).
// Covers: F960, HR-680, HR-685, T-301
func TestT301_OnlyTheHubInstallsOwnVersionIsEvidence(t *testing.T) {
	f := newFx(t)
	s := f.svc(billing.Business)
	const rule, tech = "org.hub.external_disclosure_repeat", "T1567"
	v1 := f.customRule(hubRule, true)
	f.exec(`INSERT INTO pc.hub_installs (org_id, id, name, version, kind, item_sha256, index_version, result_kind, result_ref,
		installed_by, status, claim) VALUES ($1, $2, 'pc.detect.external-disclosure-repeat', '1.1.0', 'detection_rule', $3, 1,
		'custom_rule', $4, 'alice', 'INSTALLED', $5)`, f.org, ids.NewV7(), strings.Repeat("0", 64), v1.String(), ids.NewV7())
	r, ok := row(f.detect(t, s, tech), rule)
	if !ok || r.Source != domain.SourceHub || r.Disabled {
		t.Fatalf("Hub-installed rule: %+v %v", r, ok)
	}
	f.exec(`UPDATE pc.custom_detection_rules SET state = 'DISABLED', disabled_by = $3, disabled_at = now(), disabled_reason = 'replaced'
		WHERE org_id = $1 AND id = $2`, f.org, v1, f.user)
	f.customRule(hubRule+"# the org's own change\n", true)
	got := f.detect(t, s, tech)
	if r, ok := row(got, rule); ok && r.Source == domain.SourceHub {
		t.Fatalf("own version still reads as Hub: %+v", r)
	}
	if got.Detect.State == domain.LaneEvidenced {
		t.Errorf("own rule reads as evidence: %s", got.Detect.State)
	}
}

// laneLostAlerts counts the alerts pc.threatmap.lane_lost raised.
func (f *fx) laneLostAlerts() int {
	return f.count("SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND rule_id = 'pc.threatmap.lane_lost'", f.org)
}

func (f *fx) laneLostEvents() int {
	return f.count("SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.threatmap.lane_lost'", f.org)
}

// TestHR687_TurningARuleOffRaisesOneAlertPerDroppedLane: a live built-in
// rule turned off drops the Detect lane of each technique it alone keeps
// EVIDENCED; the snapshot records one threatmap.lane_lost per drop and the
// rule raises one alert per technique and lane; a second run the same day
// raises nothing, and the same lane dropping again the same day folds into
// its alert (G0 M28 D719, D719a).
// Covers: F972, F973, HR-680, HR-687, T-300
func TestHR687_TurningARuleOffRaisesOneAlertPerDroppedLane(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	eng := &engine.Engine{
		Pool: f.p, Builtin: p.Rules, PackVersion: p.Version, Env: env, Raiser: &alerts.Raiser{}, Sink: &failures.Sink{},
		Ents: edition(billing.Business),
	}
	drain := func() {
		t.Helper()
		// The feed reads chained entries only.
		if _, err := ledger.ChainAll(ctx, f.p, f.org, 1000); err != nil {
			t.Fatal(err)
		}
		for range 50 {
			r, err := eng.Process(ctx, f.org)
			if err != nil {
				t.Fatal(err)
			}
			if r.Events == 0 && r.To == r.From {
				return
			}
		}
		t.Fatal("feed did not drain")
	}
	drain()
	rule := liveCandidate(t)
	snap := &tmapp.Snapshotter{Pool: f.p, Ents: edition(billing.Business), Store: pgthreatmap.Store{}}
	run := func() tmapp.SnapshotResult {
		t.Helper()
		res, err := snap.Run(ctx, f.org)
		if err != nil {
			t.Fatal(err)
		}
		drain()
		return res
	}
	if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).TouchDetectionRuleInput(ctx, f.org, rule, time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	if res := run(); res.Drops != 0 || res.Scopes != 2 {
		t.Fatalf("first run: %+v", res)
	}
	off := func() {
		f.d.AdminExec(t, "UPDATE pc.detection_rule_state SET disabled_at = now(), disabled_reason = 'test' WHERE org_id = $1 AND rule_id = $2", f.org, rule)
	}
	off()
	res := run()
	if res.Drops < 2 {
		t.Fatalf("turning %s off dropped %d lanes, want two or more", rule, res.Drops)
	}
	if n := f.laneLostEvents(); n != res.Drops {
		t.Fatalf("%d lane_lost events for %d drops", n, res.Drops)
	}
	alerts := f.laneLostAlerts()
	if alerts != res.Drops {
		t.Fatalf("%d alerts for %d drops", alerts, res.Drops)
	}
	if again := run(); again.Drops != 0 || f.laneLostAlerts() != alerts {
		t.Fatalf("second run: %+v, %d alerts", again, f.laneLostAlerts())
	}
	f.d.AdminExec(t, "UPDATE pc.detection_rule_state SET disabled_at = NULL, disabled_reason = NULL WHERE org_id = $1 AND rule_id = $2", f.org, rule)
	if back := run(); back.Drops != 0 {
		t.Fatalf("turning it back on: %+v", back)
	}
	off()
	if twice := run(); twice.Drops != res.Drops || f.laneLostAlerts() != alerts {
		t.Fatalf("the same drops the same day: %+v, %d alerts, want %d", twice, f.laneLostAlerts(), alerts)
	}
	hist, err := f.svc(billing.Business).History(f.as(tenancy.CredBrowserSession, td.RoleAuditor, f.orgScope()), catalog.FrameworkATTACK, ids.UUID{}, 1)
	if err != nil || len(hist.Days) != 1 {
		t.Fatalf("history: %+v %v", hist, err)
	}
}

// liveCandidate is a built-in rule with non-audit inputs that maps two or
// more matrix techniques no rule listening only to audit events maps: with
// recent input it alone keeps their Detect lanes EVIDENCED.
func liveCandidate(t *testing.T) string {
	t.Helper()
	best, most := "", 0
	for _, f := range catalog.Frameworks() {
		m := mapset.Evaluator(f)
		auditOnly := func(id string) bool {
			b := m.Builtins[id]
			return len(b.Inputs) > 0 && !slices.ContainsFunc(b.Inputs, func(k string) bool { return len(k) < 6 || k[:6] != "audit." })
		}
		count := map[string]int{}
		for _, tech := range catalog.Load(f).Matrix() {
			tm := m.Techniques[tech.ID]
			if slices.ContainsFunc(tm.Rules, auditOnly) {
				continue
			}
			for _, r := range tm.Rules {
				count[r]++
			}
		}
		for r, n := range count {
			if n > most || n == most && r < best {
				best, most = r, n
			}
		}
	}
	if most < 2 {
		t.Fatal("no built-in rule alone maps two matrix techniques")
	}
	return best
}

// TestHR687_TheDispatcherQueuesOneSnapshotPerActiveOrg: the snapshot jobs
// register at the shortest interval, and one dispatch queues exactly one
// threatmap.snapshot_org job per active org; a second dispatch while those
// wait adds none (G0 M28 D719, D727a).
// Covers: F972, HR-687
func TestHR687_TheDispatcherQueuesOneSnapshotPerActiveOrg(t *testing.T) {
	f := newFx(t)
	reg := jobs.NewRegistry()
	periodic, err := tmapp.RegisterSnapshots(reg, &tmapp.Snapshotter{Pool: f.p, Ents: edition(billing.Business), Store: pgthreatmap.Store{}},
		tmapp.MinSnapshotInterval, nil)
	if err != nil || len(periodic) != 1 {
		t.Fatalf("register: %d periodic jobs, %v", len(periodic), err)
	}
	if k := reg.Kinds(); !slices.Contains(k, "threatmap.snapshot") || !slices.Contains(k, "threatmap.snapshot_org") {
		t.Fatalf("kinds %v", k)
	}
	// A worker client runs the registered dispatcher; its org jobs snooze,
	// so they stay queued and a second dispatch meets them.
	run := jobs.NewRegistry()
	if err := jobs.Register[tmapp.SnapshotDispatchArgs](run, tmapp.SnapshotDispatcherForTest(f.p)); err != nil {
		t.Fatal(err)
	}
	if err := jobs.Register[tmapp.SnapshotOrgArgs](run, snoozeSnapshot{}); err != nil {
		t.Fatal(err)
	}
	client, err := jobs.NewClient(f.p, run, jobs.Config{Queues: map[string]int{river.QueueDefault: 2}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = client.Stop(stop)
	})
	dispatched := 0
	dispatchOnce := func() {
		t.Helper()
		if _, err := client.Insert(ctx, tmapp.SnapshotDispatchArgs{}, nil); err != nil {
			t.Fatal(err)
		}
		dispatched++
		deadline := time.Now().Add(30 * time.Second)
		for f.adminCount(`SELECT count(*)::text FROM pc.river_job WHERE kind = 'threatmap.snapshot' AND state = 'completed'`) < dispatched { //nolint:contextcheck // dbtest's admin reads take no context
			if time.Now().After(deadline) {
				t.Fatalf("dispatch %d did not complete", dispatched)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	queued := func() map[string]int {
		t.Helper()
		var raw string
		f.d.AdminQueryRow(t, `SELECT coalesce(string_agg(org || '=' || n, ','), '') FROM (
			SELECT args->>'org' AS org, count(*)::text AS n FROM pc.river_job WHERE kind = 'threatmap.snapshot_org' GROUP BY 1) q`, nil, &raw)
		out := map[string]int{}
		for _, kv := range strings.Split(raw, ",") {
			if org, n, ok := strings.Cut(kv, "="); ok {
				out[org], _ = strconv.Atoi(n)
			}
		}
		return out
	}
	var active int
	f.d.AdminQueryRow(t, "SELECT count(*)::int FROM pc.orgs WHERE state = 'ACTIVE'", nil, &active)
	for i := range 2 {
		dispatchOnce()
		q := queued()
		if q[f.org.String()] != 1 || q[f.other.String()] != 1 || len(q) != active {
			t.Fatalf("dispatch %d: queued %v for %d active orgs", i+1, q, active)
		}
		for org, n := range q {
			if n != 1 {
				t.Errorf("dispatch %d: org %s has %d jobs", i+1, org, n)
			}
		}
	}
}

// TestHR680_SeenCountsAlertsOfBothFrameworks: Seen counts the non-test
// alerts carrying the technique or a sub-technique in either framework's
// own ids, now that signals carry ATT&CK (G0 M28 D720a).
// Covers: F961, HR-680
func TestHR680_SeenCountsAlertsOfBothFrameworks(t *testing.T) {
	f := newFx(t)
	s := f.svc(billing.Business)
	raise := func(key string, atlas, attack []string, test bool) {
		t.Helper()
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			sum := sha256.Sum256([]byte(key))
			_, err := (&alerts.Raiser{}).Raise(ctx, tx.Pgx(), reflexdomain.Signal{
				Org: f.org, Source: reflexdomain.SourceDetection, RuleID: "org.seen_" + key, RuleVersion: "1",
				RuleDigest: "sha256:" + hex.EncodeToString(sum[:]), Title: "Seen " + key, Summary: "A signal for the Seen count.",
				Severity: reflexdomain.SeverityMedium, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisInferred,
				Subjects:  []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: f.agent.String()}},
				DedupeKey: "seen-" + key, OccurredAt: time.Now(), ATLAS: atlas, ATTACK: attack, Test: test,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	raise("both", []string{"AML.T0086"}, []string{"T1567"}, false)
	raise("attack-sub", nil, []string{"T1567.001"}, false)
	raise("atlas-only", []string{"AML.T0086"}, nil, false)
	raise("test", []string{"AML.T0086"}, []string{"T1567"}, true)
	as := f.as(tenancy.CredBrowserSession, td.RoleAuditor, f.orgScope())
	for _, tc := range []struct {
		f    catalog.Framework
		id   string
		want int64
	}{
		{catalog.FrameworkATTACK, "T1567", 2},
		{catalog.FrameworkATLAS, "AML.T0086", 2},
	} {
		_, tech, err := s.Technique(as, tc.f, tc.id, tmapp.Scope{})
		if err != nil {
			t.Fatal(err)
		}
		if tech.Seen.AlertsRaised != tc.want {
			t.Errorf("%s %s: %d alerts seen, want %d", tc.f, tc.id, tech.Seen.AlertsRaised, tc.want)
		}
	}
}

// snoozeSnapshot keeps an org's snapshot job queued.
type snoozeSnapshot struct {
	river.WorkerDefaults[tmapp.SnapshotOrgArgs]
}

func (snoozeSnapshot) Work(context.Context, *river.Job[tmapp.SnapshotOrgArgs]) error {
	return river.JobSnooze(time.Hour)
}

func (f *fx) adminCount(sql string) int {
	f.t.Helper()
	var s string
	f.d.AdminQueryRow(f.t, sql, nil, &s)
	n, err := strconv.Atoi(s)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// TestHR680_PostureSinceIsWhenTheRuleWentOff: a rule turned off 20 days ago
// is a posture finding since its disabled_at, the same on every read, not
// since the read (G0 M28 D724a).
// Covers: F971, HR-680
func TestHR680_PostureSinceIsWhenTheRuleWentOff(t *testing.T) {
	f := newFx(t)
	rule := liveCandidate(t)
	offAt := time.Now().UTC().Add(-20 * 24 * time.Hour).Truncate(time.Microsecond)
	f.d.AdminExec(t, `INSERT INTO pc.detection_rule_state (org_id, rule_id, disabled_at, disabled_reason) VALUES ($1, $2, $3, 'test')
		ON CONFLICT (org_id, rule_id) DO UPDATE SET disabled_at = EXCLUDED.disabled_at, disabled_reason = EXCLUDED.disabled_reason`, f.org, rule, offAt)
	all := pvports.Reach{All: true, Org: true}
	for _, read := range []time.Duration{0, 3 * time.Hour} {
		s := f.svc(billing.Business)
		s.Now = func() time.Time { return time.Now().Add(read) }
		fs, _, err := (&tmapp.Source{Svc: s}).Findings(context.Background(), pvports.Viewer{Org: f.org, Posture: all}, pvdomain.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(fs, func(x pvdomain.Finding) bool { return x.SourceID == "detection_rule:"+rule })
		if i < 0 {
			t.Fatalf("read +%s: no finding for %s in %+v", read, rule, fs)
		}
		if fs[i].Kind != tmapp.KindRuleOff || !fs[i].Since.Equal(offAt) {
			t.Errorf("read +%s: %s since %s, want %s", read, fs[i].Kind, fs[i].Since, offAt)
		}
	}
}
