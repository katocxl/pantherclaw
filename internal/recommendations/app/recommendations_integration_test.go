// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/recommendations/app"
	"github.com/katocxl/pantherclaw/internal/recommendations/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

func service(o *exposuretest.Org) *app.Service {
	return &app.Service{Pool: o.P, Ents: edition(billing.Team)}
}

func as(o *exposuretest.Org, role td.RoleName, scope td.Scope) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}})
}

// orgWide holds posture.read and posture.manage at org scope.
func orgWide(o *exposuretest.Org) context.Context {
	return as(o, td.RoleResponder, td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()})
}

// team holds posture.read and posture.manage at one team.
func team(o *exposuretest.Org, id ids.UUID) context.Context {
	return as(o, td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: id})
}

func list(ctx context.Context, t *testing.T, o *exposuretest.Org, dismissed bool) app.Listing {
	t.Helper()
	l, err := service(o).List(ctx, dismissed)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func item(l app.Listing, id domain.ID) (app.Item, bool) {
	for _, it := range l.Items {
		if it.Entry.ID == id {
			return it, true
		}
	}
	return app.Item{}, false
}

func records(it app.Item) []ids.UUID {
	var out []ids.UUID
	for _, r := range it.Evidence.Records {
		out = append(out, r.ID)
	}
	return out
}

// discover adds an open scan discovery of a credential on agent.
func discover(t *testing.T, o *exposuretest.Org, agent ids.UUID, kind string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	key := make([]byte, 32)
	copy(key, id[:])
	o.Exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed)
		VALUES ($1, $2, $3, 'scan', $4, jsonb_build_object('kind', 'env_secret', 'secret_kind', $5::text))`,
		o.Org, id, agent, key, kind)
	return id
}

// scanned adds an open discovery of source, with the managed state its scan
// reported.
func scanned(t *testing.T, o *exposuretest.Org, agent ids.UUID, source, state string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	key := make([]byte, 32)
	copy(key, id[:])
	var scope, principal *string
	if source == "ci_scan" {
		s := "acme/payments"
		scope, principal = &s, &s
	}
	o.Exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, scan_scope, scan_principal, observed)
		VALUES ($1, $2, $3, $4, $5, $6, $7, jsonb_build_object('kind', 'mcp_server', 'managed_settings', $8::text))`,
		o.Org, id, agent, source, key, scope, principal, state)
	return id
}

// TestHR536_ManagedSettingsMissing: the recommendation rests on open local
// scan discoveries the viewer may read that say not_found. Any other state,
// a CI-mode scan and another team's agent do not count; what it returns is
// a count and ids, and it says what stays unsupported (G0 M23 D114).
//
// Covers: F852
func TestHR536_ManagedSettingsMissing(t *testing.T) {
	o := exposuretest.New(t)
	a, b := o.Claim(t, o.Agent), o.Claim(t, o.Other)
	if _, ok := item(list(orgWide(o), t, o, false), domain.ManagedSettings); ok {
		t.Fatal("applies with no discovery")
	}
	scanned(t, o, o.Agent, "scan", "present")
	scanned(t, o, o.Agent, "scan", "conflict")
	scanned(t, o, o.Agent, "scan", `not_found"`)
	scanned(t, o, o.Agent, "ci_scan", "not_found")
	if _, ok := item(list(orgWide(o), t, o, false), domain.ManagedSettings); ok {
		t.Fatal("applies with no missing settings on a person's machine")
	}
	hidden := scanned(t, o, o.Other, "scan", "not_found")
	if _, ok := item(list(team(o, a), t, o, false), domain.ManagedSettings); ok {
		t.Fatal("team A sees team B's discovery")
	}
	it, ok := item(list(team(o, b), t, o, false), domain.ManagedSettings)
	if !ok || it.Evidence.Count != 1 || records(it)[0] != hidden || it.Evidence.Records[0].Kind != domain.RecordDiscovery {
		t.Fatalf("team B: %+v %v", it, ok)
	}
	if len(it.Entry.StillUnsupported) == 0 || it.Entry.Reach != domain.AgentBacked {
		t.Fatalf("%+v", it.Entry)
	}
}

// useDatabase makes the org's connection a database connection and records
// coverage of it for agent.
func useDatabase(t *testing.T, o *exposuretest.Org, agent ids.UUID) {
	t.Helper()
	o.D.AdminExec(t, `UPDATE pc.connections SET kind = 'postgres', base_url = NULL WHERE id = $1`, o.Conn)
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		e, err := ledger.Append(ctx, tx, "coverage.snapshot", evdomain.Actor{Type: "system", ID: "test"}, []byte(`{}`))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body,
			body_sha256, ledger_entry_id) VALUES ($1, $2, $3, $4, 'db.orders.read', 'OBSERVE_ONLY', '{}', '{}', $5, $6)`,
			o.Org, ids.NewV7(), agent, o.Conn, make([]byte, 32), e.ID)
		return err
	})
}

func count(t *testing.T, o *exposuretest.Org, sql string, args ...any) int {
	t.Helper()
	var n int
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	return n
}

// TestHR535_AReadChangesNothing: computing recommendations writes no row,
// and everything it returns says what stays unsupported.
//
// Covers: F343
func TestHR535_AReadChangesNothing(t *testing.T) {
	o := exposuretest.New(t)
	o.Claim(t, o.Agent)
	discover(t, o, o.Agent, "aws_access_key_id")
	o.Dispatch(t, "payments.refund")
	tables := []string{
		"agents", "discoveries", "connections", "trusted_issuers", "notification_channels", "siem_destinations",
		"fact_providers", "grants", "ledger_entries", "recommendation_dismissals",
	}
	before := map[string]int{}
	for _, table := range tables {
		before[table] = count(t, o, "SELECT count(*) FROM pc."+table)
	}
	l := list(orgWide(o), t, o, false)
	if len(l.Items) == 0 || l.Restricted || l.AsOf.IsZero() {
		t.Fatalf("%+v", l)
	}
	for _, it := range l.Items {
		if len(it.Entry.StillUnsupported) == 0 {
			t.Errorf("%s states nothing unsupported", it.Entry.ID)
		}
	}
	for _, table := range tables {
		if n := count(t, o, "SELECT count(*) FROM pc."+table); n != before[table] {
			t.Errorf("%s: %d rows, was %d", table, n, before[table])
		}
	}
}

// TestHR536_DiscoveriesCoverOnlyVisibleAgents: another team's discovery
// never appears, and never counts. The IDOR leg of HR-536.
//
// Covers: F343
func TestHR536_DiscoveriesCoverOnlyVisibleAgents(t *testing.T) {
	o := exposuretest.New(t)
	a, b := o.Claim(t, o.Agent), o.Claim(t, o.Other)
	hidden := discover(t, o, o.Other, "openai_api_key")
	discover(t, o, o.Other, "aws_access_key_id")

	mine := list(team(o, a), t, o, false)
	if !mine.Restricted {
		t.Fatal("a team viewer is not restricted")
	}
	if _, ok := item(mine, domain.ModelKeys); ok {
		t.Fatal("team A sees team B's discovery")
	}
	theirs := list(team(o, b), t, o, false)
	it, ok := item(theirs, domain.ModelKeys)
	if !ok || it.Evidence.Count != 1 || records(it)[0] != hidden {
		t.Fatalf("team B: %+v %v", it, ok)
	}
	if _, ok := item(theirs, domain.AWSKeys); ok {
		t.Fatal("a team viewer sees whether the org has an AWS connection")
	}
	all, ok := item(list(orgWide(o), t, o, false), domain.AWSKeys)
	if !ok || all.Evidence.Count != 1 {
		t.Fatalf("org: %+v %v", all, ok)
	}
}

// TestHR536_AnUnclaimedDiscoveryNeedsOrgScope: a discovered agent has no
// team, so only an org-scope viewer sees what a scan found on it.
//
// Covers: F343
func TestHR536_AnUnclaimedDiscoveryNeedsOrgScope(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Claim(t, o.Agent)
	discover(t, o, o.Other, "openai_api_key")
	if _, ok := item(list(team(o, a), t, o, false), domain.ModelKeys); ok {
		t.Fatal("a team viewer sees an unclaimed agent's discovery")
	}
	if _, ok := item(list(orgWide(o), t, o, false), domain.ModelKeys); !ok {
		t.Fatal("the org viewer does not")
	}
}

// TestHR536_AgentCountsCoverOnlyVisibleAgents: a count that rests on the
// org's integrations is for org scope (D317); an agent-backed count and its
// evidence hold the viewer's agents and no others.
//
// Covers: F343
func TestHR536_AgentCountsCoverOnlyVisibleAgents(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Claim(t, o.Agent)
	o.Claim(t, o.Other)
	own := discover(t, o, o.Agent, "openai_api_key")
	discover(t, o, o.Other, "openai_api_key")
	scoped := list(team(o, a), t, o, false)
	if _, ok := item(scoped, domain.CIWorkload); ok {
		t.Fatal("a team viewer sees whether the org has a CI issuer")
	}
	mine, ok := item(scoped, domain.ModelKeys)
	if !ok || mine.Evidence.Count != 1 || len(records(mine)) != 1 || records(mine)[0] != own {
		t.Fatalf("team: %+v %v", mine, ok)
	}
	all, ok := item(list(orgWide(o), t, o, false), domain.CIWorkload)
	if !ok || all.Evidence.Count != 2 {
		t.Fatalf("org: %+v %v", all, ok)
	}
}

// TestHR536_CoverageCoversOnlyVisibleAgents: the coverage leg: use of a
// database connection is shown at org scope, and to no team, not even the
// one whose agent uses it (D317).
//
// Covers: F343
func TestHR536_CoverageCoversOnlyVisibleAgents(t *testing.T) {
	o := exposuretest.New(t)
	a, b := o.Claim(t, o.Agent), o.Claim(t, o.Other)
	useDatabase(t, o, o.Other)
	if _, ok := item(list(team(o, a), t, o, false), domain.DataClasses); ok {
		t.Fatal("team A sees team B's coverage")
	}
	if _, ok := item(list(team(o, b), t, o, false), domain.DataClasses); ok {
		t.Fatal("a team viewer sees whether the org has a fact provider")
	}
	all, ok := item(list(orgWide(o), t, o, false), domain.DataClasses)
	if !ok || all.Evidence.Count != 1 || records(all)[0] != o.Other {
		t.Fatalf("org: %+v %v", all, ok)
	}
}

// TestHR536_OrgWideGapsNeedOrgScope: the org-wide leg: an integration gap
// shows only with posture.read at org scope, even to a viewer whose own
// agent caused the signal.
//
// Covers: F343
func TestHR536_OrgWideGapsNeedOrgScope(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Claim(t, o.Agent)
	txn := o.Dispatch(t, "payments.refund")
	gaps := []domain.ID{domain.IncidentTicket, domain.SIEMExport}
	scoped, all := list(team(o, a), t, o, false), list(orgWide(o), t, o, false)
	for _, id := range gaps {
		if _, ok := item(scoped, id); ok {
			t.Errorf("%s: shown to a team viewer", id)
		}
		it, ok := item(all, id)
		if !ok || it.Evidence.Count != 1 || records(it)[0] != txn {
			t.Errorf("%s: %+v %v", id, it, ok)
		}
	}
}

// TestHR536_ADismissalsDetailNeedsOrgScope: a team viewer learns only that a
// recommendation is dismissed, never who did it or why.
//
// Covers: F343
func TestHR536_ADismissalsDetailNeedsOrgScope(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Claim(t, o.Agent)
	discover(t, o, o.Agent, "openai_api_key")
	if err := service(o).Dismiss(orgWide(o), domain.ModelKeys, "We use another gateway here."); err != nil {
		t.Fatal(err)
	}
	it, ok := item(list(team(o, a), t, o, true), domain.ModelKeys)
	if !ok || !it.Dismissed || it.Dismissal != nil {
		t.Fatalf("team: %+v %v", it, ok)
	}
	it, ok = item(list(orgWide(o), t, o, true), domain.ModelKeys)
	if !ok || it.Dismissal == nil || it.Dismissal.Reason != "We use another gateway here." {
		t.Fatalf("org: %+v %v", it, ok)
	}
}

// TestT232_NothingCrossesAnOrg: one org's discoveries, gaps and dismissals
// never reach another org, whatever the id.
//
// Covers: F343
func TestT232_NothingCrossesAnOrg(t *testing.T) {
	o := exposuretest.New(t)
	other := exposuretest.NewIn(t, o.D, o.P)
	o.Claim(t, o.Agent)
	secret := discover(t, o, o.Agent, "aws_access_key_id")
	o.Dispatch(t, "payments.refund")
	if err := service(o).Dismiss(orgWide(o), domain.CIWorkload, "Handled by another team."); err != nil {
		t.Fatal(err)
	}
	l := list(orgWide(other), t, other, true)
	if len(l.Items) != 0 {
		t.Fatalf("the other org sees %+v", l.Items)
	}
	// Its own dismissal of the same id is its own row.
	other.Claim(t, other.Agent)
	it, ok := item(list(orgWide(other), t, other, true), domain.CIWorkload)
	if !ok || it.Dismissed || records(it)[0] == secret {
		t.Fatalf("%+v %v", it, ok)
	}
}

// TestT232_AScopedViewerCannotHideOrgAdvice: dismissal hides a
// recommendation from the whole org, so a team-scoped holder of
// posture.manage cannot do it, or undo one.
//
// Covers: F343
func TestT232_AScopedViewerCannotHideOrgAdvice(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Claim(t, o.Agent)
	err := service(o).Dismiss(team(o, a), domain.CIWorkload, "Not needed for our team.")
	if err == nil {
		t.Fatal("a team viewer dismissed")
	}
	if !strings.Contains(err.Error(), "posture.manage") {
		t.Fatalf("%v", err)
	}
	if err := service(o).Dismiss(orgWide(o), domain.CIWorkload, "Not needed for this org."); err != nil {
		t.Fatal(err)
	}
	if err := service(o).Undismiss(team(o, a), domain.CIWorkload); err == nil {
		t.Fatal("a team viewer undid a dismissal")
	}
}

// TestIntDismissalLifecycle: a dismissal hides the recommendation for
// everyone until it is undone, and each change is audited and in the ledger.
//
// Covers: F343
func TestIntDismissalLifecycle(t *testing.T) {
	o := exposuretest.New(t)
	o.Claim(t, o.Agent)
	ctx, svc := orgWide(o), service(o)
	if _, ok := item(list(ctx, t, o, false), domain.CIWorkload); !ok {
		t.Fatal("no recommendation to dismiss")
	}
	for _, reason := range []string{"", "too short", "   padded   ", strings.Repeat("x", 501)} {
		if err := svc.Dismiss(ctx, domain.CIWorkload, reason); !errors.Is(err, app.ErrReason) {
			t.Errorf("reason %q: %v", reason, err)
		}
	}
	if err := svc.Dismiss(ctx, "identity.not_in_the_catalog", "A long enough reason."); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if err := svc.Dismiss(ctx, domain.CIWorkload, "A long enough reason."); err != nil {
		t.Fatal(err)
	}
	if err := svc.Dismiss(ctx, domain.CIWorkload, "A long enough reason."); !errors.Is(err, app.ErrDismissed) {
		t.Fatalf("%v", err)
	}
	if _, ok := item(list(ctx, t, o, false), domain.CIWorkload); ok {
		t.Fatal("still listed once dismissed")
	}
	if err := svc.Undismiss(ctx, domain.CIWorkload); err != nil {
		t.Fatal(err)
	}
	if err := svc.Undismiss(ctx, domain.CIWorkload); !errors.Is(err, app.ErrNotDismissed) {
		t.Fatalf("%v", err)
	}
	if _, ok := item(list(ctx, t, o, false), domain.CIWorkload); !ok {
		t.Fatal("not listed once undone")
	}
	if n := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind = $1`, app.LedgerKind); n != 2 {
		t.Fatalf("ledger entries: %d", n)
	}
	if n := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind IN ('audit.recommendation.dismissed', 'audit.recommendation.undismissed')`); n != 2 {
		t.Fatalf("audit events: %d", n)
	}
}

// TestIntLongestReasonsAreKept: a reason of the longest length dismisses in
// any script, and the table keeps all of it.
//
// Covers: F343
func TestIntLongestReasonsAreKept(t *testing.T) {
	for _, char := range []string{"x", "é", "漢", "😀"} {
		t.Run(char, func(t *testing.T) {
			o := exposuretest.New(t)
			o.Claim(t, o.Agent)
			reason := strings.Repeat(char, 500)
			if err := service(o).Dismiss(orgWide(o), domain.CIWorkload, reason); err != nil {
				t.Fatal(err)
			}
			if n := count(t, o, `SELECT count(*) FROM pc.recommendation_dismissals WHERE reason = $1`, reason); n != 1 {
				t.Fatalf("stored reasons: %d", n)
			}
		})
	}
}

// TestIntRetiredAgentsDoNotCount: a discovery on a retired agent is no
// signal.
//
// Covers: F343
func TestIntRetiredAgentsDoNotCount(t *testing.T) {
	o := exposuretest.New(t)
	o.Claim(t, o.Agent)
	discover(t, o, o.Agent, "aws_access_key_id")
	ctx := orgWide(o)
	if _, ok := item(list(ctx, t, o, false), domain.AWSKeys); !ok {
		t.Fatal("no recommendation from a live agent's discovery")
	}
	o.D.AdminExec(t, `UPDATE pc.agents SET state = 'RETIRED', retired_at = now() WHERE id = $1`, o.Agent)
	if _, ok := item(list(ctx, t, o, false), domain.AWSKeys); ok {
		t.Fatal("a retired agent's discovery still counts")
	}
}

// TestIntEdition: below Team, reads and dismissals are refused; undoing a
// dismissal works in every edition.
//
// Covers: F343
func TestIntEdition(t *testing.T) {
	o := exposuretest.New(t)
	o.Claim(t, o.Agent)
	ctx := orgWide(o)
	if err := service(o).Dismiss(ctx, domain.CIWorkload, "Dismissed on the Team plan."); err != nil {
		t.Fatal(err)
	}
	for name, svc := range map[string]*app.Service{
		"community":      {Pool: o.P, Ents: edition(billing.Community)},
		"no entitlement": {Pool: o.P},
	} {
		if _, err := svc.List(ctx, false); !errors.Is(err, app.ErrEdition) {
			t.Errorf("%s: list: %v", name, err)
		}
		if err := svc.Dismiss(ctx, domain.KubeWorkload, "A long enough reason."); !errors.Is(err, app.ErrEdition) {
			t.Errorf("%s: dismiss: %v", name, err)
		}
	}
	svc := &app.Service{Pool: o.P, Ents: edition(billing.Community)}
	if err := svc.Undismiss(ctx, domain.CIWorkload); err != nil {
		t.Fatal(err)
	}
}

// TestIntPermission: without posture.read nothing is returned.
//
// Covers: F343
func TestIntPermission(t *testing.T) {
	o := exposuretest.New(t)
	ctx := as(o, td.RoleRunLauncher, td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()})
	if _, err := service(o).List(ctx, false); err == nil {
		t.Fatal("listed without posture.read")
	}
}

// TestIntIntegrationsCloseRecommendations: an active integration closes its
// recommendation; a disabled one does not.
//
// Covers: F343
func TestIntIntegrationsCloseRecommendations(t *testing.T) {
	o := exposuretest.New(t)
	o.Claim(t, o.Agent)
	discover(t, o, o.Agent, "aws_secret_access_key")
	ctx := orgWide(o)
	if _, ok := item(list(ctx, t, o, false), domain.AWSKeys); !ok {
		t.Fatal("no AWS recommendation")
	}
	o.D.AdminExec(t, `UPDATE pc.connections SET package = $2 WHERE id = $1`, o.Conn, domain.PackageAWS)
	if _, ok := item(list(ctx, t, o, false), domain.AWSKeys); ok {
		t.Fatal("still recommended with the connection active")
	}
	o.D.AdminExec(t, `UPDATE pc.connections SET state = 'RETIRED' WHERE id = $1`, o.Conn)
	if _, ok := item(list(ctx, t, o, false), domain.AWSKeys); !ok {
		t.Fatal("a retired connection closed it")
	}
}

// TestIntAppChannelsCountOnceActivated: a slack_app or teams_app channel
// closes nothing until its side table says ACTIVE, the shape routing reads
// (D317).
//
// Covers: F343
func TestIntAppChannelsCountOnceActivated(t *testing.T) {
	o := exposuretest.New(t)
	cred := ids.NewV7()
	o.Exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		o.Org, cred, o.User, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	channels := func() []string {
		t.Helper()
		var out []string
		o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			r, err := dbq.New(tx).RecommendationIntegrations(ctx, o.Org)
			out = r.Channels
			return err
		})
		return out
	}
	channel := func(kind string) ids.UUID {
		t.Helper()
		id := ids.NewV7()
		o.Exec(t, `INSERT INTO pc.notification_channels (org_id, id, name, kind, event_types, secret, created_by)
			VALUES ($1, $2, $3, $4, '{approval.*}', $5, 'test')`, o.Org, id, strings.TrimSuffix(kind, "_app"), kind, bytes.Repeat([]byte{3}, 32))
		return id
	}

	slack := channel("slack_app")
	o.Exec(t, `INSERT INTO pc.slack_app_channels (org_id, channel_record_id, slack_channel) VALUES ($1, $2, 'C0APPROVAL1')`, o.Org, slack)
	teams := channel("teams_app")
	o.Exec(t, `INSERT INTO pc.teams_app_channels (org_id, channel_record_id, tenant_id, team_id, teams_channel, app_id, service_url)
		VALUES ($1, $2, $3, '19:team@thread.tacv2', '19:abc@thread.tacv2', $3, 'https://smba.trafficmanager.net/teams/')`, o.Org, teams, ids.NewV7())
	if got := channels(); len(got) != 0 {
		t.Fatalf("PENDING_ACTIVATION channels count: %v", got)
	}

	o.Exec(t, `UPDATE pc.slack_app_channels SET state = 'ACTIVE', team_id = 'T0TEAM', bot_id = 'B0BOT', activated_by = $2, activated_credential = $3,
		activated_at = now() WHERE org_id = $1`, o.Org, o.User, cred)
	if got := channels(); !slices.Equal(got, []string{"slack_app"}) {
		t.Fatalf("an activated Slack channel: %v", got)
	}
	o.Exec(t, `UPDATE pc.teams_app_channels SET state = 'ACTIVE', membership_type = 'internal', activated_by = $2, activated_credential = $3,
		activated_at = now() WHERE org_id = $1`, o.Org, o.User, cred)
	if got := channels(); !slices.Equal(got, []string{"slack_app", "teams_app"}) {
		t.Fatalf("an activated Teams channel: %v", got)
	}
}

// TestF343_SubmittedKeysReachTheCatalogue (D238): what `pclaw scan --submit`
// sends, from a plain or a device scan, is the signal the model-keys entry
// reads.
//
// Covers: F343
func TestF343_SubmittedKeysReachTheCatalogue(t *testing.T) {
	o := exposuretest.New(t)
	inv := aapp.NewInventory(o.P, edition(billing.Team))
	submit := as(o, td.RoleAgentOwner, td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()})
	key := func(s string) [32]byte { return sha256.Sum256([]byte(s)) }
	if _, err := inv.SubmitScan(submit, "laptop", []aapp.ScanFinding{{
		Kind: "env_secret", Key: key("plain"), Attributes: map[string]string{"secret_kind": "openai_api_key"},
	}}, aapp.ScanMode{}); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.SubmitScan(submit, "laptop", []aapp.ScanFinding{{
		Kind: "env_secret", Key: key("device"), Attributes: map[string]string{"secret_kind": "anthropic_api_key"},
	}}, aapp.ScanMode{Scope: "device:0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	if it, ok := item(list(orgWide(o), t, o, false), domain.ModelKeys); !ok || it.Evidence.Count != 2 {
		t.Fatalf("model keys: %+v %v", it, ok)
	}
}
