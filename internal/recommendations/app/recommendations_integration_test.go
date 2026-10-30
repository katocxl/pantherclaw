// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
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
	hidden := discover(t, o, o.Other, "aws_access_key_id")

	mine := list(team(o, a), t, o, false)
	if !mine.Restricted {
		t.Fatal("a team viewer is not restricted")
	}
	if _, ok := item(mine, domain.AWSCredentials); ok {
		t.Fatal("team A sees team B's discovery")
	}
	theirs, ok := item(list(team(o, b), t, o, false), domain.AWSCredentials)
	if !ok || theirs.Evidence.Count != 1 || records(theirs)[0] != hidden {
		t.Fatalf("team B: %+v %v", theirs, ok)
	}
	all, ok := item(list(orgWide(o), t, o, false), domain.AWSCredentials)
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

// TestHR536_AgentCountsCoverOnlyVisibleAgents: an agent-backed count and its
// evidence hold the viewer's agents and no others.
//
// Covers: F343
func TestHR536_AgentCountsCoverOnlyVisibleAgents(t *testing.T) {
	o := exposuretest.New(t)
	a := o.Claim(t, o.Agent)
	o.Claim(t, o.Other)
	mine, ok := item(list(team(o, a), t, o, false), domain.CIWorkload)
	if !ok || mine.Evidence.Count != 1 || len(records(mine)) != 1 || records(mine)[0] != o.Agent {
		t.Fatalf("team: %+v %v", mine, ok)
	}
	all, ok := item(list(orgWide(o), t, o, false), domain.CIWorkload)
	if !ok || all.Evidence.Count != 2 {
		t.Fatalf("org: %+v %v", all, ok)
	}
}

// TestHR536_CoverageCoversOnlyVisibleAgents: the coverage leg: a team sees
// only its own agent's use of a database connection.
//
// Covers: F343
func TestHR536_CoverageCoversOnlyVisibleAgents(t *testing.T) {
	o := exposuretest.New(t)
	a, b := o.Claim(t, o.Agent), o.Claim(t, o.Other)
	useDatabase(t, o, o.Other)
	if _, ok := item(list(team(o, a), t, o, false), domain.DataClasses); ok {
		t.Fatal("team A sees team B's coverage")
	}
	theirs, ok := item(list(team(o, b), t, o, false), domain.DataClasses)
	if !ok || theirs.Evidence.Count != 1 || records(theirs)[0] != o.Other {
		t.Fatalf("team B: %+v %v", theirs, ok)
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
	if err := service(o).Dismiss(orgWide(o), domain.CIWorkload, "We use another issuer here."); err != nil {
		t.Fatal(err)
	}
	it, ok := item(list(team(o, a), t, o, true), domain.CIWorkload)
	if !ok || !it.Dismissed || it.Dismissal != nil {
		t.Fatalf("team: %+v %v", it, ok)
	}
	it, ok = item(list(orgWide(o), t, o, true), domain.CIWorkload)
	if !ok || it.Dismissal == nil || it.Dismissal.Reason != "We use another issuer here." {
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
	for _, reason := range []string{"", "too short", "   padded   ", strings.Repeat("x", 1001)} {
		if err := svc.Dismiss(ctx, domain.CIWorkload, reason); !errors.Is(err, app.ErrReason) {
			t.Errorf("reason %q: %v", reason, err)
		}
	}
	if err := svc.Dismiss(ctx, "identity.not_in_the_catalogue", "A long enough reason."); !errors.Is(err, app.ErrNotFound) {
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
	if _, ok := item(list(ctx, t, o, false), domain.AWSCredentials); !ok {
		t.Fatal("no AWS recommendation")
	}
	o.D.AdminExec(t, `UPDATE pc.connections SET package = $2 WHERE id = $1`, o.Conn, domain.PackageAWS)
	if _, ok := item(list(ctx, t, o, false), domain.AWSCredentials); ok {
		t.Fatal("still recommended with the connection active")
	}
	o.D.AdminExec(t, `UPDATE pc.connections SET state = 'RETIRED' WHERE id = $1`, o.Conn)
	if _, ok := item(list(ctx, t, o, false), domain.AWSCredentials); !ok {
		t.Fatal("a retired connection closed it")
	}
}
