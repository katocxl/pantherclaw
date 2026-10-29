// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/agents/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// notices records what would be announced.
type notices struct {
	mu   sync.Mutex
	msgs []napp.Message
}

func (n *notices) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, m)
	return napp.Enqueued{Notification: ids.NewV7()}, nil
}

func (n *notices) of(typ string) []napp.Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []napp.Message
	for _, m := range n.msgs {
		if m.Type == typ {
			out = append(out, m)
		}
	}
	return out
}

func server(name, transport string) app.ScanFinding {
	return app.ScanFinding{Kind: "mcp_server", Key: sha256.Sum256([]byte("mcp_server" + name)),
		Attributes: map[string]string{"name": name, "client": "cursor", "transport": transport}}
}

// TestHR458_VanishedCIDiscoveryOnlyNotifies: a ci_scan discovery missed by
// 3 complete scans of its scope in a row is announced once, and nothing
// about it or its agent changes; seen again, its misses reset and its
// reappearance is recorded without a notice. Another scope's scans never
// count against it.
// Covers: PN-001.3
func TestHR458_VanishedCIDiscoveryOnlyNotifies(t *testing.T) {
	w := newWorld(t)
	n := &notices{}
	w.inv.WithNotify(n)
	ci := as(w.org, td.KindServiceAccount, bind(td.RoleAgentOwner, td.ScopeOrg, w.org.UUID()))
	repo := app.ScanMode{Scope: "acme/payments", Complete: true}
	keep, gone := server("keep", "stdio"), server("gone", "stdio")
	if r, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{keep, gone}, repo); err != nil || r.Created != 2 || r.Missed != 0 {
		t.Fatalf("first scan %+v %v", r, err)
	}
	// The same finding in another scope is another discovery; its scans
	// never count against acme/payments.
	other := app.ScanMode{Scope: "acme/web", Complete: true}
	for range 4 {
		if _, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{keep}, other); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 4 {
		r, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{keep}, repo)
		if err != nil || r.Missed != 1 {
			t.Fatalf("scan %d: %+v %v", i+2, r, err)
		}
	}
	if got := w.count(t, `SELECT missed_scans FROM pc.discoveries WHERE org_id = $1 AND source = 'ci_scan' AND observed ->> 'name' = 'gone'`, w.org); got != 4 {
		t.Errorf("missed_scans = %d, want 4", got)
	}
	if got := len(n.of("agent.discovery_vanished")); got != 1 {
		t.Errorf("%d vanish notices after 4 misses, want 1", got)
	}
	if got := w.count(t, "SELECT count(*) FROM pc.agent_changes WHERE org_id = $1 AND kind = 'agent.discovery_vanished'", w.org); got != 1 {
		t.Errorf("%d vanish changes, want 1", got)
	}
	// Nothing changed: the discovery is open, its agent discovered, no
	// grant or retirement.
	if got := w.count(t, `SELECT count(*) FROM pc.discoveries d JOIN pc.agents a ON a.org_id = d.org_id AND a.id = d.agent_id
		WHERE d.org_id = $1 AND d.observed ->> 'name' = 'gone' AND d.state = 'OPEN' AND a.state = 'DISCOVERED'`, w.org); got != 1 {
		t.Errorf("the vanished discovery or its agent changed state")
	}
	if got := w.count(t, "SELECT count(*) FROM pc.grants WHERE org_id = $1", w.org); got != 0 {
		t.Errorf("%d grants", got)
	}
	// Seen again: misses reset, the reappearance recorded, no notice.
	if _, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{keep, gone}, repo); err != nil {
		t.Fatal(err)
	}
	if got := w.count(t, `SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND source = 'ci_scan' AND scan_scope = 'acme/payments'
		AND missed_scans = 0 AND vanish_notified_at IS NULL`, w.org); got != 2 {
		t.Errorf("%d discoveries reset, want 2", got)
	}
	if got := w.count(t, "SELECT count(*) FROM pc.agent_changes WHERE org_id = $1 AND kind = 'agent.discovery_reappeared'", w.org); got != 1 {
		t.Errorf("%d reappearances recorded, want 1", got)
	}
	if got := len(n.msgs); got != 1 {
		t.Errorf("%d notices in all, want only the vanish notice", got)
	}
}

// TestHR459_OnlyACompleteScanCountsAMiss: a scan without the complete flag,
// a desktop scan, and a complete scan that dropped findings count no miss;
// a complete scan is one submission of at most 200 findings (D130) and
// needs a scope.
// Covers: PN-001.3
func TestHR459_OnlyACompleteScanCountsAMiss(t *testing.T) {
	w := newWorld(t)
	ci := as(w.org, td.KindServiceAccount, bind(td.RoleAgentOwner, td.ScopeOrg, w.org.UUID()))
	scope := "acme/payments"
	if _, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{server("a", "stdio"), server("b", "stdio")},
		app.ScanMode{Scope: scope, Complete: true}); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if r, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{server("a", "stdio")}, app.ScanMode{Scope: scope}); err != nil || r.Missed != 0 {
			t.Fatalf("not complete: %+v %v", r, err)
		}
		if _, err := w.inv.SubmitScan(ci, "laptop", []app.ScanFinding{server("a", "stdio")}, app.ScanMode{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.count(t, "SELECT coalesce(sum(missed_scans), 0)::int FROM pc.discoveries WHERE org_id = $1", w.org); got != 0 {
		t.Errorf("scans that were not complete counted %d misses", got)
	}
	// Over 200 findings, or no scope, is refused before anything is read.
	var many []app.ScanFinding
	for i := range app.MaxCompleteFindings + 1 {
		many = append(many, server("s"+string(rune('a'+i%26))+string(rune('a'+i/26)), "stdio"))
	}
	if _, err := w.inv.SubmitScan(ci, "runner", many, app.ScanMode{Scope: scope, Complete: true}); !errors.Is(err, app.ErrCompleteTooLarge) {
		t.Errorf("an over-200 complete scan: %v", err)
	}
	if _, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{server("a", "stdio")}, app.ScanMode{Complete: true}); !errors.Is(err, app.ErrScopeRequired) {
		t.Errorf("a complete scan without a scope: %v", err)
	}
	if _, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{server("a", "stdio")}, app.ScanMode{Scope: "bad‮scope", Complete: true}); !errors.Is(err, app.ErrScope) {
		t.Errorf("a bidi scope: %v", err)
	}
	// A complete scan that dropped findings (the org's open cap) did not
	// record all it saw, so it counts nothing.
	w.exec(t, w.org, `INSERT INTO pc.agents (org_id, id, name, state, created_by)
		SELECT $1, gen_random_uuid(), 'filler', 'DISCOVERED', 'test' FROM generate_series(1, $2)`, w.org, app.MaxOpenScanDiscoveries)
	w.exec(t, w.org, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, scan_scope, observed)
		SELECT $1, gen_random_uuid(), a.id, 'ci_scan', sha256(a.id::text::bytea), 'filler', '{}' FROM pc.agents a
		WHERE a.org_id = $1 AND a.name = 'filler'`, w.org)
	r, err := w.inv.SubmitScan(ci, "runner", []app.ScanFinding{server("new", "stdio")}, app.ScanMode{Scope: scope, Complete: true})
	if err != nil || r.Dropped != 1 || r.Missed != 0 {
		t.Fatalf("a complete scan that dropped a finding: %+v %v", r, err)
	}
	if got := w.count(t, "SELECT coalesce(sum(missed_scans), 0)::int FROM pc.discoveries WHERE org_id = $1 AND scan_scope = $2", w.org, scope); got != 0 {
		t.Errorf("a scan that dropped findings counted %d misses", got)
	}
}

// TestHR460_MaterialChangeOnClaimedDiscoveryIsRecorded: what a claimed (or
// open) discovery's route may do changing is recorded with the before and
// after values of the changed material keys only, and its owners are told;
// the agent keeps its state. A change of other attributes records nothing.
// Covers: PN-001.3
func TestHR460_MaterialChangeOnClaimedDiscoveryIsRecorded(t *testing.T) {
	w := newWorld(t)
	n := &notices{}
	w.inv.WithNotify(n)
	owner := w.teamOwner()
	f := server("tickets", "stdio")
	if _, err := w.inv.SubmitScan(owner, "laptop", []app.ScanFinding{f}, app.ScanMode{}); err != nil {
		t.Fatal(err)
	}
	var agent ids.UUID
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT agent_id FROM pc.discoveries WHERE org_id = $1 AND source = 'scan'", w.org).Scan(&agent)
	}); err != nil {
		t.Fatal(err)
	}
	orgOwner := as(w.org, td.KindUser, bind(td.RoleAgentOwner, td.ScopeOrg, w.org.UUID()))
	det := w.details()
	if _, err := w.inv.Claim(orgOwner, agent, &det, ids.UUID{}, "our ticket bot"); err != nil {
		t.Fatal(err)
	}
	// Only the client changed: not material, nothing recorded.
	f.Attributes["client"] = "vscode"
	if _, err := w.inv.SubmitScan(owner, "laptop", []app.ScanFinding{f}, app.ScanMode{}); err != nil {
		t.Fatal(err)
	}
	if len(n.of("agent.discovery_changed")) != 0 {
		t.Fatal("a non-material change was announced")
	}
	f.Attributes["transport"], f.Attributes["url_host"] = "http", "evil.example"
	if _, err := w.inv.SubmitScan(owner, "laptop", []app.ScanFinding{f}, app.ScanMode{}); err != nil {
		t.Fatal(err)
	}
	pr, err := page.Parse(100, "")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := w.inv.ListChanges(orgOwner, agent, pr)
	if err != nil {
		t.Fatal(err)
	}
	ch := listed.Items
	var got *app.Change
	for i := range ch {
		if ch[i].Kind == string(domain.ChangeDiscoveryChanged) {
			got = &ch[i]
		}
	}
	if got == nil || got.Details["before.transport"] != "stdio" || got.Details["after.transport"] != "http" ||
		got.Details["before.url_host"] != "(none)" || got.Details["after.url_host"] != "evil.example" {
		t.Fatalf("change %+v", got)
	}
	for k := range got.Details {
		if k == "before.client" || k == "after.client" || k == "before.name" {
			t.Errorf("a non-material key was recorded: %s", k)
		}
	}
	msgs := n.of("agent.discovery_changed")
	if len(msgs) != 1 || !slices.Contains(msgs[0].Personal, w.owner) || !slices.Contains(msgs[0].Personal, w.backup) ||
		msgs[0].Params["keys"] != "transport, url_host" {
		t.Fatalf("notices %+v", msgs)
	}
	if got := w.count(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1 AND id = $2 AND state = 'CLAIMED'", w.org, agent); got != 1 {
		t.Error("the claimed agent changed state")
	}
}
