// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/github/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// vanishNotices counts the vanish notices queued.
type vanishNotices struct {
	mu sync.Mutex
	n  int
}

func (v *vanishNotices) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if m.Type == "agent.discovery_vanished" {
		v.n++
	}
	return napp.Enqueued{Notification: ids.NewV7()}, nil
}

// complete is a report that read every source.
var complete = map[string]string{
	"/scanned/mcp_configs": "true", "/scanned/org_installations": "true", "/scanned/repositories": "true",
	"/scanned/rulesets": "true", "/scanned/workflows": "true",
}

// orgScans runs org scans of one connection end to end: a person starts
// each, the gateway claims its lease, submits findings and reports.
type orgScans struct {
	e       *env
	conn    ids.UUID
	gateway ids.UUID
	scans   *app.Scans
	store   *pgtransactions.Store
	inv     *aapp.Inventory
	notices *vanishNotices
}

func newOrgScans(t *testing.T) *orgScans {
	e := newEnv(t)
	gateway := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", e.org, gateway)
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	n := &vanishNotices{}
	return &orgScans{
		e: e, gateway: gateway, conn: e.gitHubConnection(t, gateway, e.brokerKey(t, gateway), "github", false),
		scans: &app.Scans{Pool: e.pool, Ents: edition(billing.Team)}, store: &pgtransactions.Store{Pool: e.pool, Notify: n},
		inv: aapp.NewInventory(e.pool, edition(billing.Team)), notices: n,
	}
}

// run runs one scan that finds findings and reports fields, found or not.
func (s *orgScans) run(t *testing.T, findings []aapp.ScanFinding, fields map[string]string, found bool) {
	t.Helper()
	scan, err := s.scans.Start(s.e.caller(td.KindUser, td.RoleSecurityAdmin), s.conn)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := s.store.Claim(context.Background(), s.e.org, s.gateway, 4, 30*time.Second)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases %+v %v", leases, err)
	}
	if len(findings) > 0 {
		if _, err := s.inv.SubmitGitHubScan(context.Background(), s.e.org, s.gateway, scan.ID, leases[0].Secret, findings); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.store.Report(context.Background(), s.e.org, s.gateway, tapp.Report{
		Task: leases[0].Task, Secret: leases[0].Secret, HTTPStatus: 200, Found: found, Complete: found, Fields: fields,
	}, nil); err != nil {
		t.Fatal(err)
	}
}

func (s *orgScans) missed(t *testing.T, kind string) int {
	t.Helper()
	return s.e.count(t, `SELECT coalesce(max(missed_scans), -1)::int FROM pc.discoveries
		WHERE org_id = $1 AND source = 'github_scan' AND observed ->> 'kind' = $2`, s.e.org, kind)
}

func workflow(b byte) aapp.ScanFinding {
	return aapp.ScanFinding{Kind: "github_workflow", Key: [32]byte{b}, Attributes: map[string]string{"repository": "acme/payments", "path": ".github/workflows/deploy.yml"}}
}

func ghApp(b byte) aapp.ScanFinding {
	return aapp.ScanFinding{Kind: "github_app", Key: [32]byte{b}, Attributes: map[string]string{"app_slug": "bot"}}
}

// TestHR458_VanishedOrgScanDiscoveryOnlyNotifies: an org-scan discovery
// missed by 3 complete scans is announced once, its agent unchanged; seen
// again, its misses reset.
// Covers: PN-001.3
func TestHR458_VanishedOrgScanDiscoveryOnlyNotifies(t *testing.T) {
	s := newOrgScans(t)
	s.run(t, []aapp.ScanFinding{workflow(1), ghApp(2)}, complete, true)
	for range 4 {
		s.run(t, []aapp.ScanFinding{ghApp(2)}, complete, true)
	}
	if got := s.missed(t, "github_workflow"); got != 4 {
		t.Errorf("workflow missed %d scans, want 4", got)
	}
	if got := s.missed(t, "github_app"); got != 0 {
		t.Errorf("the app seen every scan missed %d", got)
	}
	if s.notices.n != 1 {
		t.Errorf("%d vanish notices, want 1", s.notices.n)
	}
	if got := s.e.count(t, `SELECT count(*) FROM pc.discoveries d JOIN pc.agents a ON a.org_id = d.org_id AND a.id = d.agent_id
		WHERE d.org_id = $1 AND d.observed ->> 'kind' = 'github_workflow' AND d.state = 'OPEN' AND a.state = 'DISCOVERED'
		AND d.vanish_notified_at IS NOT NULL`, s.e.org); got != 1 {
		t.Error("the vanished discovery or its agent changed state")
	}
	if got := s.e.count(t, "SELECT count(*) FROM pc.grants WHERE org_id = $1", s.e.org); got != 0 {
		t.Errorf("%d grants", got)
	}
	s.run(t, []aapp.ScanFinding{workflow(1), ghApp(2)}, complete, true)
	if got := s.missed(t, "github_workflow"); got != 0 {
		t.Errorf("seen again, the workflow has %d misses", got)
	}
	if got := s.e.count(t, "SELECT count(*) FROM pc.agent_changes WHERE org_id = $1 AND kind = 'agent.discovery_reappeared'", s.e.org); got != 1 {
		t.Errorf("%d reappearances", got)
	}
}

// TestHR459_PartialOrFailedOrgScanCountsNoMiss: a failed scan, one that did
// not read a kind's sources, and one that could not submit its findings
// count no miss for the kinds they did not read in full.
// Covers: PN-001.3
func TestHR459_PartialOrFailedOrgScanCountsNoMiss(t *testing.T) {
	s := newOrgScans(t)
	s.run(t, []aapp.ScanFinding{workflow(1), ghApp(2)}, complete, true)
	// Failed: the App could not be used.
	s.run(t, nil, map[string]string{"/not_scanned/organization": "the connection's GitHub App could not be used"}, false)
	// Workflows not read: only the app's absence counts.
	s.run(t, nil, map[string]string{
		"/scanned/org_installations": "true", "/scanned/repositories": "true", "/not_scanned/workflows": "rate limited",
	}, true)
	// Repositories it could not read: workflows do not count.
	partial := map[string]string{"/not_scanned/contents": "2 repositories could not be read"}
	for k, v := range complete {
		partial[k] = v
	}
	s.run(t, nil, partial, true)
	// Findings it could not submit: nothing counts.
	lost := map[string]string{"/not_scanned/findings": "some findings could not be submitted"}
	for k, v := range complete {
		lost[k] = v
	}
	s.run(t, nil, lost, true)
	if got := s.missed(t, "github_workflow"); got != 0 {
		t.Errorf("partial or failed scans counted %d workflow misses", got)
	}
	if got := s.missed(t, "github_app"); got != 2 {
		t.Errorf("the app missed %d scans that read installations in full, want 2", got)
	}
}

// TestT201_PartialOrForgedScansNeitherHideNorFakeDisappearance: a CI-mode
// scan, which a service account runs, never counts against an org scan's
// discoveries or another principal's, nor the reverse, nor names their findings; and a material
// change is recorded even by a scan that missed other kinds.
// Covers: PN-001.3
func TestT201_PartialOrForgedScansNeitherHideNorFakeDisappearance(t *testing.T) {
	s := newOrgScans(t)
	s.run(t, []aapp.ScanFinding{workflow(1)}, complete, true)
	sa := s.e.caller(td.KindServiceAccount, td.RoleAgentOwner)
	mcp := aapp.ScanFinding{Kind: "mcp_server", Key: [32]byte{9}, Attributes: map[string]string{"name": "x", "transport": "stdio"}}
	for range 4 {
		if _, err := s.inv.SubmitScan(sa, "runner", []aapp.ScanFinding{mcp}, aapp.ScanMode{Scope: "acme/payments", Complete: true}); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.missed(t, "github_workflow"); got != 0 {
		t.Errorf("CI-mode scans counted %d misses of an org-scan discovery", got)
	}
	// A CI-mode scan cannot name github_* findings to fake their presence.
	if _, err := s.inv.SubmitScan(sa, "runner", []aapp.ScanFinding{workflow(1)}, aapp.ScanMode{Scope: "acme/payments", Complete: true}); !errors.Is(err, aapp.ErrScanKind) {
		t.Errorf("a CI-mode scan naming an org-scan finding: %v", err)
	}
	// Org scans never count the CI scope's discovery.
	for range 4 {
		s.run(t, []aapp.ScanFinding{workflow(1)}, complete, true)
	}
	if got := s.e.count(t, "SELECT missed_scans FROM pc.discoveries WHERE org_id = $1 AND source = 'ci_scan'", s.e.org); got != 0 {
		t.Errorf("org scans counted %d misses of a CI-mode discovery", got)
	}
	// Another service account's complete scans of the same scope count
	// nothing against this one's discoveries (D136).
	sa2 := s.e.caller(td.KindServiceAccount, td.RoleAgentOwner)
	for range 4 {
		other := aapp.ScanFinding{Kind: "mcp_server", Key: [32]byte{10}, Attributes: map[string]string{"name": "y", "transport": "stdio"}}
		if r, err := s.inv.SubmitScan(sa2, "runner", []aapp.ScanFinding{other}, aapp.ScanMode{Scope: "acme/payments", Complete: true}); err != nil || r.Missed != 0 {
			t.Fatalf("another service account's scan: %+v %v", r, err)
		}
	}
	if got := s.e.count(t, "SELECT missed_scans FROM pc.discoveries WHERE org_id = $1 AND source = 'ci_scan' AND observed ->> 'name' = 'x'", s.e.org); got != 0 {
		t.Errorf("another service account's scans counted %d misses", got)
	}
	// A partial scan still records a material change of what it saw.
	changed := workflow(1)
	changed.Attributes["permissions"] = "contents:write"
	s.run(t, []aapp.ScanFinding{changed}, map[string]string{"/scanned/repositories": "true", "/not_scanned/workflows": "rate limited"}, true)
	if got := s.e.count(t, "SELECT count(*) FROM pc.agent_changes WHERE org_id = $1 AND kind = 'agent.discovery_changed' AND details ->> 'untrusted.after.permissions' = 'contents:write'", s.e.org); got != 1 {
		t.Errorf("%d recorded changes, want 1", got)
	}
}

// TestHR459_DismissedOrgScanDiscoveryCountsNoMiss: a dismissed org-scan
// discovery never counts a miss and is never announced (D136).
// Covers: PN-001.3
func TestHR459_DismissedOrgScanDiscoveryCountsNoMiss(t *testing.T) {
	s := newOrgScans(t)
	s.run(t, []aapp.ScanFinding{workflow(1), ghApp(2)}, complete, true)
	s.e.exec(t, "UPDATE pc.discoveries SET state = 'DISMISSED' WHERE org_id = $1 AND observed ->> 'kind' = 'github_workflow'", s.e.org)
	for range 4 {
		s.run(t, []aapp.ScanFinding{ghApp(2)}, complete, true)
	}
	if got := s.missed(t, "github_workflow"); got != 0 {
		t.Errorf("a dismissed discovery counted %d misses", got)
	}
	if s.notices.n != 0 {
		t.Errorf("%d vanish notices for a dismissed discovery", s.notices.n)
	}
}
