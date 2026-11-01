// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/agents/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestD230_RiskFieldsAreStatedAndRecorded: a holder of agent.manage states
// the risk fields, each write leaves a history entry and an audit record,
// unset fields stay, an empty list clears, and only closed values pass.
// Covers: F880
func TestD230_RiskFieldsAreStatedAndRecorded(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	a, err := w.inv.Create(ctx, w.details())
	if err != nil {
		t.Fatal(err)
	}
	if a.RiskTier != domain.RiskUnset || a.AIActRole != domain.AIActRoleUnset || a.AIActRisk != domain.AIActRiskUnset || len(a.DataClasses) != 0 {
		t.Fatalf("defaults: %+v", a)
	}
	tier, role, risk := domain.RiskHigh, domain.AIActRoleDeployer, domain.AIActRiskLimited
	got, err := w.inv.Update(ctx, a.ID, nil, nil, domain.RiskPatch{Tier: &tier, DataClasses: []string{"pii", "secret"}, Role: &role, Risk: &risk})
	if err != nil {
		t.Fatal(err)
	}
	if got.RiskTier != tier || got.AIActRole != role || got.AIActRisk != risk || !slices.Equal(got.DataClasses, []string{"pii", "secret"}) || got.Name != a.Name {
		t.Fatalf("after update: %+v", got)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.agent_changes WHERE org_id = $1 AND agent_id = $2 AND kind = 'agent.risk_updated'
		AND details->>'risk_tier' = 'HIGH' AND details->>'ai_act_role' = 'DEPLOYER'`, w.org, a.ID); n != 1 {
		t.Fatalf("history entries: %d", n)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agents.risk_updated'`, w.org); n != 1 {
		t.Fatalf("audit records: %d", n)
	}
	// A name change alongside keeps both; a tier alone keeps the classes.
	low, name := domain.RiskLow, "renamed"
	got, err = w.inv.Update(ctx, a.ID, &name, nil, domain.RiskPatch{Tier: &low})
	if err != nil || got.Name != name || got.RiskTier != low || len(got.DataClasses) != 2 {
		t.Fatalf("name and tier: %+v, %v", got, err)
	}
	if got, err = w.inv.Update(ctx, a.ID, nil, nil, domain.RiskPatch{DataClasses: []string{}}); err != nil || len(got.DataClasses) != 0 || got.RiskTier != low {
		t.Fatalf("clearing classes: %+v, %v", got, err)
	}
	bad := domain.RiskTier("EXTREME")
	_, err = w.inv.Update(ctx, a.ID, nil, nil, domain.RiskPatch{Tier: &bad})
	wantCode(t, "unknown tier", err, pcerr.InvalidArgument, "")
	_, err = w.inv.Update(ctx, a.ID, nil, nil, domain.RiskPatch{DataClasses: []string{"confidential"}})
	wantCode(t, "unknown class", err, pcerr.InvalidArgument, "")
	_, err = w.inv.Update(as(w.org, td.KindUser, bind(td.RoleViewer, td.ScopeOrg, w.org.UUID())), a.ID, nil, nil, domain.RiskPatch{Tier: &tier})
	wantCode(t, "a viewer", err, pcerr.PermissionDenied, "")
	if _, err := w.inv.Retire(ctx, a.ID, "no longer used here"); err != nil {
		t.Fatal(err)
	}
	if _, err = w.inv.Update(ctx, a.ID, nil, nil, domain.RiskPatch{Tier: &tier}); err == nil {
		t.Fatal("a retired agent changed")
	}
}

// TestD231_CardShowsPurposeOwnerRiskAndPinnedTools: the card needs what
// reading the agent needs, and lists only operations of a usable pinned
// version the agent has coverage of.
// Covers: F881
func TestD231_CardShowsPurposeOwnerRiskAndPinnedTools(t *testing.T) {
	o := exposuretest.New(t)
	inv := app.NewInventory(o.P, &fakeEnts{})
	admin := as(o.Org, td.KindUser, bind(td.RoleOrgAdmin, td.ScopeOrg, o.Org.UUID()))
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		for i, op := range []string{"payments.refund", "payments.capture", "payments.not_in_package"} {
			e, err := ledger.Append(ctx, tx, "coverage.snapshot", evdomain.Actor{Type: "system", ID: "test"}, []byte(`{}`))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, body,
				body_sha256, ledger_entry_id) VALUES ($1, $2, $3, $4, $5, 'OBSERVE_ONLY', '{}', '{}', $6, $7)`,
				o.Org, ids.NewV7(), o.Agent, o.Conn, op, make([]byte, 32), e.ID); err != nil {
				return err
			}
			if i == 2 {
				continue
			}
			sum := sha256.Sum256([]byte(op))
			if _, err := tx.Exec(ctx, `INSERT INTO pc.action_definitions (org_id, id, version_id, operation, digest, canonical)
				VALUES ($1, $2, $3, $4, $5, '{}')`, o.Org, ids.NewV7(), o.Version, op, fmt.Sprintf("sha256:%x", sum)); err != nil {
				return err
			}
		}
		return nil
	})
	card, err := inv.Card(admin, o.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(card.Tools) != 2 || card.Tools[0].Operation != "payments.capture" || card.Tools[1].Operation != "payments.refund" ||
		card.Tools[0].Connection != "payments" || card.Tools[0].Package != "pc.mock-payments" || card.Tools[0].Version != "1.0.0" || card.Truncated {
		t.Fatalf("tools: %+v", card)
	}
	if card.RiskTier != domain.RiskUnset || card.ID != o.Agent {
		t.Fatalf("card: %+v", card)
	}
	// A quarantined pin is no longer approved.
	o.D.AdminExec(t, `UPDATE pc.package_versions SET state = 'QUARANTINED' WHERE id = $1`, o.Version)
	if card, err = inv.Card(admin, o.Agent); err != nil || len(card.Tools) != 0 {
		t.Fatalf("after quarantine: %+v, %v", card, err)
	}
	// Out of scope, the card refuses exactly as reading the agent does.
	other := as(o.Org, td.KindUser, bind(td.RoleViewer, td.ScopeTeam, ids.NewV7()))
	_, err = inv.Card(other, o.Agent)
	wantCode(t, "out of scope", err, pcerr.PermissionDenied, "")
	_, getErr := inv.Get(other, o.Agent)
	wantCode(t, "reading the agent", getErr, pcerr.CodeOf(err), pcerr.ReasonOf(err))
}

// TestHR588_ServerKeepsOnlyMetadata: the server refuses a closed-kind finding
// that carries more than its named attributes, or a credential kind off the
// list, whatever a client sends. A valid one becomes a discovery.
// Covers: T-255
// Covers: F883, F889
func TestHR588_ServerKeepsOnlyMetadata(t *testing.T) {
	w := newWorld(t)
	f := func(kind string, attrs map[string]string) []app.ScanFinding {
		return []app.ScanFinding{{Kind: kind, Key: sha256.Sum256(fmt.Append(nil, kind, attrs)), Attributes: attrs}}
	}
	for _, bad := range []app.ScanFinding{
		f("hook", map[string]string{"event": "Stop", "executable": "x", "command": "x --key sekret"})[0],
		f("skill", map[string]string{"name": "a", "path": "/a", "body": "text"})[0],
		f("env_secret", map[string]string{"secret_kind": "openai_api_key", "redacted": "sk-proj-…"})[0],
		f("env_secret", map[string]string{"secret_kind": "not_a_kind"})[0],
		f("env_secret", map[string]string{})[0],
	} {
		_, err := w.inv.SubmitScan(w.teamOwner(), "laptop", []app.ScanFinding{bad}, app.ScanMode{})
		wantCode(t, bad.Kind, err, pcerr.InvalidArgument, "SCAN_ATTRIBUTES")
	}
	for _, good := range [][]app.ScanFinding{
		f("hook", map[string]string{"event": "Stop", "executable": "guard.sh"}),
		f("hook", map[string]string{"event": "Stop"}),
		f("skill", map[string]string{"name": "review", "path": "/home/a/.claude/skills/review"}),
		f("env_secret", map[string]string{"secret_kind": "openai_api_key"}),
	} {
		r, err := w.inv.SubmitScan(w.teamOwner(), "laptop", good, app.ScanMode{})
		if err != nil || r.Created != 1 {
			t.Fatalf("%v: %+v, %v", good, r, err)
		}
	}
	if n := w.count(t, `SELECT count(*) FROM pc.agents WHERE org_id = $1 AND state = 'DISCOVERED'
		AND name IN ('hook Stop (guard.sh)', 'hook Stop', 'skill review', 'credential openai_api_key')`, w.org); n != 4 {
		t.Fatalf("named agents: %d", n)
	}
}

// TestD234_CapIsPerSourceAndScope: a full device fills only its own room, and
// what it drops is still counted; another device and unscoped scans go on.
// Covers: F885
func TestD234_CapIsPerSourceAndScope(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	batch := func(prefix string, n int) []app.ScanFinding {
		out := make([]app.ScanFinding, n)
		for i := range out {
			out[i] = finding("mcp_server", fmt.Sprint(prefix, i))
		}
		return out
	}
	full := app.ScanMode{Scope: "device:0000000000000001"}
	r, err := w.inv.SubmitScan(ctx, "a", batch("a", app.MaxOpenScanDiscoveries), full)
	if err != nil || r.Created != app.MaxOpenScanDiscoveries {
		t.Fatalf("filling a device: %+v, %v", r, err)
	}
	if r, err = w.inv.SubmitScan(ctx, "a", batch("over", 2), full); err != nil || r.Dropped != 2 || r.Created != 0 {
		t.Fatalf("past the cap: %+v, %v", r, err)
	}
	if r, err = w.inv.SubmitScan(ctx, "b", batch("b", 3), app.ScanMode{Scope: "device:0000000000000002"}); err != nil || r.Created != 3 || r.Dropped != 0 {
		t.Fatalf("another device: %+v, %v", r, err)
	}
	if r, err = w.inv.SubmitScan(ctx, "c", batch("c", 3), app.ScanMode{}); err != nil || r.Created != 3 || r.Dropped != 0 {
		t.Fatalf("an unscoped scan: %+v, %v", r, err)
	}
}

// scanner is a service account holding the Scanner role on a team.
func (w *world) scanner() context.Context {
	return as(w.org, td.KindServiceAccount, bind(td.RoleScanner, td.ScopeTeam, w.team))
}

// TestHR589_ScannerSubmitsOneDevicesPartialScan: the Scanner role admits a
// partial scan of a device scope, and no other scan.
// Covers: F887
func TestHR589_ScannerSubmitsOneDevicesPartialScan(t *testing.T) {
	w := newWorld(t)
	finding := []app.ScanFinding{{
		Kind: "skill", Key: sha256.Sum256([]byte("review")),
		Attributes: map[string]string{"name": "review", "path": "/home/a/.claude/skills/review"},
	}}
	const device = "device:0123456789abcdef"
	r, err := w.inv.SubmitScan(w.scanner(), "laptop", finding, app.ScanMode{Scope: device})
	if err != nil || r.Created != 1 {
		t.Fatalf("a device scan: %+v, %v", r, err)
	}
	for what, mode := range map[string]app.ScanMode{
		"no scope":       {},
		"a CI scope":     {Scope: "ci/repo"},
		"short id":       {Scope: "device:0123"},
		"upper-case id":  {Scope: "device:0123456789ABCDEF"},
		"a complete run": {Scope: device, Complete: true},
	} {
		_, err := w.inv.SubmitScan(w.scanner(), "laptop", finding, mode)
		wantCode(t, what, err, pcerr.PermissionDenied, "SCANNER_SCOPE")
	}
	// A holder of neither permission is refused for its missing permission,
	// also on a device scope.
	_, err = w.inv.SubmitScan(as(w.org, td.KindUser, bind(td.RoleViewer, td.ScopeOrg, w.org.UUID())), "laptop", finding, app.ScanMode{Scope: device})
	if pcerr.CodeOf(err) != pcerr.PermissionDenied || pcerr.ReasonOf(err) == "SCANNER_SCOPE" {
		t.Errorf("a viewer: %v", err)
	}
	// agent.manage keeps every mode.
	if _, err := w.inv.SubmitScan(w.teamOwner(), "laptop", finding, app.ScanMode{Scope: "ci/repo", Complete: true}); err != nil {
		t.Errorf("agent.manage: %v", err)
	}
}

// TestT254_ScanKeyStolenFromALaptop: with the key the thief can add findings
// to a device's scope and nothing else: it cannot read or change the
// inventory, or clear what a complete scan would close.
// Covers: F887
func TestT254_ScanKeyStolenFromALaptop(t *testing.T) {
	w := newWorld(t)
	a, err := w.inv.Create(w.teamOwner(), w.details())
	if err != nil {
		t.Fatal(err)
	}
	stolen := w.scanner()
	if _, err := w.inv.Create(stolen, w.details()); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("Create: %v", err)
	}
	name := "taken"
	if _, err := w.inv.Update(stolen, a.ID, &name, nil, domain.RiskPatch{}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("Update: %v", err)
	}
	if _, err := w.inv.Get(stolen, a.ID); pcerr.CodeOf(err) != pcerr.PermissionDenied && pcerr.CodeOf(err) != pcerr.NotFound {
		t.Errorf("Get: %v", err)
	}
	if _, err := w.inv.Card(stolen, a.ID); pcerr.CodeOf(err) != pcerr.PermissionDenied && pcerr.CodeOf(err) != pcerr.NotFound {
		t.Errorf("Card: %v", err)
	}
	if _, err := w.inv.Retire(stolen, a.ID, "taken"); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("Retire: %v", err)
	}
	// A CI scan's discovery stays: the stolen key cannot run a complete scan
	// over that scope to count it missed.
	finding := []app.ScanFinding{{
		Kind: "skill", Key: sha256.Sum256([]byte("ci")),
		Attributes: map[string]string{"name": "ci", "path": "/ci"},
	}}
	if _, err := w.inv.SubmitScan(w.teamOwner(), "ci", finding, app.ScanMode{Scope: "ci/repo", Complete: true}); err != nil {
		t.Fatal(err)
	}
	_, err = w.inv.SubmitScan(stolen, "ci", nil, app.ScanMode{Scope: "ci/repo", Complete: true})
	wantCode(t, "clearing a CI scope", err, pcerr.PermissionDenied, "SCANNER_SCOPE")
	if n := w.count(t, `SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND source = 'ci_scan' AND state = 'OPEN'`, w.org); n != 1 {
		t.Fatalf("open CI discoveries: %d", n)
	}
}

// TestD246_DeviceScopesAreBoundedAcrossAnOrg: one key starts so many device
// scopes an hour, an org holds so many open, known scopes go on, and each
// limit leaves one audit record in its window.
// Covers: F885
func TestD246_DeviceScopesAreBoundedAcrossAnOrg(t *testing.T) {
	w := newWorld(t)
	w.inv.WithDeviceLimits(2, 100)
	n := 0
	submit := func(ctx context.Context, device int) error {
		n++
		_, err := w.inv.SubmitScan(ctx, "", []app.ScanFinding{{
			Kind: "skill", Key: sha256.Sum256(fmt.Append(nil, n)),
			Attributes: map[string]string{"name": "s", "path": "~/s"},
		}}, app.ScanMode{Scope: fmt.Sprintf("device:%016x", device)})
		return err
	}
	audits := func() int {
		return w.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agents.scan_device_limit'`, w.org)
	}
	key := w.scanner()
	for _, d := range []int{1, 2} {
		if err := submit(key, d); err != nil {
			t.Fatalf("device %d: %v", d, err)
		}
	}
	for _, d := range []int{3, 4, 5} {
		wantCode(t, "past the key's limit", submit(key, d), pcerr.ResourceExhausted, "SCAN_DEVICE_LIMIT")
	}
	if got := audits(); got != 1 {
		t.Fatalf("audit records: %d", got)
	}
	if err := submit(key, 1); err != nil {
		t.Errorf("a known scope: %v", err)
	}
	if err := submit(w.scanner(), 6); err != nil {
		t.Errorf("another key: %v", err)
	}
	w.inv.WithDeviceLimits(100, 3)
	for _, d := range []int{7, 8} {
		wantCode(t, "past the org's limit", submit(w.scanner(), d), pcerr.ResourceExhausted, "SCAN_DEVICE_LIMIT")
	}
	if got := audits(); got != 2 {
		t.Fatalf("audit records with the org's limit: %d", got)
	}
	if err := submit(key, 2); err != nil {
		t.Errorf("a known scope past the org's limit: %v", err)
	}
	// Other scopes are not device scans.
	if _, err := w.inv.SubmitScan(w.teamOwner(), "", []app.ScanFinding{{
		Kind: "skill", Key: sha256.Sum256([]byte("ci")),
		Attributes: map[string]string{"name": "s", "path": "/s"},
	}}, app.ScanMode{Scope: "ci/repo"}); err != nil {
		t.Errorf("a CI scope: %v", err)
	}
}

// TestD252_TheServerKeepsNamedPlainAttributes: every kind has closed names and
// plain values; what falls outside is dropped and counted, and stored nowhere.
// Covers: F883
func TestD252_TheServerKeepsNamedPlainAttributes(t *testing.T) {
	w := newWorld(t)
	r, err := w.inv.SubmitScan(w.teamOwner(), "laptop", []app.ScanFinding{
		{Kind: "mcp_server", Key: sha256.Sum256([]byte("m")), Attributes: map[string]string{
			"name": "tickets", "client": "cursor", "args": "--token SEKRET", "command": "py\x1b[2Jthon", "config": "/x‮/y",
		}},
		{Kind: "agent_project", Key: sha256.Sum256([]byte("p")), Attributes: map[string]string{
			"path": "~/p", "manifest": "go.mod", "readme": "SEKRET",
		}},
		{Kind: "hook", Key: sha256.Sum256([]byte("h")), Attributes: map[string]string{"event": "Stop", "executable": "a\nb"}},
	}, app.ScanMode{})
	if err != nil || r.Created != 3 || r.DroppedAttributes != 5 {
		t.Fatalf("%+v, %v", r, err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND observed->>'name' = 'tickets'
		AND observed->>'client' = 'cursor' AND NOT observed ? 'args' AND NOT observed ? 'command' AND NOT observed ? 'config'`, w.org); n != 1 {
		t.Fatalf("mcp_server row: %d", n)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND observed::text LIKE '%SEKRET%'`, w.org); n != 0 {
		t.Fatalf("%d rows hold a dropped value", n)
	}
}
