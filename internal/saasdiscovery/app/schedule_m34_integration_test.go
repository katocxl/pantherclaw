// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/app"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

const m34Account = "123456789012"

// m34Collector is an active AgentCore collector connection served by a new
// gateway, and that gateway.
func (e *env) m34Collector(t *testing.T, source string) (conn, gateway ids.UUID) {
	t.Helper()
	gateway = ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, $3, 'test')", e.org, gateway, "gw-"+gateway.String())
	c, ok := domain.CollectorOf(source)
	if !ok {
		t.Fatalf("no collector for %s", source)
	}
	return e.connection(t, gateway, e.brokerKey(t, gateway), c.Package, c.CredentialKind), gateway
}

// m34Member gives person the agent_owner role at the org, as a role binding
// the daily job reads.
func (e *env) m34Member(t *testing.T, person ids.UUID) {
	t.Helper()
	e.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, 'agent_owner', $3, 'ORG', 'test')`, e.org, ids.NewV7(), person)
}

// m34Scans are the scan runs of conn with origin.
func (e *env) m34Scans(t *testing.T, conn ids.UUID, origin string) int {
	t.Helper()
	return e.count(t, "SELECT count(*) FROM pc.saas_scan_runs WHERE org_id = $1 AND connection_id = $2 AND origin = $3", e.org, conn, origin)
}

func (e *env) m34LastStarted(t *testing.T, conn ids.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	e.d.AdminQueryRow(t, "SELECT last_started_at FROM pc.saas_scan_schedules WHERE org_id = $1 AND connection_id = $2",
		[]any{e.org, conn}, &at)
	return at
}

// TestHR768_OnlyAPersonSetsADailyScan: a person holding agent.manage sets a
// daily scan of a runtime source's tenant through a connection of its
// collector package and stops it, each audited; a machine, a person without
// agent.manage, a tenant of the wrong shape, a source with no collector and
// a connection of another package are refused, and stopping a schedule that
// does not exist changes nothing (G0 M34 D997, D997a).
//
// Covers: F1046, HR-768
func TestHR768_OnlyAPersonSetsADailyScan(t *testing.T) {
	e := newEnv(t)
	conn, _ := e.m34Collector(t, domain.SourceAWSAgentCore)
	other, _ := e.m34Collector(t, domain.SourceChatGPTEnterprise)

	if _, err := e.svc.SetSchedule(e.as(ids.NewV7(), td.KindServiceAccount), domain.SourceAWSAgentCore, conn, m34Account, true); !errors.Is(err, app.ErrScheduleHumanOnly) {
		t.Errorf("a machine: %v", err)
	}
	viewer := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: e.user},
		Bindings: []td.Binding{{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tenancy.CredBrowserSession, Session: ids.NewV7()})
	if _, err := e.svc.SetSchedule(viewer, domain.SourceAWSAgentCore, conn, m34Account, true); err == nil {
		t.Error("a viewer set a schedule")
	}
	for what, c := range map[string]struct {
		source, tenant string
		conn           ids.UUID
	}{
		"an 11-digit account":         {domain.SourceAWSAgentCore, "12345678901", conn},
		"a Vertex tenant without '/'": {domain.SourceVertexAgentEngine, "my-project", conn},
		"a source with no collector":  {"github_scan", m34Account, conn},
		"no connection":               {domain.SourceAWSAgentCore, m34Account, ids.UUID{}},
		"another package":             {domain.SourceAWSAgentCore, m34Account, other},
		"a connection of no row":      {domain.SourceAWSAgentCore, m34Account, ids.NewV7()},
	} {
		if _, err := e.svc.SetSchedule(e.admin, c.source, c.conn, c.tenant, true); err == nil {
			t.Errorf("%s: set", what)
		}
	}
	if n := e.count(t, "SELECT count(*) FROM pc.saas_scan_schedules WHERE org_id = $1", e.org); n != 0 {
		t.Fatalf("%d schedules after the refusals", n)
	}

	s, err := e.svc.SetSchedule(e.admin, domain.SourceAWSAgentCore, conn, m34Account, true)
	if err != nil || s == nil || s.CreatedBy != "user:"+e.user.String() || s.LastStartedAt != nil {
		t.Fatalf("set: %+v %v", s, err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.saas.scan_schedule_set'", e.org); n != 1 {
		t.Errorf("%d scan_schedule_set entries", n)
	}
	if _, err := e.svc.SetSchedule(e.admin, domain.SourceAWSAgentCore, conn, "210987654321", false); err != nil {
		t.Errorf("stopping a schedule that does not exist: %v", err)
	}
	if _, err := e.svc.SetSchedule(e.admin, domain.SourceAWSAgentCore, conn, m34Account, false); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.saas.scan_schedule_cleared'", e.org); n != 1 {
		t.Errorf("%d scan_schedule_cleared entries, want 1", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.saas_scan_schedules WHERE org_id = $1", e.org); n != 0 {
		t.Errorf("%d schedules after stopping", n)
	}
}

// TestHR768_TheDailyJobStartsEachDueScheduleAsItsPerson: the daily job
// starts one scan per due schedule with origin schedule, started by the
// schedule's person and audited by System with the person named, and marks
// it started; a schedule started under 20 hours ago waits; a schedule whose
// person is no longer an active member holding agent.manage, whose
// connection's scan is still running, or of an edition without SaaS
// discovery is skipped and logged, its last start unchanged (G0 M34 D997a,
// FQ34-3).
//
// Covers: F1046, HR-768
func TestHR768_TheDailyJobStartsEachDueScheduleAsItsPerson(t *testing.T) {
	e := newEnv(t)
	e.m34Member(t, e.user)
	var logs bytes.Buffer
	sched := &app.Scheduler{Pool: e.pool, Editions: edition(billing.Business), Log: slog.New(slog.NewTextHandler(&logs, nil))}
	ctx := context.Background()

	conn, _ := e.m34Collector(t, domain.SourceAWSAgentCore)
	vertex, _ := e.m34Collector(t, domain.SourceVertexAgentEngine)
	if _, err := e.svc.SetSchedule(e.admin, domain.SourceAWSAgentCore, conn, m34Account, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetSchedule(e.admin, domain.SourceVertexAgentEngine, vertex, "my-project/us-central1", true); err != nil {
		t.Fatal(err)
	}

	// Another edition starts nothing.
	off := &app.Scheduler{Pool: e.pool, Editions: edition(billing.Community), Log: slog.New(slog.NewTextHandler(&logs, nil))}
	if n, err := off.RunOrg(ctx, e.org); err != nil || n != 0 {
		t.Fatalf("community: %d %v", n, err)
	}
	if !strings.Contains(logs.String(), "reason=edition") || e.m34LastStarted(t, conn) != nil {
		t.Fatalf("community: not skipped as edition: %s", logs.String())
	}

	n, err := sched.RunOrg(ctx, e.org)
	if err != nil || n != 2 {
		t.Fatalf("run: %d %v", n, err)
	}
	if e.m34Scans(t, conn, "schedule") != 1 || e.m34Scans(t, vertex, "schedule") != 1 {
		t.Fatal("not one scheduled scan per schedule")
	}
	if c := e.count(t, `SELECT count(*) FROM pc.saas_scan_runs WHERE org_id = $1 AND connection_id = $2 AND origin = 'schedule'
		AND started_by = $3 AND tenant = $4`, e.org, conn, "user:"+e.user.String(), m34Account); c != 1 {
		t.Error("the scheduled scan is not the person's")
	}
	if c := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE 'audit.saas.scan%'
		AND convert_from(body, 'UTF8') LIKE '%schedule_person%' AND convert_from(body, 'UTF8') LIKE '%saas_schedule%'`, e.org); c != 2 {
		t.Errorf("%d scheduled-scan audit entries naming System and the person, want 2", c)
	}
	first := e.m34LastStarted(t, conn)
	if first == nil {
		t.Fatal("last_started_at not set")
	}

	// Under 20 hours: nothing new.
	if n, err := sched.RunOrg(ctx, e.org); err != nil || n != 0 {
		t.Fatalf("again: %d %v", n, err)
	}
	if e.m34Scans(t, conn, "schedule") != 1 {
		t.Fatal("a second scan under 20 hours")
	}

	// Due again while the first scan still runs: skipped, last start kept.
	e.exec(t, "UPDATE pc.saas_scan_schedules SET last_started_at = now() - interval '21 hours' WHERE org_id = $1", e.org)
	due := e.m34LastStarted(t, conn)
	logs.Reset()
	if n, err := sched.RunOrg(ctx, e.org); err != nil || n != 0 {
		t.Fatalf("running: %d %v", n, err)
	}
	if !strings.Contains(logs.String(), "reason=running") || !e.m34LastStarted(t, conn).Equal(*due) {
		t.Fatalf("a running scan: %s", logs.String())
	}

	// The scans end; the person loses agent.manage: skipped, last start kept.
	e.exec(t, "UPDATE pc.saas_scan_runs SET state = 'FAILED', finished_at = now() WHERE org_id = $1", e.org)
	e.exec(t, "UPDATE pc.verifications SET state = 'EXPIRED', finished_at = now() WHERE org_id = $1", e.org)
	e.exec(t, "DELETE FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2", e.org, e.user)
	logs.Reset()
	if n, err := sched.RunOrg(ctx, e.org); err != nil || n != 0 {
		t.Fatalf("no agent.manage: %d %v", n, err)
	}
	if !strings.Contains(logs.String(), "reason=person") || !e.m34LastStarted(t, conn).Equal(*due) || e.m34Scans(t, conn, "schedule") != 1 {
		t.Fatalf("a person without agent.manage: %s", logs.String())
	}
	// A member again, but disabled: still skipped.
	e.m34Member(t, e.user)
	e.exec(t, "UPDATE pc.users SET state = 'DISABLED' WHERE org_id = $1 AND id = $2", e.org, e.user)
	logs.Reset()
	if n, err := sched.RunOrg(ctx, e.org); err != nil || n != 0 || !strings.Contains(logs.String(), "reason=person") {
		t.Fatalf("a disabled person: %d %v %s", n, err, logs.String())
	}
	// Active again: both start.
	e.exec(t, "UPDATE pc.users SET state = 'ACTIVE' WHERE org_id = $1 AND id = $2", e.org, e.user)
	if n, err := sched.RunOrg(ctx, e.org); err != nil || n != 2 {
		t.Fatalf("active again: %d %v", n, err)
	}
	if at := e.m34LastStarted(t, conn); at == nil || !at.After(*due) {
		t.Errorf("last_started_at %v, was %v", at, due)
	}
}

// TestT347_ARuntimeAgentFoundIsTheDeployedAgentAlertsInput: an AgentCore
// runtime a scheduled scan finds is recorded as a discovered external agent,
// and its audit.agent.discovered entry names the source aws_agentcore, which
// pc.runtime.agent_deployed matches (G0 M34 D997, HR-769); a ChatGPT
// finding's entry names its own source.
//
// Covers: F1045, HR-769, T-347
func TestT347_ARuntimeAgentFoundIsTheDeployedAgentAlertsInput(t *testing.T) {
	e := newEnv(t)
	e.m34Member(t, e.user)
	conn, gateway := e.m34Collector(t, domain.SourceAWSAgentCore)
	if _, err := e.svc.SetSchedule(e.admin, domain.SourceAWSAgentCore, conn, m34Account, true); err != nil {
		t.Fatal(err)
	}
	sched := &app.Scheduler{Pool: e.pool, Editions: edition(billing.Business)}
	if n, err := sched.RunOrg(context.Background(), e.org); err != nil || n != 1 {
		t.Fatalf("run: %d %v", n, err)
	}
	store := &pgtransactions.Store{Pool: e.pool}
	leases, err := store.Claim(context.Background(), e.org, gateway, 4, 30*time.Second)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases %+v %v", leases, err)
	}
	var scan ids.UUID
	e.d.AdminQueryRow(t, "SELECT id FROM pc.saas_scan_runs WHERE org_id = $1 AND connection_id = $2", []any{e.org, conn}, &scan)
	f := aapp.ScanFinding{
		Kind: domain.KindAgentCoreRuntime, Key: domain.Key(domain.SourceAWSAgentCore, m34Account, "orders_agent-AbC123"),
		Attributes: map[string]string{
			"tenant": m34Account, "agent_id": "orders_agent-AbC123", "name": "orders_agent", "region": "us-east-1", "status": "READY",
		},
	}
	res, err := e.inv.SubmitSaaSScan(context.Background(), e.org, gateway, scan, leases[0].Secret, []aapp.ScanFinding{f})
	if err != nil || res.Created != 1 {
		t.Fatalf("submit %+v %v", res, err)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agent.discovered'
		AND convert_from(body, 'UTF8') LIKE '%"source":"aws_agentcore"%'`, e.org); n != 1 {
		t.Fatalf("%d agent.discovered entries naming aws_agentcore", n)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore' AND state = 'OPEN'`, e.org); n != 1 {
		t.Fatalf("%d open AgentCore discoveries", n)
	}
	if _, _, err := e.svc.Import(e.admin, report(finding("g-other", nil))); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agent.discovered'
		AND convert_from(body, 'UTF8') LIKE '%"source":"aws_agentcore"%'`, e.org); n != 1 {
		t.Fatalf("a ChatGPT finding named aws_agentcore: %d", n)
	}
}

// TestT349_AScheduledScanWithAStaleCredentialSaysWhatItDidNotRead: the
// daily scan of a connection whose collector credential the provider
// refuses finishes with the runtimes read not scanned, with the gateway's
// fixed reason, and never as "none found": an agent recorded before is not
// counted missed. The schedule's start is still recorded, so the next daily
// scan tries again after 20 hours (G0 M34 D997, HR-637, HR-768).
//
// Covers: F1046, HR-768, T-349
func TestT349_AScheduledScanWithAStaleCredentialSaysWhatItDidNotRead(t *testing.T) {
	e := newEnv(t)
	e.m34Member(t, e.user)
	conn, gateway := e.m34Collector(t, domain.SourceAWSAgentCore)
	if _, err := e.svc.SetSchedule(e.admin, domain.SourceAWSAgentCore, conn, m34Account, true); err != nil {
		t.Fatal(err)
	}
	sched := &app.Scheduler{Pool: e.pool, Editions: edition(billing.Business)}
	store := &pgtransactions.Store{Pool: e.pool}
	run := func(fields map[string]string, findings ...aapp.ScanFinding) ids.UUID {
		t.Helper()
		e.exec(t, "UPDATE pc.saas_scan_schedules SET last_started_at = now() - interval '21 hours' WHERE org_id = $1 AND last_started_at IS NOT NULL", e.org)
		if n, err := sched.RunOrg(context.Background(), e.org); err != nil || n != 1 {
			t.Fatalf("run: %d %v", n, err)
		}
		leases, err := store.Claim(context.Background(), e.org, gateway, 4, 30*time.Second)
		if err != nil || len(leases) != 1 {
			t.Fatalf("leases %+v %v", leases, err)
		}
		var scan ids.UUID
		e.d.AdminQueryRow(t, "SELECT id FROM pc.saas_scan_runs WHERE org_id = $1 AND verification_id = $2", []any{e.org, leases[0].Task}, &scan)
		if _, err := e.inv.SubmitSaaSScan(context.Background(), e.org, gateway, scan, leases[0].Secret, findings); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Report(context.Background(), e.org, gateway, tapp.Report{
			Task: leases[0].Task, Secret: leases[0].Secret, HTTPStatus: 200, Found: true, Complete: true, Fields: fields,
		}, nil); err != nil {
			t.Fatal(err)
		}
		return scan
	}
	f := aapp.ScanFinding{
		Kind: domain.KindAgentCoreRuntime, Key: domain.Key(domain.SourceAWSAgentCore, m34Account, "orders-1"),
		Attributes: map[string]string{"tenant": m34Account, "agent_id": "orders-1", "name": "orders", "region": "us-east-1", "status": "READY"},
	}
	run(map[string]string{"/scanned/runtimes": "true", "/counts/agents": "1"}, f)
	before := e.m34LastStarted(t, conn)

	why := "the connection may not read it (HTTP 403)"
	scan := run(map[string]string{"/not_scanned/runtimes": why})
	got, err := e.svc.Get(e.admin, scan)
	if err != nil || got.State != "DONE" || got.NotScanned[domain.ReadRuntimes] != why {
		t.Fatalf("the stale credential's scan: %+v %v", got, err)
	}
	var missed int
	e.d.AdminQueryRow(t, "SELECT missed_scans FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore'", []any{e.org}, &missed)
	if missed != 0 {
		t.Errorf("an unread run counted %d misses", missed)
	}
	if at := e.m34LastStarted(t, conn); at == nil || !at.After(*before) {
		t.Errorf("last_started_at %v, was %v", at, before)
	}
}
