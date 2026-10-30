// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func (e *env) httpConnection(t *testing.T, gw ids.UUID) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	e.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
		VALUES ($1, $2, $3, 'http', $4, 'pc.mock-payments', 'https://payments.example.test', 'none', 'test', 'test')`,
		e.org, id, "c-"+id.String()[28:], gw)
	return id
}

// at returns the gateway use cases on a fake clock.
func (e *env) at(now time.Time) (*app.Service, *clock.Fake) {
	clk := clock.NewFake(now)
	return app.New(e.pool, nil, "", clk), clk
}

// TestHR410_AStatusReportCountsOnlyForItsOwnGateway: a replica's report is
// recorded for the gateway of its certificate alone, with only the
// connections that gateway serves; the gateway is connected while a
// replica reported in the last 90 seconds, and a replica silent for a day
// is pruned. A revoked gateway's report is refused (G0 M15 D10, D11).
// Covers: PN-010.6
func TestHR410_AStatusReportCountsOnlyForItsOwnGateway(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, a := e.enroll(t, "a")
	_, b := e.enroll(t, "b")
	own, other := e.httpConnection(t, a.Gateway), e.httpConnection(t, b.Gateway)
	svc, clk := e.at(time.Now())
	ctx := context.Background()
	start := clk.Now().Add(-time.Minute)
	if err := svc.ReportStatus(ctx, a, app.ReplicaStatus{
		Replica: "AAAAAAAAAAAAAAAAAAAAAA", Version: "1.5.0", Build: "abc", StartTime: &start, ConfigVersion: 3,
		Connections: []app.ConnectionStatus{{Connection: own, State: "SERVING"}, {Connection: other, State: "SERVING"}},
	}); err != nil {
		t.Fatal(err)
	}
	d, err := svc.GetGateway(e.admin, a.Gateway)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Status.Connected || len(d.Status.Replicas) != 1 || d.Status.Replicas[0].ConfigVersion != 3 {
		t.Fatalf("status %+v", d.Status)
	}
	if cs := app.ReplicaConnections(d.Status.Replicas[0]); len(cs) != 1 || cs[0].Connection != own {
		t.Fatalf("another gateway's connection was kept: %+v", cs)
	}
	if d, err := svc.GetGateway(e.admin, b.Gateway); err != nil || d.Status.Connected || len(d.Status.Replicas) != 0 {
		t.Fatalf("gateway b got a's report: %+v %v", d.Status, err)
	}
	clk.Advance(app.ConnectedWithin)
	if _, st, _, err := svc.ListGateways(e.admin, 10, "", false); err != nil || st[a.Gateway].Connected || len(st[a.Gateway].Replicas) != 1 {
		t.Fatalf("after 90 s: %+v %v", st[a.Gateway], err)
	}
	clk.Advance(app.ReplicaRetention)
	if n, err := svc.PruneReplicas(ctx, e.org); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, err := e.svc.RevokeGateway(e.admin, b.Gateway, "test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReportStatus(ctx, b, app.ReplicaStatus{Replica: "BBBBBBBBBBBBBBBBBBBBBB"}); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a revoked gateway's report: %v", err)
	}
}

func stateKey(s string) []byte { k := sha256.Sum256([]byte(s)); return k[:] }

// TestHR411_MCPStateIsPerGatewayAndStoredSealed: an entry belongs to the
// gateway that wrote it: another gateway of the org neither reads nor
// deletes it, and the task body comes back byte for byte as the gateway
// sealed it (the server never opens it).
func TestHR411_MCPStateIsPerGatewayAndStoredSealed(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, a := e.enroll(t, "a")
	_, b := e.enroll(t, "b")
	conn := e.httpConnection(t, a.Gateway)
	svc, clk := e.at(time.Now())
	ctx := context.Background()
	run, inst := ids.NewV7(), ids.NewV7()
	body := bytes.Repeat([]byte{0xA5}, 4096)
	task := app.MCPEntry{
		Kind: app.MCPTask, Key: stateKey("task"), Connection: conn, Run: &run, Instance: &inst, ActionID: ids.NewV7().String(),
		Status: "working", SealedBody: body, ExpireTime: clk.Now().Add(time.Hour),
	}
	if v, err := svc.PutMCPState(ctx, a, task, 0); err != nil || v != 1 {
		t.Fatalf("put: %d %v", v, err)
	}
	if _, err := svc.GetMCPState(ctx, b, app.MCPTask, task.Key); !errors.Is(err, app.ErrMCPStateNotFound) {
		t.Fatalf("another gateway read the task: %v", err)
	}
	if ok, err := svc.DeleteMCPState(ctx, b, app.MCPTask, task.Key, 0); err != nil || ok {
		t.Fatalf("another gateway deleted the task: %v %v", ok, err)
	}
	if _, err := svc.GetMCPState(ctx, a, app.MCPHold, task.Key); !errors.Is(err, app.ErrMCPStateNotFound) {
		t.Fatalf("a task read as a hold: %v", err)
	}
	got, err := svc.GetMCPState(ctx, a, app.MCPTask, task.Key)
	if err != nil || !bytes.Equal(got.SealedBody, body) || got.ConnectionID != conn || *got.RunID != run || *got.InstanceID != inst {
		t.Fatalf("get: %+v %v", got, err)
	}
	// A hold or session carries no body, a session no action.
	bad := []app.MCPEntry{
		{Kind: app.MCPHold, Key: stateKey("h"), Connection: conn, ActionID: "x", SealedBody: body, ExpireTime: clk.Now().Add(time.Hour)},
		{Kind: app.MCPSession, Key: stateKey("s"), Connection: conn, ActionID: "x", ExpireTime: clk.Now().Add(time.Hour)},
		{Kind: app.MCPSession, Key: []byte("short"), Connection: conn, ExpireTime: clk.Now().Add(time.Hour)},
		{Kind: app.MCPHold, Key: stateKey("h"), Connection: conn, ActionID: "x", ExpireTime: clk.Now().Add(24 * time.Hour)},
	}
	for i, en := range bad {
		if _, err := svc.PutMCPState(ctx, a, en, 0); !errors.Is(err, app.ErrMCPStateInvalid) {
			t.Fatalf("bad entry %d: %v", i, err)
		}
	}
}

// TestHR412_MCPStateConflictsAndBoundsOnlyCostANewAction: writes are
// compare-and-set; past the bounds a new hold or task is refused; an
// expired entry is not found, can be written again and is purged.
func TestHR412_MCPStateConflictsAndBoundsOnlyCostANewAction(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, a := e.enroll(t, "a")
	conn := e.httpConnection(t, a.Gateway)
	svc, clk := e.at(time.Now())
	ctx := context.Background()
	run, inst := ids.NewV7(), ids.NewV7()
	hold := func(name string, ttl time.Duration) app.MCPEntry {
		return app.MCPEntry{
			Kind: app.MCPHold, Key: stateKey(name), Connection: conn, Run: &run, Instance: &inst,
			ActionID: ids.NewV7().String(), ExpireTime: clk.Now().Add(ttl),
		}
	}
	h := hold("h0", time.Hour)
	if _, err := svc.PutMCPState(ctx, a, h, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutMCPState(ctx, a, h, 0); !errors.Is(err, app.ErrMCPStateConflict) {
		t.Fatalf("created twice: %v", err)
	}
	if _, err := svc.PutMCPState(ctx, a, h, 7); !errors.Is(err, app.ErrMCPStateConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if v, err := svc.PutMCPState(ctx, a, h, 1); err != nil || v != 2 {
		t.Fatalf("update: %d %v", v, err)
	}
	if _, err := svc.DeleteMCPState(ctx, a, app.MCPHold, h.Key, 1); !errors.Is(err, app.ErrMCPStateConflict) {
		t.Fatalf("delete of a stale version: %v", err)
	}
	for i := 1; i < app.MaxMCPEntriesPerInstance; i++ {
		if _, err := svc.PutMCPState(ctx, a, hold(fmt.Sprint("h", i), time.Hour), 0); err != nil {
			t.Fatalf("hold %d: %v", i, err)
		}
	}
	if _, err := svc.PutMCPState(ctx, a, hold("one-too-many", time.Hour), 0); !errors.Is(err, app.ErrMCPStateFull) {
		t.Fatalf("past the instance bound: %v", err)
	}
	if ok, err := svc.DeleteMCPState(ctx, a, app.MCPHold, stateKey("h1"), 0); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	short := hold("short", time.Minute)
	if _, err := svc.PutMCPState(ctx, a, short, 0); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	if _, err := svc.GetMCPState(ctx, a, app.MCPHold, short.Key); !errors.Is(err, app.ErrMCPStateNotFound) {
		t.Fatalf("an expired hold was found: %v", err)
	}
	if ok, err := svc.DeleteMCPState(ctx, a, app.MCPHold, stateKey("missing"), 3); err != nil || ok {
		t.Fatalf("delete of a missing entry: %v %v", ok, err)
	}
	if n, err := svc.PurgeMCPState(ctx, e.org); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	short.ExpireTime = clk.Now().Add(time.Minute)
	if v, err := svc.PutMCPState(ctx, a, short, 0); err != nil || v != 1 {
		t.Fatalf("an expired key written again: %d %v", v, err)
	}
	// A task's body counts toward the gateway's bytes.
	big := app.MCPEntry{
		Kind: app.MCPTask, Key: stateKey("big"), Connection: conn, Instance: &inst, ActionID: "a", Status: "working",
		SealedBody: make([]byte, 1), ExpireTime: clk.Now().Add(time.Hour),
	}
	if _, err := svc.PutMCPState(ctx, a, big, 0); !errors.Is(err, app.ErrMCPStateFull) {
		t.Fatalf("a task past the instance bound: %v", err)
	}
	// So does a relayed elicitation (D39), which may carry a sealed body.
	el := app.MCPEntry{
		Kind: app.MCPElicitation, Key: stateKey("el"), Connection: conn, Instance: &inst, SealedBody: []byte{1},
		ExpireTime: clk.Now().Add(10 * time.Minute),
	}
	if _, err := svc.PutMCPState(ctx, a, el, 0); !errors.Is(err, app.ErrMCPStateFull) {
		t.Fatalf("an elicitation past the instance bound: %v", err)
	}
	other := ids.NewV7()
	el.Instance = &other
	if _, err := svc.PutMCPState(ctx, a, el, 0); err != nil {
		t.Fatalf("an elicitation of another instance: %v", err)
	}
	if got, err := svc.GetMCPState(ctx, a, app.MCPElicitation, el.Key); err != nil || !bytes.Equal(got.SealedBody, el.SealedBody) {
		t.Fatalf("elicitation: %+v %v", got, err)
	}
}

// TestHR413_SessionsStayBoundAndAnInstanceKeepsSixteen: a session entry
// keeps its connection, instance, key thumbprint and run; an instance's
// seventeenth session ends its least recently updated one.
func TestHR413_SessionsStayBoundAndAnInstanceKeepsSixteen(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, a := e.enroll(t, "a")
	conn := e.httpConnection(t, a.Gateway)
	svc, clk := e.at(time.Now())
	ctx := context.Background()
	run, inst := ids.NewV7(), ids.NewV7()
	sess := func(i int) app.MCPEntry {
		return app.MCPEntry{
			Kind: app.MCPSession, Key: stateKey(fmt.Sprint("session", i)), Connection: conn, Run: &run, Instance: &inst,
			JKT: "thumbprint", ExpireTime: clk.Now().Add(8 * time.Hour),
		}
	}
	for i := range app.MaxMCPSessionsPerInstance {
		if _, err := svc.PutMCPState(ctx, a, sess(i), 0); err != nil {
			t.Fatal(err)
		}
		clk.Advance(time.Second)
	}
	// session0 is touched; session1 is now the least recently updated.
	if _, err := svc.PutMCPState(ctx, a, sess(0), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutMCPState(ctx, a, sess(99), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetMCPState(ctx, a, app.MCPSession, sess(1).Key); !errors.Is(err, app.ErrMCPStateNotFound) {
		t.Fatalf("the least recently updated session stayed: %v", err)
	}
	got, err := svc.GetMCPState(ctx, a, app.MCPSession, sess(0).Key)
	if err != nil || got.Jkt == nil || *got.Jkt != "thumbprint" || *got.RunID != run || *got.InstanceID != inst || got.ConnectionID != conn {
		t.Fatalf("session: %+v %v", got, err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.gateway_mcp_state WHERE org_id = $1 AND kind = 'SESSION'", e.org); n != app.MaxMCPSessionsPerInstance {
		t.Fatalf("%d sessions", n)
	}
}

// TestT182_TheServerKeepsEntriesBoundAndToServedConnections: a replica
// cannot rebind an entry (its connection, run, instance and key thumbprint
// never change), cannot write state for a connection its gateway does not
// serve, and cannot delete by version an entry that already expired; each
// kind keeps its own shape and lifetime (G0 M15 T-182, D42).
func TestT182_TheServerKeepsEntriesBoundAndToServedConnections(t *testing.T) {
	e := newEnv(t)
	e.pinMockPayments(t)
	_, a := e.enroll(t, "a")
	_, b := e.enroll(t, "b")
	conn, theirs := e.httpConnection(t, a.Gateway), e.httpConnection(t, b.Gateway)
	svc, clk := e.at(time.Now())
	ctx := context.Background()
	run, inst := ids.NewV7(), ids.NewV7()
	sess := app.MCPEntry{
		Kind: app.MCPSession, Key: stateKey("s"), Connection: conn, Run: &run, Instance: &inst, JKT: "jkt-1",
		ExpireTime: clk.Now().Add(8 * time.Hour),
	}
	if _, err := svc.PutMCPState(ctx, a, sess, 0); err != nil {
		t.Fatal(err)
	}
	other := ids.NewV7()
	for name, edit := range map[string]func(*app.MCPEntry){
		"run":        func(x *app.MCPEntry) { x.Run = &other },
		"instance":   func(x *app.MCPEntry) { x.Instance = &other },
		"thumbprint": func(x *app.MCPEntry) { x.JKT = "jkt-2" },
		"connection": func(x *app.MCPEntry) { x.Connection = e.httpConnection(t, a.Gateway) },
	} {
		rebound := sess
		edit(&rebound)
		if _, err := svc.PutMCPState(ctx, a, rebound, 1); !errors.Is(err, app.ErrMCPStateConflict) {
			t.Errorf("a session rebound to another %s: %v", name, err)
		}
	}
	if got, err := svc.GetMCPState(ctx, a, app.MCPSession, sess.Key); err != nil || *got.RunID != run || *got.Jkt != "jkt-1" || got.Version != 1 {
		t.Fatalf("after the refused rebinding: %+v %v", got, err)
	}
	unserved := sess
	unserved.Key, unserved.Connection = stateKey("unserved"), theirs
	// NotFound, as ReportDrift answers, so connections cannot be probed (D43).
	if _, err := svc.PutMCPState(ctx, a, unserved, 0); !errors.Is(err, app.ErrMCPStateConnection) || pcerr.CodeOf(err) != pcerr.NotFound {
		t.Fatalf("state for another gateway's connection: %v", err)
	}
	unserved.Connection = ids.NewV7()
	if _, err := svc.PutMCPState(ctx, a, unserved, 0); !errors.Is(err, app.ErrMCPStateConnection) {
		t.Fatalf("state for an unknown connection: %v", err)
	}
	hold := app.MCPEntry{
		Kind: app.MCPHold, Key: stateKey("h"), Connection: conn, Run: &run, Instance: &inst, ActionID: "act",
		ExpireTime: clk.Now().Add(time.Minute),
	}
	if _, err := svc.PutMCPState(ctx, a, hold, 0); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	if ok, err := svc.DeleteMCPState(ctx, a, app.MCPHold, hold.Key, 1); ok || err != nil {
		t.Fatalf("a versioned delete of an expired entry: %v %v", ok, err)
	}
	// Shapes and lifetimes per kind.
	for name, en := range map[string]app.MCPEntry{
		"a hold past an hour": {
			Kind: app.MCPHold, Key: stateKey("h2"), Connection: conn, ActionID: "a",
			ExpireTime: clk.Now().Add(2 * time.Hour),
		},
		"a session past eight hours": {
			Kind: app.MCPSession, Key: stateKey("s2"), Connection: conn,
			ExpireTime: clk.Now().Add(9 * time.Hour),
		},
		"an elicitation past ten minutes": {
			Kind: app.MCPElicitation, Key: stateKey("e1"), Connection: conn, SealedBody: []byte{1},
			ExpireTime: clk.Now().Add(20 * time.Minute),
		},
		"an elicitation without a body": {
			Kind: app.MCPElicitation, Key: stateKey("e2"), Connection: conn,
			ExpireTime: clk.Now().Add(5 * time.Minute),
		},
		"an elicitation with a status": {
			Kind: app.MCPElicitation, Key: stateKey("e3"), Connection: conn, SealedBody: []byte{1},
			Status: "working", ExpireTime: clk.Now().Add(5 * time.Minute),
		},
		"an elicitation with an action": {
			Kind: app.MCPElicitation, Key: stateKey("e4"), Connection: conn, SealedBody: []byte{1},
			ActionID: "a", ExpireTime: clk.Now().Add(5 * time.Minute),
		},
	} {
		if _, err := svc.PutMCPState(ctx, a, en, 0); !errors.Is(err, app.ErrMCPStateInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The database refuses the same shapes from pc_app directly.
	for name, sql := range map[string]string{
		"an elicitation without a body": `INSERT INTO pc.gateway_mcp_state (org_id, gateway_id, kind, key, connection_id, version, expire_time,
			update_time) VALUES ($1, $2, 'ELICITATION', $3, $4, 1, now() + interval '5 minutes', now())`,
		"a hold past an hour": `INSERT INTO pc.gateway_mcp_state (org_id, gateway_id, kind, key, connection_id, action_id, version,
			expire_time, update_time) VALUES ($1, $2, 'HOLD', $3, $4, 'a', 1, now() + interval '2 hours', now())`,
	} {
		err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, e.org, a.Gateway, stateKey(name), conn)
			return err
		})
		if !db.IsCheckViolation(err) {
			t.Errorf("%s inserted directly: %v", name, err)
		}
	}
	err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.gateway_mcp_state SET run_id = $1", other)
		return err
	})
	if err == nil {
		t.Fatal("pc_app rebound an entry directly")
	}
}
