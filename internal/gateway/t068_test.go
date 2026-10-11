// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	otherConnID = "01920000-0000-7000-8000-0000000000d2"
	otherPath   = "/mcp/other"
)

// otherConnection is a second connection on the harness's gateway: "other",
// serving pc.other-payments, a package with the same tool names as
// mock-payments and its own description, with its own target.
type otherConnection struct {
	conn   *control.Connection
	target *fakeTarget
}

func addOtherConnection(t *testing.T, h *harness) otherConnection {
	t.Helper()
	target := &fakeTarget{status: http.StatusOK}
	ts := httptest.NewServer(target)
	t.Cleanup(ts.Close)
	c, err := compile(t, "", func(raw []byte) []byte {
		raw = bytes.Replace(raw, []byte("name: pc.mock-payments"), []byte("name: pc.other-payments"), 1)
		return bytes.Replace(raw, []byte("Every refund is SIMULATED."), []byte("Every refund goes to the OTHER ledger."), 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	c.GatewayConnection = &pb.GatewayConnection{
		Id: otherConnID, Name: "other", Kind: "http", Package: "pc.other-payments", PackageVersion: "1.0.0", BaseUrl: ts.URL,
		AllowedHosts: []string{"127.0.0.1"}, DestinationClass: "internal", AccessMode: "none", DefaultMode: "enforce",
		MaxResponseBytes: 1 << 20, TimeoutMs: 500, State: "ACTIVE", Revision: 1,
	}
	c.Modes = map[string]string{}
	cfg := h.gw.config.(*fakeConfig).cfg
	cfg.ByName["other"], cfg.ByID[otherConnID] = c, c
	return otherConnection{conn: c, target: target}
}

// TestT068_OneConnectionsSessionsAndTasksAreNotFoundThroughAnother: one
// gateway serves two connections whose packages have the same tool names
// (T-068). The same workload, with the same key and in the same run,
// takes what belongs to its call on one connection to the other: a
// 2025-11-25 session id is "session not found", and polling, updating or
// canceling a held call's task is "task not found", before any Authority
// call. The identical call on the other connection is another action and
// never reuses the held one. The task stays its own connection's: once
// approved, its poll runs the refund there and nowhere else.
func TestT068_OneConnectionsSessionsAndTasksAreNotFoundThroughAnother(t *testing.T) {
	h := setup(t, func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL })
	other := addOtherConnection(t, h)
	run := ids.NewV7().String()

	sid := h.openSession(t, run)
	same := map[string]string{HeaderRunID: run}
	r := h.mcpCall(t, http.MethodPost, mcpPath, withTasks(jsonRPC("tools/call", refundArgs)), same)
	task := r.body.Result.TaskID
	if r.code != http.StatusOK || r.body.Result.ResultType != "task" || task == "" {
		t.Fatalf("the held call on payments: %d %+v %+v", r.code, r.body.Error, r.body.Result)
	}
	held := h.auth.snap().actions[len(h.auth.snap().actions)-1].Action.ActionID
	verified, _ := h.auth.verifyCount()
	authorized := h.auth.snap().authorize

	legacy := map[string]string{"MCP-Protocol-Version": "2025-11-25", "Mcp-Session-Id": sid, HeaderRunID: run}
	for _, body := range []string{legacyRPC("tools/list", ""), legacyRPC("tools/call", refundArgs)} {
		if r := h.mcpCall(t, http.MethodPost, otherPath, body, legacy); r.code != http.StatusNotFound {
			t.Errorf("payments' session on other: %d %+v %+v", r.code, r.body.Error, r.body.Result)
		}
	}
	if n, _ := h.auth.verifyCount(); n != verified || h.auth.snap().authorize != authorized {
		t.Fatal("a session used on another connection reached the Authority")
	}
	for _, m := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
		if r := h.mcpCall(t, http.MethodPost, otherPath, taskBody(m, task), same); r.code != http.StatusOK || r.errCode() != -32602 {
			t.Errorf("%s of payments' task on other: %d %+v %+v", m, r.code, r.body.Error, r.body.Result)
		}
	}
	if h.auth.snap().authorize != authorized {
		t.Fatal("a task request on another connection resubmitted the held action")
	}

	if r := h.mcpCall(t, http.MethodPost, otherPath, jsonRPC("tools/call", refundArgs), same); !r.body.Result.IsError {
		t.Fatalf("the identical call on other: %+v", r.body.Result)
	}
	a := h.auth.snap().actions[len(h.auth.snap().actions)-1].Action
	if a.ActionID == held || a.Connection != otherConnID || a.Definition.Package != "pc.other-payments" {
		t.Fatalf("the identical call on other became %+v (held %s)", a, held)
	}

	h.auth.decide(pb.Decision_DECISION_ALLOW)
	r = h.mcpCall(t, http.MethodPost, mcpPath, taskBody("tasks/get", task), same)
	if r.body.Result.Status != "completed" || h.target.calls() != 1 || other.target.calls() != 0 {
		t.Fatalf("the approved task on payments: %+v, payments' target %d, other's %d", r.body.Result, h.target.calls(), other.target.calls())
	}
	if a := h.auth.snap().actions[len(h.auth.snap().actions)-1].Action; a.ActionID != held || a.Connection != connID {
		t.Fatalf("the task resubmitted %+v", a)
	}
}

// TestT068_ToolsOfOneConnectionNeverShadowAnothers: two connections offer
// tools with the same names (T-068). Each connection's tools/list is its
// own reviewed package's, with that package's descriptions, and is never
// stored by a shared cache; a call to the shared name is mapped through
// the connection it was sent to, so its decision names that connection and
// package, and it reaches only that connection's target.
func TestT068_ToolsOfOneConnectionNeverShadowAnothers(t *testing.T) {
	h := setup(t)
	other := addOtherConnection(t, h)
	for path, tc := range map[string]struct{ own, foreign string }{
		mcpPath:   {"Every refund is SIMULATED.", "OTHER ledger"},
		otherPath: {"Every refund goes to the OTHER ledger.", "Every refund is SIMULATED."},
	} {
		r := h.mcpCall(t, http.MethodPost, path, jsonRPC("tools/list", ""), nil)
		if r.code != http.StatusOK || r.hdr.Get("Cache-Control") != "private, no-store" || r.body.Result.CacheScope != "private" ||
			len(r.body.Result.Tools) != 2 || r.body.Result.Tools[0].Name != "create_refund" {
			t.Fatalf("%s tools/list: %d %+v %v", path, r.code, r.body.Result, r.hdr)
		}
		if d := r.body.Result.Tools[0].Description; !strings.Contains(d, tc.own) || strings.Contains(d, tc.foreign) {
			t.Errorf("%s serves create_refund as %q", path, d)
		}
	}

	for _, tc := range []struct {
		path, conn, pkg string
		target          *fakeTarget
	}{
		{otherPath, otherConnID, "pc.other-payments", other.target},
		{mcpPath, connID, "pc.mock-payments", h.target},
	} {
		r := h.mcpCall(t, http.MethodPost, tc.path, jsonRPC("tools/call", refundArgs), nil)
		if r.code != http.StatusOK || r.body.Result.IsError {
			t.Fatalf("create_refund on %s: %d %+v %+v", tc.path, r.code, r.body.Error, r.body.Result)
		}
		a := h.auth.snap().actions[len(h.auth.snap().actions)-1].Action
		if a.Connection != tc.conn || a.Definition.Package != tc.pkg || tc.target.calls() != 1 {
			t.Fatalf("create_refund on %s: mapped %+v, its target got %d", tc.path, a, tc.target.calls())
		}
	}
	if h.target.calls() != 1 || other.target.calls() != 1 {
		t.Fatalf("targets: payments %d, other %d", h.target.calls(), other.target.calls())
	}
}
