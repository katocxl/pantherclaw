// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordExceptions struct {
	pantherclawv1connect.UnimplementedPolicyExceptionServiceHandler
	request *pantherclawv1.RequestPolicyExceptionRequest
	list    *pantherclawv1.ListPolicyExceptionsRequest
	revoke  *pantherclawv1.RevokePolicyExceptionRequest
}

func (r *recordExceptions) RequestPolicyException(_ context.Context, req *pantherclawv1.RequestPolicyExceptionRequest) (
	*pantherclawv1.RequestPolicyExceptionResponse, error,
) {
	r.request = req
	return &pantherclawv1.RequestPolicyExceptionResponse{
		Exception: &pantherclawv1.PolicyException{Id: "x1", State: "PENDING"}, ChangeRequestId: "c1", ChangeRequestUrl: "https://pc.test/policy-changes/c1",
	}, nil
}

func (r *recordExceptions) ListPolicyExceptions(_ context.Context, req *pantherclawv1.ListPolicyExceptionsRequest) (
	*pantherclawv1.ListPolicyExceptionsResponse, error,
) {
	r.list = req
	return &pantherclawv1.ListPolicyExceptionsResponse{}, nil
}

func (r *recordExceptions) RevokePolicyException(_ context.Context, req *pantherclawv1.RevokePolicyExceptionRequest) (
	*pantherclawv1.RevokePolicyExceptionResponse, error,
) {
	r.revoke = req
	return &pantherclawv1.RevokePolicyExceptionResponse{}, nil
}

// TestPolicyExceptionCommands: pclaw policy exception request, list and
// revoke send what was asked; a request without its reason or beyond 30
// days, or a revocation without a reason, is never sent.
func TestPolicyExceptionCommands(t *testing.T) {
	rx := &recordExceptions{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterPolicyExceptionServiceHandler(cs, rx)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const agent = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	for name, args := range map[string][]string{
		"no reason": {"policy", "exception", "request", "hold-large", "--agent", agent, "--operation", "payments.refund.create", "--expires-in", "24h"},
		"31 days": {"policy", "exception", "request", "hold-large", "--agent", agent, "--operation", "payments.refund.create",
			"--reason", "backlog", "--expires-in", "744h"},
		"no verb":      {"policy", "exception"},
		"unknown verb": {"policy", "exception", "extend", "x1"},
	} {
		if code, _, _ := run(t, env, args...); code == 0 || rx.request != nil {
			t.Fatalf("%s: sent", name)
		}
	}
	code, out, errs := run(t, env, "policy", "exception", "request", "hold-large", "--agent", agent, "--operation", "payments.refund.create",
		"--operation", "payments.refund.cancel", "--reason", "Quarter-end backlog.", "--expires-in", "72h")
	if code != 0 || rx.request.GetRuleId() != "hold-large" || len(rx.request.GetOperations()) != 2 ||
		rx.request.GetExpiresInSeconds() != 72*3600 || rx.request.OwnerId != nil || !strings.Contains(out, `"PENDING"`) ||
		!strings.Contains(errs, "Waiting for confirmation") {
		t.Fatalf("request: %d %s %s %+v", code, out, errs, rx.request)
	}
	if code, _, errs := run(t, env, "policy", "exception", "list", "--state", "active", "--agent", agent); code != 0 ||
		rx.list.GetState() != "ACTIVE" || rx.list.GetAgentId() != agent {
		t.Fatalf("list: %d %s %+v", code, errs, rx.list)
	}
	if code, _, _ := run(t, env, "policy", "exception", "revoke", "x1"); code == 0 || rx.revoke != nil {
		t.Fatal("a revocation without a reason was sent")
	}
	if code, _, errs := run(t, env, "policy", "exception", "revoke", "x1", "--reason", "Cleared."); code != 0 || rx.revoke.GetId() != "x1" {
		t.Fatalf("revoke: %d %s", code, errs)
	}
}
