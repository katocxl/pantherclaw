// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordGateways struct {
	pantherclawv1connect.UnimplementedGatewayAdminServiceHandler
	list   *pantherclawv1.ListGatewaysRequest
	revoke *pantherclawv1.RevokeGatewayRequest
}

func (r *recordGateways) ListGateways(_ context.Context, req *pantherclawv1.ListGatewaysRequest) (*pantherclawv1.ListGatewaysResponse, error) {
	r.list = req
	return &pantherclawv1.ListGatewaysResponse{}, nil
}

func (r *recordGateways) RevokeGateway(_ context.Context, req *pantherclawv1.RevokeGatewayRequest) (*pantherclawv1.RevokeGatewayResponse, error) {
	r.revoke = req
	return &pantherclawv1.RevokeGatewayResponse{}, nil
}

type recordConnections struct {
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	create *pantherclawv1.CreateConnectionRequest
	update *pantherclawv1.UpdateConnectionRequest
	mode   *pantherclawv1.SetRouteModeRequest
}

func (r *recordConnections) CreateConnection(_ context.Context, req *pantherclawv1.CreateConnectionRequest) (*pantherclawv1.CreateConnectionResponse, error) {
	r.create = req
	return &pantherclawv1.CreateConnectionResponse{}, nil
}

func (r *recordConnections) UpdateConnection(_ context.Context, req *pantherclawv1.UpdateConnectionRequest) (*pantherclawv1.UpdateConnectionResponse, error) {
	r.update = req
	return &pantherclawv1.UpdateConnectionResponse{}, nil
}

func (r *recordConnections) SetRouteMode(_ context.Context, req *pantherclawv1.SetRouteModeRequest) (*pantherclawv1.SetRouteModeResponse, error) {
	r.mode = req
	return &pantherclawv1.SetRouteModeResponse{}, nil
}

func TestM6ConnectionCommands(t *testing.T) {
	rc := &recordConnections{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, rc)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	code, _, errs := run(t, env, "connection", "create", "payments", "--kind", "http", "--gateway", "0192aaaa-bbbb-7ccc-8ddd-000000000001",
		"--package", "pc.mock-payments", "--base-url", "https://payments.example.test", "--allowed-host", "a.test", "--allowed-host", "b.test",
		"--access", "pantherclaw_held", "--header", "Authorization", "--scheme", "Bearer", "--default-mode", "enforce")
	c := rc.create
	if code != 0 || c.GetName() != "payments" || c.GetKind() != pantherclawv1.ConnectionKind_CONNECTION_KIND_HTTP ||
		len(c.GetAllowedHosts()) != 2 || c.GetAccessMode() != pantherclawv1.AccessMode_ACCESS_MODE_PANTHERCLAW_HELD ||
		c.GetDefaultMode() != pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE || c.GetDestinationClass() != pantherclawv1.DestinationClass_DESTINATION_CLASS_UNSPECIFIED {
		t.Fatalf("connection create = %d %q, request %v", code, errs, c)
	}
	if c.GetModelRelay() || c.GetSimulated() {
		t.Fatalf("a plain connection asked for a model relay: %v", c)
	}
	// A campaign's model relay (G0 M25 D313).
	code, _, errs = run(t, env, "connection", "create", "relay", "--kind", "http", "--gateway", "0192aaaa-bbbb-7ccc-8ddd-000000000001",
		"--package", "model-relay", "--base-url", "http://127.0.0.1:9911", "--access", "none", "--simulated", "--model-relay")
	if c = rc.create; code != 0 || !c.GetModelRelay() || !c.GetSimulated() {
		t.Fatalf("model relay create = %d %q, request %v", code, errs, c)
	}
	if code, _, errs := run(t, env, "connection", "create", "x", "--kind", "ftp"); code == 0 || !strings.Contains(errs, "--kind") {
		t.Fatalf("bad kind = %d %q", code, errs)
	}
	if code, _, errs := run(t, env, "connection", "update", "0192aaaa-bbbb-7ccc-8ddd-000000000002", "--revision", "3", "--clear-allowed-hosts",
		"--default-mode", "monitor", "--timeout-ms", "2500"); code != 0 || rc.update.GetRevision() != 3 || !rc.update.GetUpdateAllowedHosts() ||
		len(rc.update.GetAllowedHosts()) != 0 || rc.update.GetDefaultMode() != pantherclawv1.RouteMode_ROUTE_MODE_MONITOR ||
		rc.update.GetTimeoutMs() != 2500 || rc.update.BaseUrl != nil || rc.update.AccessMode != nil {
		t.Fatalf("connection update = %d %q, request %v", code, errs, rc.update)
	}
	if code, _, _ := run(t, env, "connection", "set-mode", "0192aaaa-bbbb-7ccc-8ddd-000000000002", "payments-refund", "enforce"); code != 0 ||
		rc.mode.GetRoute() != "payments-refund" || rc.mode.GetMode() != pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE {
		t.Fatalf("connection set-mode = %d, request %v", code, rc.mode)
	}
	if code, _, _ := run(t, env, "connection", "set-mode", "0192aaaa-bbbb-7ccc-8ddd-000000000002", "payments-refund", "observe"); code == 0 {
		t.Fatal("an unknown mode was sent")
	}
}

type fixedKillSwitch struct {
	pantherclawv1connect.UnimplementedContainmentServiceHandler
}

func (fixedKillSwitch) GetKillSwitch(context.Context, *pantherclawv1.GetKillSwitchRequest) (*pantherclawv1.GetKillSwitchResponse, error) {
	return &pantherclawv1.GetKillSwitchResponse{
		Engaged: true, Epoch: 7, EngagedBy: "user:0192aaaa-bbbb-7ccc-8ddd-000000000001", EngageTime: timestamppb.Now(),
		PageUrl: "https://pc.example/containment?org=0192aaaa-bbbb-7ccc-8ddd-000000000002",
	}, nil
}

func TestM6Commands(t *testing.T) {
	gw := &recordGateways{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterGatewayAdminServiceHandler(cs, gw)
	pantherclawv1connect.RegisterContainmentServiceHandler(cs, fixedKillSwitch{})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	if code, _, errs := run(t, env, "gateway", "list", "--include-revoked"); code != 0 || !gw.list.GetIncludeRevoked() {
		t.Fatalf("gateway list = %d %q, request %v", code, errs, gw.list)
	}
	if code, _, errs := run(t, env, "gateway", "revoke", "0192aaaa-bbbb-7ccc-8ddd-000000000003", "--reason", "lost host"); code != 0 ||
		gw.revoke.GetReason() != "lost host" {
		t.Fatalf("gateway revoke = %d %q, request %v", code, errs, gw.revoke)
	}
	code, out, errs := run(t, env, "killswitch", "status")
	// protojson varies its whitespace on purpose: match the field loosely.
	if code != 0 || !regexp.MustCompile(`"engaged":\s*true`).MatchString(out) ||
		!strings.Contains(errs, "emergency-stop page: https://pc.example/containment?org=0192aaaa-bbbb-7ccc-8ddd-000000000002") {
		t.Fatalf("killswitch status = %d %q %q", code, out, errs)
	}
	// There is no command that engages or restores.
	for _, verb := range []string{"engage", "restore", "on", "off"} {
		if code, _, _ := run(t, env, "killswitch", verb); code == 0 {
			t.Fatalf("killswitch %s succeeded", verb)
		}
	}
}
