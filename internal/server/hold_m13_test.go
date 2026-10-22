// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/katocxl/pantherclaw/internal/authority"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

// procedures lists every procedure of a service in a proto file.
func procedures(t *testing.T, file protoreflect.FileDescriptor, service string) []string {
	t.Helper()
	sd := file.Services().ByName(protoreflect.Name(service))
	if sd == nil {
		t.Fatalf("no service %s", service)
	}
	var out []string
	for i := range sd.Methods().Len() {
		out = append(out, "/"+string(sd.FullName())+"/"+string(sd.Methods().Get(i).Name()))
	}
	return out
}

func isHold(err error) bool {
	return errors.Is(err, authority.ErrMaintenanceHold) && pcerr.ReasonOf(err) == "MAINTENANCE_HOLD" &&
		rpc.ConnectCode(pcerr.CodeOf(err)) == connect.CodeUnavailable
}

// TestHR379_NoDecisionWhileHeld: while the maintenance hold is on, every
// decision path refuses with UNAVAILABLE MAINTENANCE_HOLD before anything
// else runs — every procedure of the gateway listener (Authorize,
// dispatch, the containment stream and the rest, so the gateway's hook,
// SDK and MCP faces fail closed), the workload data plane and the
// Authority's procedures on the API listener, the wait stream, both AuthZEN
// decision routes, and the Authority's in-process entry points (Authorize,
// Decide, BeginDispatch, Verify, ObserveTool) that AuthZEN, A2A and
// automations call. Management procedures still reach authentication, and
// without the hold nothing is refused.
func TestHR379_NoDecisionWhileHeld(t *testing.T) {
	reached := 0
	next := func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		reached++
		return ctx, nil
	}
	call := func(a rpc.Authenticator, proc string) error {
		_, err := a(context.Background(), nil, connect.Spec{Procedure: proc})
		return err
	}
	type path struct{ name, procedure string }
	var gatewayListener []path
	for _, s := range []struct {
		file    protoreflect.FileDescriptor
		service string
	}{
		{pantherclawv1.File_pantherclaw_v1_authority_proto, "AuthorityService"},
		{pantherclawv1.File_pantherclaw_v1_gateways_proto, "GatewayService"},
		{pantherclawv1.File_pantherclaw_v1_agents_proto, "AgentService"},
	} {
		for _, p := range procedures(t, s.file, s.service) {
			gatewayListener = append(gatewayListener, path{"gateway listener", p})
		}
	}
	var api []path
	for _, p := range procedures(t, pantherclawv1.File_pantherclaw_v1_workload_proto, "WorkloadService") {
		api = append(api, path{"workload", p})
	}
	for _, m := range []string{"Authorize", "GetNonce", "VerifyWorkload", "BeginDispatch"} {
		api = append(api, path{"authority on the API", "/pantherclaw.v1.AuthorityService/" + m})
	}
	for proc, perm := range procedurePermissions {
		if strings.HasPrefix(string(perm), "workload.") {
			api = append(api, path{"workload permission", proc})
		}
	}
	if len(gatewayListener) < 20 || len(api) < 10 {
		t.Fatalf("too few paths: %d gateway listener, %d API", len(gatewayListener), len(api))
	}

	for _, held := range []bool{true, false} {
		gw := holdAuthenticator(held, heldOnGatewayListener, next)
		ap := holdAuthenticator(held, heldOnAPI, next)
		for _, c := range append(gatewayListener, api...) {
			a := ap
			if c.name == "gateway listener" {
				a = gw
			}
			reached = 0
			err := call(a, c.procedure)
			if held && (!isHold(err) || reached != 0) {
				t.Errorf("held: %s %s = %v (authentication reached %d times), want MAINTENANCE_HOLD first", c.name, c.procedure, err, reached)
			}
			if !held && (err != nil || reached != 1) {
				t.Errorf("not held: %s %s = %v, want it passed on", c.name, c.procedure, err)
			}
		}
	}

	// Management procedures keep working while held.
	ap := holdAuthenticator(true, heldOnAPI, next)
	managed := 0
	for proc, perm := range procedurePermissions {
		p := string(perm)
		if strings.HasPrefix(p, "workload.") || p == "gateway.authorize" || p == "gateway.dispatch" {
			continue
		}
		reached = 0
		if err := call(ap, proc); err != nil || reached != 1 {
			t.Errorf("held: management %s (%s) = %v, want it to reach authentication", proc, p, err)
		}
		managed++
	}
	if managed < 50 {
		t.Errorf("only %d management procedures checked", managed)
	}

	// HTTP routes outside Connect.
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, held := range []bool{true, false} {
		h := holdHTTP(held, heldHTTPPath, ok)
		for _, c := range []struct {
			method, path string
			refused      bool
		}{
			{http.MethodGet, workloadrpc.WaitPath + ids.NewV7().String(), true},
			{http.MethodPost, authzenEvaluationPath, true},
			{http.MethodPost, authzenEvaluationsPath, true},
			{http.MethodGet, authzenConfigPath, false},
			{http.MethodGet, "/livez", false},
			{http.MethodGet, "/.well-known/pantherclaw/jwks.json", false},
			{http.MethodPost, "/pantherclaw.v1.AgentService/ListAgents", false},
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), c.method, c.path, nil))
			refused := rec.Code == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), "MAINTENANCE_HOLD")
			if want := held && c.refused; refused != want || (!refused && rec.Code != http.StatusNoContent) {
				t.Errorf("held=%v %s %s = %d %s, want refused=%v", held, c.method, c.path, rec.Code, rec.Body.String(), want)
			}
		}
	}

	// The Authority itself, for every in-process caller.
	svc := authority.New(authority.Config{}).WithMaintenanceHold(true)
	ctx := context.Background()
	gwID := authority.Gateway{ID: "gw", Org: ids.New[ids.Org]()}
	_, errA := svc.Authorize(ctx, gwID, []byte(`{}`), nil)
	_, errD := svc.Decide(ctx, authority.ExternalRequest{Gateway: gwID})
	_, errB := svc.BeginDispatch(ctx, gwID, ids.NewV7(), 1, authority.Outbound{})
	_, errV := svc.Verify(ctx, gwID, nil, ids.UUID{})
	_, _, errO := svc.ObserveTool(ctx, gwID, nil, ids.UUID{}, ids.UUID{}, "tool", nil)
	for name, err := range map[string]error{"Authorize": errA, "Decide": errD, "BeginDispatch": errB, "Verify": errV, "ObserveTool": errO} {
		if !isHold(err) {
			t.Errorf("held Authority.%s = %v, want MAINTENANCE_HOLD", name, err)
		}
	}
	if !svc.Held() || authority.New(authority.Config{}).Held() {
		t.Error("Held does not report the hold")
	}
}

// TestHR379_GatewayListenerRefusesEveryProcedure: the gateway listener as
// wired refuses every one of its procedures, unary and streaming, with
// MAINTENANCE_HOLD while held.
func TestHR379_GatewayListenerRefusesEveryProcedure(t *testing.T) {
	m := &m6Services{hold: true, scans: pantherclawv1connect.UnimplementedAgentServiceHandler{}}
	h, err := m.gatewayHandler(authority.New(authority.Config{}), pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range []struct {
		file    protoreflect.FileDescriptor
		service string
	}{
		{pantherclawv1.File_pantherclaw_v1_authority_proto, "AuthorityService"},
		{pantherclawv1.File_pantherclaw_v1_gateways_proto, "GatewayService"},
		{pantherclawv1.File_pantherclaw_v1_agents_proto, "AgentService"},
	} {
		sd := s.file.Services().ByName(protoreflect.Name(s.service))
		for i := range sd.Methods().Len() {
			md := sd.Methods().Get(i)
			path := "/" + string(sd.FullName()) + "/" + string(md.Name())
			body, ctype := []byte("{}"), "application/json"
			if md.IsStreamingServer() || md.IsStreamingClient() {
				body, ctype = []byte{0, 0, 0, 0, 2, '{', '}'}, "application/connect+json"
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, bytes.NewReader(body))
			req.Header.Set("Content-Type", ctype)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if !strings.Contains(rec.Body.String(), "MAINTENANCE_HOLD") || !strings.Contains(rec.Body.String(), "unavailable") {
				t.Errorf("%s = %d %s, want unavailable MAINTENANCE_HOLD", path, rec.Code, rec.Body.String())
			}
			n++
		}
	}
	if n < 20 {
		t.Fatalf("only %d gateway procedures", n)
	}
}
