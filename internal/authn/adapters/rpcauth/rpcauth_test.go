// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeAuthn accepts the bearer "viewer" (org Viewer) and rejects the rest.
type fakeAuthn struct{ org ids.OrgID }

func (f fakeAuthn) Authenticate(_ context.Context, bearer string) (tapp.Caller, error) {
	if bearer != "viewer" {
		return tapp.Caller{}, pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "invalid or expired credentials")
	}
	return tapp.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}, Credential: tapp.CredAccessToken}, nil
}

// fakeAccess echoes the caller the interceptor put into the context.
type fakeAccess struct {
	pantherclawv1connect.UnimplementedAccessServiceHandler
}

func (fakeAccess) WhoAmI(ctx context.Context, _ *pantherclawv1.WhoAmIRequest) (*pantherclawv1.WhoAmIResponse, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.WhoAmIResponse{OrgId: c.Org.String(), Credential: string(c.Credential)}, nil
}

func (fakeAccess) ListUsers(context.Context, *pantherclawv1.ListUsersRequest) (*pantherclawv1.ListUsersResponse, error) {
	return &pantherclawv1.ListUsersResponse{}, nil
}

func (fakeAccess) ListRoles(context.Context, *pantherclawv1.ListRolesRequest) (*pantherclawv1.ListRolesResponse, error) {
	return &pantherclawv1.ListRolesResponse{}, nil
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(r)
}

func setup(t *testing.T, perms map[string]td.Permission, gw rpc.Authenticator) (ids.OrgID, func(string) pantherclawv1connect.AccessServiceClient) {
	t.Helper()
	org := ids.New[ids.Org]()
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(fakeAuthn{org: org}, perms, gw)})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAccessServiceHandler(s, fakeAccess{})
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return org, func(tok string) pantherclawv1connect.AccessServiceClient {
		hc := &http.Client{Transport: bearer{token: tok, base: ts.Client().Transport}}
		return pantherclawv1connect.NewAccessServiceClient(connect.NewClient(connecthttp.NewTransport(hc, ts.URL)))
	}
}

func code(err error) connect.Code { return connect.CodeOf(err) }

func TestInterceptorAuthenticatesAndAuthorizes(t *testing.T) {
	perms := map[string]td.Permission{
		pantherclawv1connect.AccessServiceWhoAmIProcedure:    td.PermAuthenticated,
		pantherclawv1connect.AccessServiceListUsersProcedure: td.PermUserRead,
		// ListRoles is deliberately missing: unknown procedures fail closed.
	}
	org, client := setup(t, perms, nil)
	ctx := context.Background()

	res, err := client("viewer").WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{})
	if err != nil || res.GetOrgId() != org.String() || res.GetCredential() != "access_token" {
		t.Fatalf("WhoAmI = %v, %v", res, err)
	}
	if _, err := client("").WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{}); code(err) != connect.CodeUnauthenticated {
		t.Errorf("no credentials: %v", err)
	}
	if _, err := client("forged").WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{}); code(err) != connect.CodeUnauthenticated {
		t.Errorf("bad credentials: %v", err)
	}
	// A viewer holds user.read nowhere: refused before the handler runs.
	if _, err := client("viewer").ListUsers(ctx, &pantherclawv1.ListUsersRequest{}); code(err) != connect.CodePermissionDenied {
		t.Errorf("missing permission: %v", err)
	}
	if _, err := client("viewer").ListRoles(ctx, &pantherclawv1.ListRolesRequest{}); code(err) != connect.CodePermissionDenied {
		t.Errorf("procedure without a declared permission: %v", err)
	}
}

func TestGatewayProceduresAreDelegated(t *testing.T) {
	perms := map[string]td.Permission{pantherclawv1connect.AccessServiceWhoAmIProcedure: td.PermGatewayAuthorize}
	_, client := setup(t, perms, nil)
	if _, err := client("viewer").WhoAmI(context.Background(), &pantherclawv1.WhoAmIRequest{}); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("gateway procedure without a gateway authenticator: %v", err)
	}
	called := false
	gw := func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		called = true
		return nil, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
	}
	_, client = setup(t, perms, gw)
	if _, err := client("viewer").WhoAmI(context.Background(), &pantherclawv1.WhoAmIRequest{}); code(err) != connect.CodeUnauthenticated || !called {
		t.Fatalf("user credential on a gateway procedure: called=%v err=%v", called, err)
	}
}

// TestHR180_GatewayEnrollmentReachesItsHandlerWithoutAPrincipal: Enroll is
// authenticated by its enrollment token, which the handler verifies; the
// interceptor neither asks the gateway authenticator nor puts any caller in
// the context, so a bearer credential sent along gains nothing.
func TestHR180_GatewayEnrollmentReachesItsHandlerWithoutAPrincipal(t *testing.T) {
	perms := map[string]td.Permission{pantherclawv1connect.AccessServiceWhoAmIProcedure: td.PermGatewayEnroll}
	called := false
	gw := func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		called = true
		return ctx, nil
	}
	_, client := setup(t, perms, gw)
	// The fake WhoAmI handler answers Unauthenticated without a caller in the
	// context: the request reached it, with no principal.
	_, err := client("viewer").WhoAmI(context.Background(), &pantherclawv1.WhoAmIRequest{})
	if called || code(err) != connect.CodeUnauthenticated {
		t.Fatalf("enroll: gateway authenticator called=%v, err=%v", called, err)
	}
}

// TestAFinishedCallIsNotUnauthenticated: a credential lookup that fails
// because the call's deadline passed or the client cancelled gives
// deadline_exceeded or canceled, never 401, so a client with a valid
// session is not sent to sign in again.
func TestAFinishedCallIsNotUnauthenticated(t *testing.T) {
	org := ids.New[ids.Org]()
	perms := map[string]td.Permission{pantherclawv1connect.AccessServiceWhoAmIProcedure: td.PermAuthenticated}
	auth := rpcauth.New(fakeAuthn{org: org}, perms, nil)
	spec := connect.Spec{Procedure: pantherclawv1connect.AccessServiceWhoAmIProcedure}
	call := func(ctx context.Context, token string) error {
		info := &connect.CallInfo{}
		info.RequestHeader().Set("Authorization", "Bearer "+token)
		_, err := auth(ctx, info, spec)
		return err
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancel()
	if err := call(expired, "forged"); code(err) != connect.CodeDeadlineExceeded {
		t.Errorf("expired call = %v, want deadline_exceeded", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := call(cancelled, "forged"); code(err) != connect.CodeCanceled {
		t.Errorf("cancelled call = %v, want canceled", err)
	}
	// A live call with a bad credential is still unauthenticated.
	if err := call(context.Background(), "forged"); pcerr.CodeOf(err) != pcerr.Unauthenticated {
		t.Errorf("live call = %v, want unauthenticated", err)
	}
}
