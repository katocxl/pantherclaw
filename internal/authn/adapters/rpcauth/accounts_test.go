// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var rangeAccount = ids.NewV7()

// fakeAccounts accepts the account cookie "acct" and links every org user
// to rangeAccount.
type fakeAccounts struct{}

func (fakeAccounts) AuthenticateAccount(_ context.Context, cookie string) (authnapp.AccountSession, error) {
	if cookie != "acct" {
		return authnapp.AccountSession{}, authnapp.ErrUnauthenticated
	}
	return authnapp.AccountSession{Caller: accounts.Caller{Account: rangeAccount, Session: ids.NewV7()}}, nil
}

func (fakeAccounts) UserAccount(context.Context, ids.OrgID, ids.UUID) (ids.UUID, bool, error) {
	return rangeAccount, true, nil
}

// accountAccess reports who the call is from: the org caller, or else the
// account.
type accountAccess struct {
	pantherclawv1connect.UnimplementedAccessServiceHandler
}

func (accountAccess) WhoAmI(ctx context.Context, _ *pantherclawv1.WhoAmIRequest) (*pantherclawv1.WhoAmIResponse, error) {
	if c, err := tapp.CallerFrom(ctx); err == nil {
		return &pantherclawv1.WhoAmIResponse{OrgId: c.Org.String()}, nil
	}
	a, _ := accounts.CallerFrom(ctx)
	return &pantherclawv1.WhoAmIResponse{AccountId: a.Account.String()}, nil
}

func (accountAccess) ListUsers(context.Context, *pantherclawv1.ListUsersRequest) (*pantherclawv1.ListUsersResponse, error) {
	return &pantherclawv1.ListUsersResponse{}, nil
}

func (accountAccess) AcceptInvitation(ctx context.Context, _ *pantherclawv1.AcceptInvitationRequest) (*pantherclawv1.AcceptInvitationResponse, error) {
	a, _ := accounts.CallerFrom(ctx)
	return &pantherclawv1.AcceptInvitationResponse{OrgId: "account:" + a.Account.String()}, nil
}

func accountServer(t *testing.T) *httptest.Server {
	t.Helper()
	org := ids.New[ids.Org]()
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	s, err := webguard.NewSessions(fakeSessions{org: org}, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]td.Permission{
		pantherclawv1connect.AccessServiceWhoAmIProcedure:           td.PermAuthenticated,
		pantherclawv1connect.AccessServiceListUsersProcedure:        td.PermUserRead,
		pantherclawv1connect.AccessServiceAcceptInvitationProcedure: td.PermInvitationsAccept,
	}
	srv, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(fakeAuthn{org: org}, perms, nil,
		rpcauth.WithBrowserSessions(s, nil), rpcauth.WithAccountSessions(fakeAccounts{}, "pc_account", ts.URL))})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAccessServiceHandler(srv, accountAccess{})
	rpc.Mount(mux, srv)
	return ts
}

// accountCall is a console call with the account cookie instead of the
// org session's.
func accountCall(t *testing.T, ts *httptest.Server, c browserCall, procedure string) (answer, string) {
	t.Helper()
	cookie := c.cookie
	c.cookie = ""
	if c.headers == nil {
		c.headers = map[string]string{}
	}
	if cookie != "" {
		c.headers["Cookie"] = "pc_account=" + cookie
	}
	return c.do(t, ts, procedure)
}

// TestHR350_AccountSessionsReachOnlyTheAllowListOnTheAPI: an account
// session calls who-am-I and the account procedures with the console's
// request checks, and nothing org-scoped; an org browser session reaches
// the account procedures for its user's account.
func TestHR350_AccountSessionsReachOnlyTheAllowListOnTheAPI(t *testing.T) {
	ts := accountServer(t)
	ok := consoleCall(ts)
	ok.cookie = "acct"
	if res, body := accountCall(t, ts, ok, whoAmI); res.StatusCode != http.StatusOK || !strings.Contains(body, rangeAccount.String()) {
		t.Fatalf("account WhoAmI = %d %s", res.StatusCode, body)
	}
	if res, body := accountCall(t, ts, ok, pantherclawv1connect.AccessServiceListUsersProcedure); res.StatusCode == http.StatusOK {
		t.Errorf("an account session listed users: %s", body)
	}
	cross := ok
	cross.headers = map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example", webguard.CSRFHeader: "1"}
	if res, _ := accountCall(t, ts, cross, whoAmI); res.StatusCode == http.StatusOK {
		t.Error("a cross-site page used the account session")
	}
	both := ok
	both.bearer = "token"
	if res, body := accountCall(t, ts, both, whoAmI); res.StatusCode == http.StatusOK || !strings.Contains(body, "AMBIGUOUS_CREDENTIAL") {
		t.Errorf("bearer and account cookie: %d %s", res.StatusCode, body)
	}
	bad := ok
	bad.cookie = "stolen"
	if res, _ := accountCall(t, ts, bad, whoAmI); res.StatusCode == http.StatusOK {
		t.Error("an unknown account cookie was accepted")
	}
	// An org browser session accepts an invitation for its user's account.
	inv := consoleCall(ts)
	inv.body = `{"token":"pci_` + strings.Repeat("a", 32) + "_" + strings.Repeat("B", 43) + `"}`
	if res, body := inv.do(t, ts, pantherclawv1connect.AccessServiceAcceptInvitationProcedure); res.StatusCode != http.StatusOK ||
		!strings.Contains(body, "account:"+rangeAccount.String()) {
		t.Errorf("org session AcceptInvitation = %d %s", res.StatusCode, body)
	}
}
