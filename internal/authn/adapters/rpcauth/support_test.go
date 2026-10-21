// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeSupport accepts one support cookie and records the procedures it
// authenticated (the support service audits each one).
type fakeSupport struct {
	org    ids.OrgID
	cookie string
	calls  *[]string
}

func (f fakeSupport) Authenticate(_ context.Context, cookie, procedure string) (tapp.Caller, error) {
	if cookie != f.cookie {
		return tapp.Caller{}, pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "authentication required")
	}
	*f.calls = append(*f.calls, procedure)
	return tapp.Caller{
		Subject: td.Subject{
			Org: f.org, Principal: td.PrincipalRef{Kind: td.KindSupport, ID: ids.NewV7()},
			Bindings: tapp.SupportScopeBindings(f.org, tapp.SupportScopeReadOnly),
		},
		Credential: tapp.CredSupportSession, Session: ids.NewV7(), SupportGrant: ids.NewV7(),
	}, nil
}

func supportServer(t *testing.T) (*httptest.Server, string, *[]string) {
	t.Helper()
	org := ids.New[ids.Org]()
	tok, err := credential.New(credential.SupportSession, "", org)
	if err != nil {
		t.Fatal(err)
	}
	calls := &[]string{}
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	s, err := webguard.NewSessions(fakeSessions{org: org}, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]td.Permission{
		pantherclawv1connect.AccessServiceWhoAmIProcedure:    td.PermAuthenticated,
		pantherclawv1connect.AccessServiceListUsersProcedure: td.PermUserRead,
		pantherclawv1connect.AccessServiceGetUserProcedure:   td.PermUserManage,
	}
	readOnly := func(p string) bool {
		return p == pantherclawv1connect.AccessServiceWhoAmIProcedure || p == pantherclawv1connect.AccessServiceGetUserProcedure
	}
	srv, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(fakeAuthn{org: org}, perms, nil,
		rpcauth.WithBrowserSessions(s, nil), rpcauth.WithSupportSessions(fakeSupport{org: org, cookie: tok.Reveal(), calls: calls}, readOnly))})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAccessServiceHandler(srv, kindAccess{})
	rpc.Mount(mux, srv)
	return ts, tok.Reveal(), calls
}

// TestHR387_SupportSessionsOnlyCallReads: a support session in the
// console's cookie is authenticated by the support service, under the
// same browser-request checks, and calls only the procedures marked as
// reads; a procedure outside them is refused even when its permission is
// one the session would hold, and the permission check still applies to
// the reads.
func TestHR387_SupportSessionsOnlyCallReads(t *testing.T) {
	ts, cookie, calls := supportServer(t)
	c := consoleCall(ts)
	c.cookie = cookie
	if res, body := c.do(t, ts, whoAmI); res.StatusCode != http.StatusOK || !strings.Contains(body, `"credential":"support_session"`) ||
		!strings.Contains(body, `"orgName":"support_session"`) {
		t.Fatalf("who am I = %d %s", res.StatusCode, body)
	}
	// user.read is held, but ListUsers is not marked as a read here.
	if res, body := c.do(t, ts, pantherclawv1connect.AccessServiceListUsersProcedure); res.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, "SUPPORT_READ_ONLY") {
		t.Fatalf("not a read = %d %s", res.StatusCode, body)
	}
	// Marked as a read, but user.manage is not held.
	if res, body := c.do(t, ts, pantherclawv1connect.AccessServiceGetUserProcedure); res.StatusCode != http.StatusForbidden ||
		!strings.Contains(body, "user.manage") {
		t.Fatalf("missing permission = %d %s", res.StatusCode, body)
	}
	if len(*calls) != 3 {
		t.Errorf("support service saw %d calls, want 3 (each one audited)", len(*calls))
	}
	// The browser-request checks apply: no PC-CSRF, no session.
	bad := consoleCall(ts)
	bad.cookie, bad.headers["PC-CSRF"] = cookie, ""
	if res, _ := bad.do(t, ts, whoAmI); res.StatusCode != http.StatusForbidden {
		t.Errorf("without PC-CSRF = %d", res.StatusCode)
	}
	// A support cookie never authenticates as a browser session, and a
	// forged one is refused.
	forged := consoleCall(ts)
	forged.cookie = cookie[:len(cookie)-1] + "0"
	if res, _ := forged.do(t, ts, whoAmI); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged support cookie = %d", res.StatusCode)
	}
	if len(*calls) != 3 {
		t.Errorf("refused requests reached the support service: %v", *calls)
	}
}
