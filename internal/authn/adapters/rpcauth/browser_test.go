// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeSessions accepts the cookie "good", and "rotate" (rotating it to
// "rotated").
type fakeSessions struct{ org ids.OrgID }

func (f fakeSessions) Authenticate(_ context.Context, cookie string) (authnapp.BrowserSession, error) {
	if cookie != "good" && cookie != "rotate" {
		return authnapp.BrowserSession{}, authnapp.ErrUnauthenticated
	}
	s := authnapp.BrowserSession{Caller: tapp.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession, Session: ids.NewV7()}}
	if cookie == "rotate" {
		s.Rotated = "rotated"
	}
	return s, nil
}

func (f fakeSessions) Recheck(ctx context.Context, cookie string) (authnapp.BrowserSession, error) {
	return f.Authenticate(ctx, cookie)
}

// kindAccess reports the caller's credential and the audit auth kind.
type kindAccess struct {
	pantherclawv1connect.UnimplementedAccessServiceHandler
}

func (kindAccess) WhoAmI(ctx context.Context, _ *pantherclawv1.WhoAmIRequest) (*pantherclawv1.WhoAmIResponse, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	kind, _ := audit.AuthKindFrom(ctx)
	return &pantherclawv1.WhoAmIResponse{OrgId: c.Org.String(), Credential: string(c.Credential), OrgName: kind}, nil
}

func (kindAccess) ListUsers(context.Context, *pantherclawv1.ListUsersRequest) (*pantherclawv1.ListUsersResponse, error) {
	return &pantherclawv1.ListUsersResponse{}, nil
}

// browserServer serves AccessService with cookie sessions on; its public
// URL is the test server's own.
func browserServer(t *testing.T, sessions bool) (*httptest.Server, ids.OrgID) {
	t.Helper()
	org := ids.New[ids.Org]()
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	var opts []rpcauth.Option
	if sessions {
		s, err := webguard.NewSessions(fakeSessions{org: org}, ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		opts = append(opts, rpcauth.WithBrowserSessions(s, nil))
	}
	perms := map[string]td.Permission{
		pantherclawv1connect.AccessServiceWhoAmIProcedure:    td.PermAuthenticated,
		pantherclawv1connect.AccessServiceListUsersProcedure: td.PermUserManage,
	}
	srv, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(fakeAuthn{org: org}, perms, nil, opts...)})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAccessServiceHandler(srv, kindAccess{})
	rpc.Mount(mux, srv)
	return ts, org
}

// browserCall is one console call; mutate changes it from the accepted
// shape.
type browserCall struct {
	method, contentType, body, cookie, bearer string
	headers                                   map[string]string
}

func consoleCall(ts *httptest.Server) browserCall {
	return browserCall{
		method: http.MethodPost, contentType: "application/json", body: "{}", cookie: "good",
		headers: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": ts.URL, webguard.CSRFHeader: "1"},
	}
}

// answer is a response's status and headers; its body is read and closed.
type answer struct {
	StatusCode int
	Header     http.Header
}

func (c browserCall) do(t *testing.T, ts *httptest.Server, procedure string) (answer, string) {
	t.Helper()
	u := ts.URL + procedure
	var body io.Reader = strings.NewReader(c.body)
	if c.method == http.MethodGet {
		u += "?" + url.Values{"connect": {"v1"}, "encoding": {"json"}, "message": {c.body}}.Encode()
		body = nil
	}
	req, err := http.NewRequestWithContext(context.Background(), c.method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if c.contentType != "" && c.method != http.MethodGet {
		req.Header.Set("Content-Type", c.contentType)
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: webguard.SessionCookieBase, Value: c.cookie})
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for k, v := range c.headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return answer{res.StatusCode, res.Header}, string(b)
}

const whoAmI = pantherclawv1connect.AccessServiceWhoAmIProcedure

// TestHR342_ConsoleCookieAccepted: a same-origin console POST with
// PC-CSRF: 1 and a Connect JSON or proto body is authenticated by the
// session cookie, with the browser_session credential and audit auth kind.
func TestHR342_ConsoleCookieAccepted(t *testing.T) {
	ts, org := browserServer(t, true)
	res, body := consoleCall(ts).do(t, ts, whoAmI)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, org.String()) ||
		!strings.Contains(body, `"credential":"browser_session"`) || !strings.Contains(body, `"orgName":"browser_session"`) {
		t.Fatalf("console call = %d %s", res.StatusCode, body)
	}
	// Without Fetch Metadata the Origin alone proves the page.
	c := consoleCall(ts)
	c.headers["Sec-Fetch-Site"] = ""
	if res, body := c.do(t, ts, whoAmI); res.StatusCode != http.StatusOK {
		t.Fatalf("Origin only = %d %s", res.StatusCode, body)
	}
	// Binary protobuf body.
	c = consoleCall(ts)
	c.contentType, c.body = "application/proto", ""
	if res, body := c.do(t, ts, whoAmI); res.StatusCode != http.StatusOK {
		t.Fatalf("application/proto = %d %s", res.StatusCode, body)
	}
	// No CORS: a preflight gets no Access-Control headers.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, ts.URL+whoAmI, nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "pc-csrf, content-type")
	pre, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = pre.Body.Close()
	for k := range pre.Header {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Errorf("preflight answered with %s", k)
		}
	}
}

// TestT160_CookieCSRFOnConnect (HR-342): every way a cross-site page could
// ride the session cookie into a Connect call is refused before the
// session is used.
func TestT160_CookieCSRFOnConnect(t *testing.T) {
	ts, org := browserServer(t, true)
	for name, mutate := range map[string]func(*browserCall){
		"cross-site":            func(c *browserCall) { c.headers["Sec-Fetch-Site"] = "cross-site" },
		"same-site":             func(c *browserCall) { c.headers["Sec-Fetch-Site"] = "same-site" },
		"typed URL":             func(c *browserCall) { c.headers["Sec-Fetch-Site"] = "none" },
		"other Origin":          func(c *browserCall) { c.headers["Origin"] = "https://evil.example" },
		"no metadata no Origin": func(c *browserCall) { c.headers["Sec-Fetch-Site"], c.headers["Origin"] = "", "" },
		"no metadata bad Origin": func(c *browserCall) {
			c.headers["Sec-Fetch-Site"], c.headers["Origin"] = "", "null"
		},
		"no PC-CSRF":         func(c *browserCall) { c.headers[webguard.CSRFHeader] = "" },
		"PC-CSRF not 1":      func(c *browserCall) { c.headers[webguard.CSRFHeader] = "true" },
		"GET":                func(c *browserCall) { c.method = http.MethodGet },
		"form content type":  func(c *browserCall) { c.contentType = "application/x-www-form-urlencoded" },
		"text/plain":         func(c *browserCall) { c.contentType = "text/plain" },
		"streaming protocol": func(c *browserCall) { c.contentType = "application/connect+json" },
		"forged cookie":      func(c *browserCall) { c.cookie = "forged" },
	} {
		c := consoleCall(ts)
		mutate(&c)
		res, body := c.do(t, ts, whoAmI)
		if res.StatusCode == http.StatusOK || strings.Contains(body, org.String()) {
			t.Errorf("%s: accepted (%d %s)", name, res.StatusCode, body)
		}
	}
	// gRPC-web carries the cookie as well; it is refused (the status rides
	// in a header or the trailer frame).
	frame := func(b []byte) []byte {
		out := []byte{0, 0, 0, 0, byte(len(b))}
		return append(out, b...)
	}
	msg, _ := proto.Marshal(&pantherclawv1.WhoAmIRequest{})
	c := consoleCall(ts)
	c.contentType, c.body = "application/grpc-web+proto", string(frame(msg))
	res, body := c.do(t, ts, whoAmI)
	status := res.Header.Get("Grpc-Status")
	if !strings.Contains(body, "grpc-status:") && status == "" {
		t.Fatalf("grpc-web: no status (%d %v)", res.StatusCode, res.Header)
	}
	if status == "0" || strings.Contains(body, "grpc-status:0") || strings.Contains(body, org.String()) {
		t.Errorf("grpc-web accepted: %d %v", res.StatusCode, res.Header)
	}
}

// TestHR343_BearerAndCookieTogether: both credentials in one call are
// refused as AMBIGUOUS_CREDENTIAL, whichever would be valid; the bearer
// path alone is unchanged, and a server without browser sessions ignores
// the cookie.
func TestHR343_BearerAndCookieTogether(t *testing.T) {
	ts, org := browserServer(t, true)
	c := consoleCall(ts)
	c.bearer = "viewer"
	res, body := c.do(t, ts, whoAmI)
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "not both") {
		t.Fatalf("bearer + cookie = %d %s", res.StatusCode, body)
	}
	c.headers["Authorization"] = "Basic eA=="
	if res, _ := c.do(t, ts, whoAmI); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other Authorization + cookie = %d", res.StatusCode)
	}
	b := browserCall{method: http.MethodPost, contentType: "application/json", body: "{}", bearer: "viewer"}
	if res, body := b.do(t, ts, whoAmI); res.StatusCode != http.StatusOK || !strings.Contains(body, `"credential":"access_token"`) ||
		strings.Contains(body, "orgName") {
		t.Fatalf("bearer alone = %d %s", res.StatusCode, body)
	}
	plain, _ := browserServer(t, false)
	if res, body := consoleCall(plain).do(t, plain, whoAmI); res.StatusCode != http.StatusUnauthorized || strings.Contains(body, org.String()) {
		t.Fatalf("cookie without browser sessions = %d %s", res.StatusCode, body)
	}
}

// TestHR342_CookieRotationAndPermissions: a rotated secret replaces the
// cookie on the response with the HR-150 attributes, and a cookie caller
// is authorized like any other caller.
func TestHR342_CookieRotationAndPermissions(t *testing.T) {
	ts, _ := browserServer(t, true)
	c := consoleCall(ts)
	c.cookie = "rotate"
	res, body := c.do(t, ts, whoAmI)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("rotate = %d %s", res.StatusCode, body)
	}
	sc := res.Header.Get("Set-Cookie")
	for _, want := range []string{webguard.SessionCookieBase + "=rotated", "Path=/", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(sc, want) {
			t.Errorf("Set-Cookie %q lacks %q", sc, want)
		}
	}
	// A viewer holds no user.manage: refused although the cookie is good.
	res, _ = consoleCall(ts).do(t, ts, pantherclawv1connect.AccessServiceListUsersProcedure)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("ListUsers as viewer = %d", res.StatusCode)
	}
}
