// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// cookieAuth maps session cookies to callers; it counts rechecks and
// rotates the cookie "rotate" on its first Authenticate.
type cookieAuth struct {
	mu       sync.Mutex
	sessions map[string]tenancy.Caller
	auths    int
	rechecks int
}

func (a *cookieAuth) lookup(cookie string) (authnapp.BrowserSession, error) {
	c, ok := a.sessions[cookie]
	if !ok {
		return authnapp.BrowserSession{}, authnapp.ErrUnauthenticated
	}
	return authnapp.BrowserSession{Caller: c}, nil
}

func (a *cookieAuth) Authenticate(_ context.Context, cookie string) (authnapp.BrowserSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.auths++
	s, err := a.lookup(cookie)
	if err == nil && cookie == "rotate" {
		s.Rotated = "rotated"
		a.sessions["rotated"] = s.Caller
	}
	return s, err
}

func (a *cookieAuth) Recheck(_ context.Context, cookie string) (authnapp.BrowserSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rechecks++
	return a.lookup(cookie)
}

func (a *cookieAuth) revoke(cookie string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, cookie)
}

type cookieWorld struct {
	*world
	cookies *cookieAuth
}

func newCookieWorld(t *testing.T, cfg stream.Config) *cookieWorld {
	t.Helper()
	w := &world{
		org: ids.New[ids.Org](), feed: &fakeFeed{}, auth: &fakeAuth{callers: map[string]tenancy.Caller{}},
		expiry: map[string]time.Time{}, clk: clock.NewFake(time.Now()),
	}
	auditor := caller(w.org, td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()})
	w.auth.set("org-auditor", auditor)
	ca := &cookieAuth{sessions: map[string]tenancy.Caller{"good": auditor, "rotate": auditor}}
	if cfg.Poll == 0 {
		cfg.Poll = 5 * time.Millisecond
	}
	h, err := stream.New(w.feed, w.auth, teamScoper{}, nil, w.clk, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	w.srv = httptest.NewUnstartedServer(mux)
	w.srv.Start()
	t.Cleanup(w.srv.Close)
	s, err := webguard.NewSessions(ca, w.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.WithBrowserSessions(s).Mount(mux)
	return &cookieWorld{world: w, cookies: ca}
}

// consoleOpen opens the stream the way the console does; mutate changes
// the request from that shape.
func (w *cookieWorld) consoleOpen(t *testing.T, ctx context.Context, cookie string, mutate func(*http.Request)) opened {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.srv.URL+stream.Path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", w.srv.URL)
	req.Header.Set(webguard.CSRFHeader, "1")
	req.Header.Set("Last-Event-ID", "0")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: webguard.SessionCookieBase, Value: cookie})
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := w.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return opened{StatusCode: resp.StatusCode, Header: resp.Header, Body: resp.Body}
}

// TestHR344_ConsoleOpensTheStreamWithItsCookie: a same-origin POST with
// PC-CSRF: 1 and a JSON body streams the viewer's events; a rotated
// secret replaces the cookie before the stream starts; rechecks never
// rotate; a revoked session closes the stream.
func TestHR344_ConsoleOpensTheStreamWithItsCookie(t *testing.T) {
	w := newCookieWorld(t, stream.Config{Recheck: 20 * time.Millisecond, Heartbeat: time.Hour})
	ctx := ctxFor(t)
	w.event("reflex.alert", agent(ids.NewV7()))
	resp := w.consoleOpen(t, ctx, "rotate", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("console stream = %d %v", resp.StatusCode, resp.Header)
	}
	if sc := resp.Header.Get("Set-Cookie"); !strings.Contains(sc, webguard.SessionCookieBase+"=rotated") || !strings.Contains(sc, "HttpOnly") {
		t.Fatalf("Set-Cookie = %q", sc)
	}
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Errorf("CORS header %s", k)
		}
	}
	got, _ := frames(t, resp.Body, untilEvents(1))
	if ev := events(got); len(ev) != 1 || ev[0].id != "1" {
		t.Fatalf("events %+v", ev)
	}
	w.cookies.revoke("rotated")
	if _, closed := frames(t, resp.Body, func([]frame) bool { return false }); !closed {
		t.Fatal("revoked session: stream still open")
	}
	w.cookies.mu.Lock()
	defer w.cookies.mu.Unlock()
	if w.cookies.auths != 1 || w.cookies.rechecks == 0 {
		t.Errorf("authenticate %d times (want 1), recheck %d times", w.cookies.auths, w.cookies.rechecks)
	}
}

// TestRT061_CrossOriginReadOfTheOpsStream (HR-344): another site cannot
// open the stream with the viewer's cookie, the cookie never works on GET
// or in the URL, and bearer plus cookie is ambiguous. The bearer stream
// is unchanged.
func TestRT061_CrossOriginReadOfTheOpsStream(t *testing.T) {
	w := newCookieWorld(t, stream.Config{})
	ctx := ctxFor(t)
	for name, tc := range map[string]struct {
		mutate func(*http.Request)
		want   int
	}{
		"cross-site":   {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		"same-site":    {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, http.StatusForbidden},
		"other Origin": {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, http.StatusForbidden},
		"no proof": {func(r *http.Request) {
			r.Header.Del("Sec-Fetch-Site")
			r.Header.Del("Origin")
		}, http.StatusForbidden},
		"no PC-CSRF":        {func(r *http.Request) { r.Header.Del(webguard.CSRFHeader) }, http.StatusForbidden},
		"form body":         {func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, http.StatusForbidden},
		"GET with cookie":   {func(r *http.Request) { r.Method = http.MethodGet; r.Body = http.NoBody }, http.StatusForbidden},
		"bearer and cookie": {func(r *http.Request) { r.Header.Set("Authorization", "Bearer org-auditor") }, http.StatusUnauthorized},
		"cookie in URL": {func(r *http.Request) {
			r.URL.RawQuery = "token=good"
		}, http.StatusBadRequest},
	} {
		if resp := w.consoleOpen(t, ctx, "good", tc.mutate); resp.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
	if resp := w.consoleOpen(t, ctx, "forged", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged cookie: %d", resp.StatusCode)
	}
	if resp := w.consoleOpen(t, ctx, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST without a cookie: %d", resp.StatusCode)
	}
	if resp := w.open(t, ctx, stream.Path, "org-auditor", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("bearer GET: %d", resp.StatusCode)
	}
	if resp := w.consoleOpen(t, ctx, "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer org-auditor") }); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bearer POST: %d", resp.StatusCode)
	}
}
