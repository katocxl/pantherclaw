// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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
