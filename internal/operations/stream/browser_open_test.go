// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// consoleOpen opens the stream the way the console does (a same-origin
// GET with PC-CSRF: 1 and the session cookie); mutate changes the request
// from that shape.
func (w *cookieWorld) consoleOpen(t *testing.T, ctx context.Context, cookie string, mutate func(*http.Request)) opened {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.srv.URL+stream.Path, nil)
	if err != nil {
		t.Fatal(err)
	}
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

// TestHR344_ConsoleOpensTheStreamWithItsCookie: a same-origin GET with
// PC-CSRF: 1 streams the viewer's events with the session cookie alone; a
// rotated secret replaces the cookie before the stream starts; rechecks
// never rotate; a revoked session closes the stream.
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
	auths, rechecks := w.cookies.auths, w.cookies.rechecks
	w.cookies.mu.Unlock()
	if auths != 1 || rechecks == 0 {
		t.Errorf("authenticate %d times (want 1), recheck %d times", auths, rechecks)
	}
	// Without Fetch Metadata the Origin alone proves the page.
	o := w.consoleOpen(t, ctx, "good", func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") })
	if o.StatusCode != http.StatusOK {
		t.Fatalf("Origin only = %d", o.StatusCode)
	}
}

// TestHR344_AnEndedSessionClosesTheStreamWithinTheRecheck: the recheck
// interval is at most 30 seconds, and a session the server ends while the
// console's stream is open closes the stream within one interval.
func TestHR344_AnEndedSessionClosesTheStreamWithinTheRecheck(t *testing.T) {
	if stream.DefaultRecheck <= 0 || stream.DefaultRecheck > 30*time.Second {
		t.Fatalf("recheck interval %s", stream.DefaultRecheck)
	}
	const recheck = 200 * time.Millisecond
	w := newCookieWorld(t, stream.Config{Recheck: recheck, Heartbeat: time.Hour})
	ctx := ctxFor(t)
	resp := w.consoleOpen(t, ctx, "good", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("open = %d", resp.StatusCode)
	}
	frames(t, resp.Body, func(fs []frame) bool { return len(fs) >= 1 }) // the opening comment
	ended := time.Now()
	w.cookies.revoke("good")
	if _, closed := frames(t, resp.Body, func([]frame) bool { return false }); !closed {
		t.Fatal("ended session: stream still open")
	}
	if d := time.Since(ended); d > 2*recheck+time.Second {
		t.Fatalf("closed %s after the session ended, recheck %s", d, recheck)
	}
}

// TestRT061_CrossOriginReadOfTheOpsStream (HR-344): another site cannot
// open the stream with the viewer's cookie (an EventSource from another
// page carries the cookie but cannot add PC-CSRF), the cookie never works
// in the URL, and bearer plus cookie is ambiguous. The bearer stream is
// unchanged.
func TestRT061_CrossOriginReadOfTheOpsStream(t *testing.T) {
	w := newCookieWorld(t, stream.Config{})
	ctx := ctxFor(t)
	for name, tc := range map[string]struct {
		mutate func(*http.Request)
		want   int
	}{
		"cross-site GET without PC-CSRF": {func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Del(webguard.CSRFHeader)
		}, http.StatusForbidden},
		"cross-site":   {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		"same-site":    {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, http.StatusForbidden},
		"typed URL":    {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") }, http.StatusForbidden},
		"other Origin": {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, http.StatusForbidden},
		"no proof": {func(r *http.Request) {
			r.Header.Del("Sec-Fetch-Site")
			r.Header.Del("Origin")
		}, http.StatusForbidden},
		"no PC-CSRF":        {func(r *http.Request) { r.Header.Del(webguard.CSRFHeader) }, http.StatusForbidden},
		"PC-CSRF not 1":     {func(r *http.Request) { r.Header.Set(webguard.CSRFHeader, "yes") }, http.StatusForbidden},
		"POST":              {func(r *http.Request) { r.Method = http.MethodPost }, http.StatusMethodNotAllowed},
		"bearer and cookie": {func(r *http.Request) { r.Header.Set("Authorization", "Bearer org-auditor") }, http.StatusUnauthorized},
		"cookie in URL":     {func(r *http.Request) { r.URL.RawQuery = "token=good" }, http.StatusBadRequest},
	} {
		if resp := w.consoleOpen(t, ctx, "good", tc.mutate); resp.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
	if resp := w.consoleOpen(t, ctx, "forged", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged cookie: %d", resp.StatusCode)
	}
	if resp := w.consoleOpen(t, ctx, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no cookie, no bearer: %d", resp.StatusCode)
	}
	if resp := w.open(t, ctx, stream.Path, "org-auditor", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("bearer GET: %d", resp.StatusCode)
	}
}
