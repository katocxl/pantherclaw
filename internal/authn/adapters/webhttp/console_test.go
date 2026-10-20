// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// fakeConsole is a built console bundle.
var fakeConsole = fstest.MapFS{
	"index.html":               {Data: []byte(`<!doctype html><script type="module" src="/app/assets/app-1a2b3c.js"></script>`)},
	"assets/app-1a2b3c.js":     {Data: []byte(`console.log("app")`)},
	"assets/app-1a2b3c.css":    {Data: []byte(`body{}`)},
	"favicon.svg":              {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
	"manifest.webmanifest":     {Data: []byte(`{}`)},
	"assets/font.woff2":        {Data: []byte("wOF2")},
	"assets/notes.unknownext1": {Data: []byte("<script>alert(1)</script>")},
}

func consoleMux(t *testing.T) http.Handler {
	t.Helper()
	c, err := webhttp.NewConsole(fakeConsole)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	c.Mount(mux)
	return mux
}

func get(path string) *http.Request { return httptest.NewRequest(http.MethodGet, origin+path, nil) }

// TestHR340_ConsoleOnlyAtAppWithTheConsoleCSP: the console is served only
// under /app/, every response carries exactly the console CSP and the page
// headers, the shell is never cached, hashed assets are immutable, a
// missing asset is a 404 rather than the shell, /app/ext/ is left to
// extensions, and / leads to /app/.
func TestHR340_ConsoleOnlyAtAppWithTheConsoleCSP(t *testing.T) {
	mux := consoleMux(t)
	for _, tc := range []struct {
		path, ctype, cache, body string
		status                   int
	}{
		{"/app/", "text/html; charset=utf-8", "no-store", "<!doctype html>", 200},
		{"/app/agents/0192f3a0-0000-7000-8000-000000000001", "text/html; charset=utf-8", "no-store", "<!doctype html>", 200},
		{"/app/index.html", "text/html; charset=utf-8", "no-store", "<!doctype html>", 200},
		{"/app/assets/app-1a2b3c.js", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable", "console.log", 200},
		{"/app/assets/app-1a2b3c.css", "text/css; charset=utf-8", "public, max-age=31536000, immutable", "body{}", 200},
		{"/app/assets/font.woff2", "font/woff2", "public, max-age=31536000, immutable", "wOF2", 200},
		{"/app/favicon.svg", "image/svg+xml", "no-store", "<svg", 200},
		{"/app/manifest.webmanifest", "application/manifest+json", "no-store", "{}", 200},
		{"/app/assets/gone-9z9z9z.js", "", "no-store", "", 404},
		{"/app/assets/", "", "no-store", "", 404},
		{"/app/ext/billing/plans", "", "no-store", "", 404},
	} {
		r := do(t, mux, get(tc.path))
		if r.StatusCode != tc.status || (tc.ctype != "" && r.Header.Get("Content-Type") != tc.ctype) ||
			r.Header.Get("Cache-Control") != tc.cache || !strings.Contains(r.Body, tc.body) {
			t.Errorf("%s: %d %q %q %.40q", tc.path, r.StatusCode, r.Header.Get("Content-Type"), r.Header.Get("Cache-Control"), r.Body)
		}
		if got := r.Header.Get("Content-Security-Policy"); got != webhttp.ConsoleCSP {
			t.Errorf("%s: CSP %q", tc.path, got)
		}
		for k, v := range map[string]string{
			"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
			"Cross-Origin-Opener-Policy": "same-origin",
		} {
			if r.Header.Get(k) != v {
				t.Errorf("%s: %s = %q", tc.path, k, r.Header.Get(k))
			}
		}
	}
	if r := do(t, mux, get("/")); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/app/" {
		t.Errorf("/ = %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if r := do(t, mux, get("/app")); r.StatusCode/100 != 3 || r.Header.Get("Location") != "/app/" {
		t.Errorf("/app = %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if r := do(t, mux, httptest.NewRequest(http.MethodPost, origin+"/app/", nil)); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /app/ = %d", r.StatusCode)
	}
	if r := do(t, mux, httptest.NewRequest(http.MethodHead, origin+"/app/", nil)); r.StatusCode != http.StatusOK || r.Body != "" {
		t.Errorf("HEAD /app/ = %d %q", r.StatusCode, r.Body)
	}
	if r := do(t, mux, get("/login")); r.StatusCode != http.StatusNotFound {
		t.Errorf("the console answered outside /app/: %d", r.StatusCode)
	}
	if _, err := webhttp.NewConsole(fstest.MapFS{"app.js": {Data: []byte("x")}}); err == nil {
		t.Error("a bundle without index.html was accepted")
	}
	if _, err := webhttp.NewConsole(nil); err == nil {
		t.Error("a nil bundle was accepted")
	}
}

// TestT161_ConsoleCannotRunInjectedScript: whatever agent text ends up in
// the console, the browser runs only the server's own script files: the
// CSP has no inline or eval source, requires Trusted Types with no policy
// (no string reaches an HTML sink), forbids framing and base rewriting,
// and a bundle file of unknown type is never served as HTML.
func TestT161_ConsoleCannotRunInjectedScript(t *testing.T) {
	csp := webhttp.ConsoleCSP
	for _, want := range []string{
		"default-src 'none'", "script-src 'self';", "style-src 'self';", "require-trusted-types-for 'script'",
		"trusted-types 'none'", "frame-ancestors 'none'", "base-uri 'none'", "connect-src 'self';", "form-action 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("console CSP lacks %q", want)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "unsafe-hashes", "wasm-unsafe-eval", "data:", "blob:", "*", "http:", "https:"} {
		if strings.Contains(csp, bad) {
			t.Errorf("console CSP allows %q", bad)
		}
	}
	r := do(t, consoleMux(t), get("/app/assets/notes.unknownext1"))
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "html") || r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("unknown type served as %q", ct)
	}
}

// TestHR345_RecentSignInReturnsToTheConsole (G0 UI D58): a key endpoint
// that needs a recent sign-in sends the person back to the console page
// named in return_to when it is a clean /app path, and to /account
// otherwise.
func TestHR345_RecentSignInReturnsToTheConsole(t *testing.T) {
	_, _, mux := newHandler(t, origin)
	for rt, want := range map[string]string{
		"":                       authnapp.AccountPath,
		"/app/settings/keys":     "/app/settings/keys",
		"/app/":                  "/app/",
		"/app/approvals?team=a":  "/app/approvals?team=a",
		"/app/x#frag":            authnapp.AccountPath,
		"/app":                   authnapp.AccountPath,
		"//evil.example":         authnapp.AccountPath,
		"https://evil.example/x": authnapp.AccountPath,
		"/app/../account":        authnapp.AccountPath,
		"/app/%2F%2Fevil":        authnapp.AccountPath,
		"/approvals":             authnapp.AccountPath,
	} {
		p := authnapp.AccountPath + "/keys/registration-options"
		if rt != "" {
			p += "?" + url.Values{"return_to": {rt}}.Encode()
		}
		resp := do(t, mux, post(p))
		var body map[string]string
		if err := json.Unmarshal([]byte(resp.Body), &body); err != nil || body["error"] != "recent_auth_required" {
			t.Fatalf("%q: %d %s", rt, resp.StatusCode, resp.Body)
		}
		u, err := url.Parse(body["sign_in"])
		if err != nil || u.Query().Get("next") != want || u.Path != authnapp.LoginPath {
			t.Errorf("return_to %q: sign-in link %q, want next %q", rt, body["sign_in"], want)
		}
	}
}
