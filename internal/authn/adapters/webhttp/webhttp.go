// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package webhttp serves PantherClaw's own browser pages (G0 M5 part 1):
// browser sign-in and sign-out and the account page, (part 2) the approval
// page and (G0 M7) the reconciliation page, on the same foundation.
//
// Every response carries a strict CSP with required Trusted Types, is never
// cached or framed, and pages are rendered with html/template from embedded
// templates; the only script is a static file. A state-changing request
// (POST) must be authenticated by the session cookie and pass the CSRF check
// (HR-151): Sec-Fetch-Site same-origin (or, from a browser without Fetch
// Metadata, an Origin equal to the public origin), the PC-CSRF header and a
// JSON content type. GET handlers never change state; the route table
// records which routes need a session and the CSRF check, and a test walks
// it.
package webhttp

import (
	"context"
	"embed"
	"encoding/json/v2"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// PageCSP is the Content-Security-Policy of every page (HR-151).
const PageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'"

// CSRFHeader must accompany every state-changing browser request.
const CSRFHeader = "PC-CSRF"

// maxJSONBody bounds a JSON request body from a page.
const maxJSONBody = 64 << 10

// Browser is the browser sign-in use-case set (authn/app.Browser).
type Browser interface {
	Start(ctx context.Context, in authnapp.BrowserStart) (authnapp.Redirect, error)
	Callback(ctx context.Context, provider string, params url.Values, binding string, meta authnapp.ClientMeta) (authnapp.BrowserSignIn, error)
	Authenticate(ctx context.Context, cookie string) (authnapp.BrowserSession, error)
	Logout(ctx context.Context, cookie string) error
	Profile(ctx context.Context, s authnapp.BrowserSession) (authnapp.Profile, error)
	ListSessions(ctx context.Context, s authnapp.BrowserSession) ([]authnapp.SessionInfo, error)
	RevokeSession(ctx context.Context, s authnapp.BrowserSession, id ids.UUID) error
}

// Route describes one mounted route, for the route-table test.
type Route struct {
	Method, Path string
	// Session: the route requires a browser session. CSRF: the route
	// changes state and requires the CSRF check.
	Session, CSRF bool
}

// Handler serves the pages.
type Handler struct {
	b       Browser
	origin  string
	secure  bool
	limiter *httpx.Limiter
	log     *slog.Logger
	routes  []Route
	keys    Keys
	// containment is the emergency-stop page (G0 M6); nil when not mounted.
	containment Containment
	// approvals is the approval page (G0 M5 part 2); nil when not mounted.
	approvals Approvals
	bindings  Bindings
	// reconciliations is the reconciliation page (G0 M7); nil when not
	// mounted.
	reconciliations Reconciliations
	releaseBindings Bindings
}

// New returns the handler. publicURL is the server's public URL: its origin
// is the only one allowed to make state-changing requests, and https makes
// the cookies __Host- cookies.
func New(b Browser, publicURL string, limiter *httpx.Limiter, log *slog.Logger) (*Handler, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("webhttp: public URL must be an absolute http(s) URL")
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{b: b, origin: u.Scheme + "://" + u.Host, secure: u.Scheme == "https", limiter: limiter, log: log}, nil
}

// sessionHandler handles a request authenticated by a browser session.
type sessionHandler func(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession)

// Mount installs the routes. The callback is served by the device flow's
// handler, which hands browser states to Callback.
func (h *Handler) Mount(mux *http.ServeMux) {
	h.public(mux, http.MethodGet, authnapp.LoginPath, h.login)
	h.public(mux, http.MethodGet, "/signed-out", h.signedOut)
	h.public(mux, http.MethodGet, "/static/{file}", h.static)
	h.withSession(mux, http.MethodPost, authnapp.LogoutPath, h.logout)
	h.withSession(mux, http.MethodGet, authnapp.AccountPath, h.account)
	h.withSession(mux, http.MethodPost, authnapp.AccountPath+"/sessions/{id}/revoke", h.revokeSession)
	h.mountKeys(mux)
	h.mountContainment(mux)
	h.mountApprovals(mux)
	h.mountReconciliations(mux)
}

// Routes lists the mounted routes.
func (h *Handler) Routes() []Route { return append([]Route(nil), h.routes...) }

func (h *Handler) public(mux *http.ServeMux, method, path string, f http.HandlerFunc) {
	h.routes = append(h.routes, Route{Method: method, Path: path})
	mux.HandleFunc(method+" "+path, h.limited(f))
}

// withSession mounts a route that needs a session; a POST also needs the
// CSRF check, which runs before the session is even looked up.
func (h *Handler) withSession(mux *http.ServeMux, method, path string, f sessionHandler) {
	csrf := method != http.MethodGet && method != http.MethodHead
	h.routes = append(h.routes, Route{Method: method, Path: path, Session: true, CSRF: csrf})
	mux.HandleFunc(method+" "+path, h.limited(func(w http.ResponseWriter, r *http.Request) {
		if csrf {
			if !h.csrfOK(r) {
				h.log.WarnContext(r.Context(), "web.csrf_refused", slog.String("path", r.URL.Path),
					slog.String("sec_fetch_site", trunc(r.Header.Get("Sec-Fetch-Site"), 32)))
				h.jsonError(w, http.StatusForbidden, "csrf")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
		}
		s, ok := h.session(w, r)
		if !ok {
			if csrf {
				h.jsonError(w, http.StatusUnauthorized, "unauthenticated")
			} else {
				h.toLogin(w, r)
			}
			return
		}
		f(w, r, s)
	}))
}

func (h *Handler) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pageHeaders(w)
		if h.limiter != nil && !h.limiter.AllowRequest(r) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// pageHeaders replaces the API defaults with the page policy (HR-151).
func pageHeaders(w http.ResponseWriter) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", PageCSP)
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Cross-Origin-Opener-Policy", "same-origin")
}

// csrfOK implements the CSRF check (HR-151). Plain HTML forms can set
// neither the custom header nor a JSON content type, and cross-site fetches
// with them need a CORS preflight that this server never answers.
func (h *Handler) csrfOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		if origin != "" && origin != h.origin {
			return false
		}
	case "":
		if origin != h.origin {
			return false // no Fetch Metadata: the Origin must prove the page
		}
	default:
		return false // cross-site, same-site (another subdomain) or none (typed URL)
	}
	if r.Header.Get(CSRFHeader) != "1" {
		return false
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// Cookie names: __Host- cookies on https; plain names only for an http
// loopback development URL, where Secure cookies cannot be set.
func (h *Handler) cookieName(base string) string {
	if h.secure {
		return "__Host-" + base
	}
	return base
}

const (
	sessionCookie = "pc_session"
	loginCookie   = "pc_login"
)

func (h *Handler) setCookie(w http.ResponseWriter, base, value string, maxAge time.Duration, sameSite http.SameSite) {
	c := &http.Cookie{ //nolint:gosec // G124: Secure is set whenever the public URL is https; HttpOnly and SameSite always
		Name: h.cookieName(base), Value: value, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: sameSite,
		MaxAge: int(maxAge / time.Second),
	}
	if maxAge < 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// session authenticates the session cookie; a rotated secret replaces the
// cookie on this response.
func (h *Handler) session(w http.ResponseWriter, r *http.Request) (authnapp.BrowserSession, bool) {
	c, err := r.Cookie(h.cookieName(sessionCookie))
	if err != nil || c.Value == "" {
		return authnapp.BrowserSession{}, false
	}
	s, err := h.b.Authenticate(r.Context(), c.Value)
	if err != nil {
		if !errors.Is(err, authnapp.ErrUnauthenticated) {
			h.log.ErrorContext(r.Context(), "web.session_error", pclog.Err(err))
		}
		h.setCookie(w, sessionCookie, "", -1, http.SameSiteStrictMode)
		return authnapp.BrowserSession{}, false
	}
	if s.Rotated != "" {
		h.setCookie(w, sessionCookie, s.Rotated, authnapp.BrowserSessionLifetime, http.SameSiteStrictMode)
	}
	return s, true
}

// toLogin sends a page request without a session to sign-in for the org
// named in the URL.
func (h *Handler) toLogin(w http.ResponseWriter, r *http.Request) {
	org := r.URL.Query().Get("org")
	if _, err := ids.Parse[ids.Org](org); err != nil {
		h.render(w, http.StatusUnauthorized, "error.html", page{
			Title: "Sign in", Message: "Open this page from a PantherClaw link that names your organization, or sign in with pclaw first.",
		})
		return
	}
	q := url.Values{"org": {org}, "next": {r.URL.Path}}
	http.Redirect(w, r, authnapp.LoginPath+"?"+q.Encode(), http.StatusSeeOther)
}

// page is the data of every template.
type page struct {
	Title, Message string
	Next           string
	Profile        authnapp.Profile
	Session        authnapp.BrowserSession
	Sessions       []authnapp.SessionInfo
	// Keys is nil when security keys are not configured.
	Keys        []authnapp.CredentialInfo
	KeysEnabled bool
	SteppedUp   bool
}

func (h *Handler) render(w http.ResponseWriter, status int, name string, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, p); err != nil {
		h.log.Error("web.render", slog.String("template", name), pclog.Err(err))
	}
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.MarshalWrite(w, v); err != nil {
		h.log.Error("web.json", pclog.Err(err))
	}
}

func (h *Handler) jsonError(w http.ResponseWriter, status int, code string) {
	h.writeJSON(w, status, map[string]string{"error": code})
}

// login starts a browser sign-in: GET /login?org=<org>[&idp=<name>][&next=<path>][&recent=1].
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	red, err := h.b.Start(r.Context(), authnapp.BrowserStart{
		Org: q.Get("org"), Provider: q.Get("idp"), Next: q.Get("next"), Recent: q.Get("recent") == "1",
		ClientIP: h.clientIP(r),
	})
	switch {
	case errors.Is(err, authnapp.ErrSignInUnavailable):
		h.render(w, http.StatusNotFound, "error.html", page{Title: "Sign in", Message: "Sign-in is not available for this link. Check the organization in the link."})
		return
	case errors.Is(err, authnapp.ErrSignInBusy):
		h.render(w, http.StatusServiceUnavailable, "error.html", page{Title: "Sign in", Message: "Too many sign-ins are in progress. Try again in a few minutes."})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	// Lax so that the provider's top-level redirect back carries it.
	h.setCookie(w, loginCookie, red.Binding, authnapp.LoginRequestTTL, http.SameSiteLaxMode)
	http.Redirect(w, r, red.URL, http.StatusSeeOther)
}

// Callback completes a browser sign-in; the device flow's callback route
// hands it every pcl_ state.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	pageHeaders(w)
	binding := ""
	if c, err := r.Cookie(h.cookieName(loginCookie)); err == nil {
		binding = c.Value
	}
	h.setCookie(w, loginCookie, "", -1, http.SameSiteLaxMode)
	out, err := h.b.Callback(r.Context(), r.PathValue("provider"), r.URL.Query(), binding,
		authnapp.ClientMeta{UserAgent: r.UserAgent(), IP: h.clientIP(r)})
	switch {
	case errors.Is(err, authnapp.ErrBadCallback):
		h.render(w, http.StatusBadRequest, "error.html", page{Title: "Sign in", Message: "This sign-in response is invalid or has already been used. Start again."})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	case out.Reason != "":
		h.render(w, http.StatusForbidden, "error.html", page{Title: "Sign in", Message: reasonText[out.Reason]})
		return
	}
	next := out.Next
	if !authnapp.ValidReturnPath(next) {
		next = authnapp.AccountPath
	}
	h.setCookie(w, sessionCookie, out.Secret, authnapp.BrowserSessionLifetime, http.SameSiteStrictMode)
	// A SameSite=Strict cookie is not sent on a redirect chain that started
	// at the provider, so the next page is opened from this same-origin page.
	h.render(w, http.StatusOK, "continue.html", page{Title: "Signed in", Next: next})
}

var reasonText = map[string]string{
	"NOT_A_MEMBER":  "Your account is not a member of this organization. Ask an administrator for an invitation.",
	"USER_DISABLED": "Your account in this organization is disabled.",
	"IDP_ERROR":     "The identity provider did not complete the sign-in.",
	"LOGIN_FAILED":  "The sign-in could not be verified. Start again.",
}

func (h *Handler) signedOut(w http.ResponseWriter, _ *http.Request) {
	h.render(w, http.StatusOK, "signed_out.html", page{Title: "Signed out"})
}

// logout ends the session and clears the cookie.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	c, _ := r.Cookie(h.cookieName(sessionCookie))
	if c != nil {
		if err := h.b.Logout(r.Context(), c.Value); err != nil {
			h.log.ErrorContext(r.Context(), "web.logout", pclog.Err(err), slog.String("session", s.ID.String()))
			h.jsonError(w, http.StatusInternalServerError, "internal")
			return
		}
	}
	h.setCookie(w, sessionCookie, "", -1, http.SameSiteStrictMode)
	h.writeJSON(w, http.StatusOK, map[string]bool{"signed_out": true})
}

// account shows the account page.
func (h *Handler) account(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r) // a link for another org: sign in there
		return
	}
	prof, err := h.b.Profile(r.Context(), s)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	sessions, err := h.b.ListSessions(r.Context(), s)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p := page{Title: "Your account", Profile: prof, Session: s, Sessions: sessions, SteppedUp: s.SteppedUpWithin(authnapp.StepUpLifetime)}
	if h.keys != nil {
		keys, err := h.keys.ListCredentials(r.Context(), s)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		for _, k := range keys {
			if k.State != "REMOVED" {
				p.Keys = append(p.Keys, k)
			}
		}
		p.KeysEnabled = true
	}
	h.render(w, http.StatusOK, "account.html", p)
}

// revokeSession ends one of the caller's own sessions.
func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	switch err := h.b.RevokeSession(r.Context(), s, id); {
	case errors.Is(err, authnapp.ErrSessionNotFound):
		h.jsonError(w, http.StatusNotFound, "not_found")
	case err != nil:
		h.log.ErrorContext(r.Context(), "web.revoke_session", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
	default:
		h.writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	}
}

// static serves the embedded script and stylesheet.
func (h *Handler) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	types := map[string]string{
		"account.js": "text/javascript; charset=utf-8", "containment.js": "text/javascript; charset=utf-8",
		"approvals.js": "text/javascript; charset=utf-8", "reconciliations.js": "text/javascript; charset=utf-8",
		"pc.css": "text/css; charset=utf-8",
	}
	ct, ok := types[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(staticFS, "static/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	_, _ = w.Write(b)
}

func (h *Handler) clientIP(r *http.Request) string {
	if h.limiter == nil {
		return ""
	}
	return h.limiter.ClientIP(r)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.log.ErrorContext(r.Context(), "web.error", pclog.Err(err))
	h.render(w, http.StatusInternalServerError, "error.html", page{Title: "Error", Message: "Something went wrong. Try again in a moment."})
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
