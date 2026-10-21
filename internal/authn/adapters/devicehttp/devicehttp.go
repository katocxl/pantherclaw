// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package devicehttp serves the CLI device login over HTTP (ADR-0016): the
// device authorization endpoint for pclaw, the browser pages where a person
// confirms the code and is sent to the identity provider, the OIDC callback,
// and token revocation.
//
// The confirmation is a POST that must come from this origin (Origin or
// Sec-Fetch-Site), so another site cannot start a sign-in in the person's
// browser. The browser that confirms receives an HttpOnly binding cookie
// that the callback requires (login CSRF). Pages are rendered with
// html/template, carry a strict CSP and are never cached or framed.
package devicehttp

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// Device is the device-flow use-case set (authn/app.Device).
type Device interface {
	Start(ctx context.Context, in authnapp.DeviceStart) (authnapp.DeviceAuthorization, error)
	Prompt(ctx context.Context, org, userCode string) (authnapp.DevicePrompt, error)
	Confirm(ctx context.Context, org, userCode string) (authnapp.Redirect, error)
	Callback(ctx context.Context, provider string, params url.Values, binding string) (authnapp.Outcome, error)
	DeviceCodeGrant(ctx context.Context, form url.Values) (authnapp.TokenResponse, error)
	RefreshGrant(ctx context.Context, form url.Values) (authnapp.TokenResponse, error)
	Revoke(ctx context.Context, refresh string) error
}

// Handler serves the device login.
type Handler struct {
	d       Device
	origin  string
	secure  bool
	limiter *httpx.Limiter
	log     *slog.Logger
	// browser completes browser sign-ins (pcl_ states) on the shared
	// callback URL; nil refuses them.
	browser http.HandlerFunc
}

// New returns the handler. issuer is the server's public URL: its origin is
// the only one allowed to post the confirmation, and https makes the binding
// cookie a __Host- cookie.
func New(d Device, issuer string, limiter *httpx.Limiter, log *slog.Logger) (*Handler, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return nil, errors.New("devicehttp: issuer must be an absolute URL")
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{d: d, origin: u.Scheme + "://" + u.Host, secure: u.Scheme == "https", limiter: limiter, log: log}, nil
}

// Mount installs the routes and adds the device-code and refresh grants to
// the token endpoint.
func (h *Handler) Mount(mux *http.ServeMux, token *oauthhttp.Handler) {
	mux.HandleFunc("POST "+authnapp.DeviceAuthorizationPath, h.limited(h.authorize))
	mux.HandleFunc("GET "+authnapp.DevicePath, h.limited(h.prompt))
	mux.HandleFunc("POST "+authnapp.DevicePath, h.limited(h.confirm))
	mux.HandleFunc("GET "+authnapp.CallbackPath+"{provider}", h.limited(h.callback))
	mux.HandleFunc("POST "+authnapp.RevocationPath, h.limited(h.revoke))
	token.HandleGrant(oauthhttp.GrantDeviceCode, h.d.DeviceCodeGrant)
	token.HandleGrant(oauthhttp.GrantRefreshToken, h.d.RefreshGrant)
}

func (h *Handler) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.limiter.AllowRequest(r) {
			telemetry.RateLimited(r.Context(), telemetry.ScopeSignIn)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// authorize is the RFC 8628 device authorization endpoint (for pclaw).
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	form, err := oauthhttp.ParseForm(w, r)
	if err != nil {
		oauthhttp.WriteError(w, err)
		return
	}
	if form.Get("client_id") != authnapp.CLIClientID {
		oauthhttp.WriteError(w, authnapp.ErrInvalidClient)
		return
	}
	res, err := h.d.Start(r.Context(), authnapp.DeviceStart{
		Org: form.Get("org"), DeviceJWK: form.Get("device_jwk"), DeviceName: form.Get("device_name"),
		Invitation: form.Get("invitation"), Provider: form.Get("idp"), ClientIP: h.limiter.ClientIP(r),
	})
	if err != nil {
		oauthhttp.WriteError(w, err)
		return
	}
	oauthhttp.WriteJSON(w, http.StatusOK, res)
}

// page is the data of every template.
type page struct {
	Org      string
	UserCode string
	Prompt   authnapp.DevicePrompt
	Outcome  authnapp.Outcome
	Message  string
}

func (h *Handler) render(w http.ResponseWriter, status int, name string, p page) {
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Frame-Options", "DENY")
	// These pages post a form to an Origin-checked handler (sameOrigin).
	// Under "no-referrer" a browser's form POST (a "navigate" request, not
	// "cors") carries "Origin: null" (Fetch Standard, "serializing a request
	// origin": a request whose referrer policy is no-referrer and whose method
	// is neither GET nor HEAD gets the opaque origin), so sign-in would always
	// be refused. "same-origin" sends our real origin on our own forms and no
	// referrer anywhere else. The API keeps "no-referrer".
	hd.Set("Referrer-Policy", "same-origin")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, p); err != nil {
		h.log.Error("device.render", pclog.Err(err))
	}
}

// prompt shows the code entry form or, with a code, the confirmation page.
func (h *Handler) prompt(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	org, code := q.Get("org"), q.Get("user_code")
	if code == "" {
		h.render(w, http.StatusOK, "enter.html", page{Org: org})
		return
	}
	p, err := h.d.Prompt(r.Context(), org, code)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, http.StatusOK, "confirm.html", page{Org: org, UserCode: p.UserCode, Prompt: p})
}

// sameOrigin accepts a state-changing browser request only from this
// server's pages.
func (h *Handler) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == h.origin
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

func (h *Handler) cookieName() string {
	if h.secure {
		return "__Host-pc_device"
	}
	return "pc_device"
}

// confirm starts the identity-provider login for a confirmed code.
func (h *Handler) confirm(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		h.render(w, http.StatusForbidden, "error.html", page{Message: "This request did not come from the PantherClaw sign-in page."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		h.render(w, http.StatusBadRequest, "error.html", page{Message: "The request was malformed."})
		return
	}
	red, err := h.d.Confirm(r.Context(), r.PostForm.Get("org"), r.PostForm.Get("user_code"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Secure on https deployments; Lax so the provider's top-level redirect back carries it.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is set whenever the public URL is https
		Name: h.cookieName(), Value: red.Binding, Path: "/", MaxAge: int(authnapp.DeviceCodeTTL / time.Second),
		HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, red.URL, http.StatusSeeOther)
}

// WithBrowserCallback hands callbacks of browser sign-ins (pcl_ states) to
// f: the device and browser flows share one callback URL per provider (G0
// M5 design decision 6).
func (h *Handler) WithBrowserCallback(f http.HandlerFunc) *Handler {
	h.browser = f
	return h
}

// callback finishes the provider login and shows the result.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	if authnapp.IsBrowserState(r.URL.Query()) && h.browser != nil {
		h.browser(w, r)
		return
	}
	binding := ""
	if c, err := r.Cookie(h.cookieName()); err == nil {
		binding = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: h.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode}) //nolint:gosec // G124: deletes the cookie; Secure on https deployments
	out, err := h.d.Callback(r.Context(), r.PathValue("provider"), r.URL.Query(), binding)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	status := http.StatusOK
	if !out.Approved {
		status = http.StatusForbidden
	}
	h.render(w, status, "result.html", page{Outcome: out, Message: reasonText[out.Reason]})
}

var reasonText = map[string]string{
	"NOT_A_MEMBER":       "Your account is not a member of this organization. Ask an administrator for an invitation.",
	"USER_DISABLED":      "Your account in this organization is disabled.",
	"INVITATION_INVALID": "The invitation is no longer valid. Ask for a new one.",
	"EMAIL_MISMATCH":     "The invitation was sent to a different email address, or your identity provider did not verify your email.",
	"IDP_ERROR":          "The identity provider did not complete the sign-in.",
	"LOGIN_FAILED":       "The sign-in could not be verified. Start again from your terminal.",
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authnapp.ErrUnknownCode):
		h.render(w, http.StatusNotFound, "error.html", page{Message: "This code is wrong or has expired. Check the code in your terminal, or start again."})
	case errors.Is(err, authnapp.ErrBadCallback):
		h.render(w, http.StatusBadRequest, "error.html", page{Message: "This sign-in response is invalid or has already been used. Start again from your terminal."})
	default:
		h.log.ErrorContext(r.Context(), "device.error", pclog.Err(err))
		h.render(w, http.StatusInternalServerError, "error.html", page{Message: "Something went wrong. Try again in a moment."})
	}
}

// revoke implements RFC 7009 for refresh tokens: 200 whether or not the
// token was valid.
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	form, err := oauthhttp.ParseForm(w, r)
	if err != nil {
		oauthhttp.WriteError(w, err)
		return
	}
	if hint := form.Get("token_type_hint"); hint != "" && hint != "refresh_token" {
		oauthhttp.WriteError(w, &authnapp.OAuthError{Code: "unsupported_token_type", Description: "only refresh tokens can be revoked", Status: 400})
		return
	}
	if err := h.d.Revoke(r.Context(), strings.TrimSpace(form.Get("token"))); err != nil {
		oauthhttp.WriteError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}
