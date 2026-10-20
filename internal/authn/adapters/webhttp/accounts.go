// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/katocxl/pantherclaw/internal/accounts"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Hosted account pages (G0 UI D8, HR-348..353): the org picker after a
// sign-in without an org and the browser invitation link. Mounted only
// when the server serves accounts.

// AccountBrowser is the account sign-in use-case set (authn/app.Browser).
type AccountBrowser interface {
	AuthenticateAccount(ctx context.Context, cookie string) (authnapp.AccountSession, error)
	Memberships(ctx context.Context, s authnapp.AccountSession) ([]accounts.Membership, error)
	PickOrg(ctx context.Context, s authnapp.AccountSession, org ids.OrgID, meta authnapp.ClientMeta) (authnapp.BrowserSignIn, error)
	EndAccountSession(ctx context.Context, s authnapp.AccountSession, reason string) error
}

// accountCookie holds an account session (HttpOnly, SameSite=Strict).
const accountCookie = "pc_account"

// WithAccounts mounts the account pages; selfServe shows the "create an
// organization" link.
func (h *Handler) WithAccounts(a AccountBrowser, selfServe bool) *Handler {
	h.accounts, h.selfServe = a, selfServe
	return h
}

// AccountCookieName is the account session cookie's name on this server.
func (h *Handler) AccountCookieName() string { return h.cookieName(accountCookie) }

// SessionCookieName is the org session cookie's name on this server.
func (h *Handler) SessionCookieName() string { return h.cookieName(sessionCookie) }

// AccountSessionCookie returns the cookie that stores an account session
// (or clears it for value "").
func (h *Handler) AccountSessionCookie(value string) *http.Cookie {
	return h.cookie(accountCookie, value)
}

// OrgSessionCookie returns the cookie that stores an org session.
func (h *Handler) OrgSessionCookie(value string) *http.Cookie {
	return h.cookie(sessionCookie, value)
}

func (h *Handler) cookie(base, value string) *http.Cookie {
	c := &http.Cookie{ //nolint:gosec // G124: Secure whenever the public URL is https; HttpOnly and SameSite always
		Name: h.cookieName(base), Value: value, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(authnapp.BrowserSessionLifetime.Seconds()),
	}
	if value == "" {
		c.MaxAge = -1
	}
	return c
}

func (h *Handler) mountAccounts(mux *http.ServeMux) {
	h.public(mux, http.MethodGet, authnapp.InvitePath+"/{token}", h.invite)
	if h.accounts == nil {
		return
	}
	h.withAccountSession(mux, http.MethodGet, authnapp.OrgPickerPath, h.orgPicker)
	h.withAccountSession(mux, http.MethodPost, authnapp.OrgPickerPath+"/sign-out", h.accountSignOut)
	h.withAccountSession(mux, http.MethodPost, authnapp.OrgPickerPath+"/{org}", h.pickOrg)
}

type accountHandler func(w http.ResponseWriter, r *http.Request, s authnapp.AccountSession)

// withAccountSession mounts a route that needs an account session; a POST
// also needs the CSRF check, which runs first (HR-151).
func (h *Handler) withAccountSession(mux *http.ServeMux, method, path string, f accountHandler) {
	csrf := method != http.MethodGet && method != http.MethodHead
	h.routes = append(h.routes, Route{Method: method, Path: path, Session: true, CSRF: csrf})
	mux.HandleFunc(method+" "+path, h.limited(func(w http.ResponseWriter, r *http.Request) {
		if csrf {
			if !h.csrfOK(r) {
				h.log.WarnContext(r.Context(), "web.csrf_refused", slog.String("path", r.URL.Path))
				h.jsonError(w, http.StatusForbidden, "csrf")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
		}
		s, ok := h.accountSession(w, r)
		if !ok {
			if csrf {
				h.jsonError(w, http.StatusUnauthorized, "unauthenticated")
			} else {
				http.Redirect(w, r, authnapp.LoginPath, http.StatusSeeOther)
			}
			return
		}
		f(w, r, s)
	}))
}

func (h *Handler) accountSession(w http.ResponseWriter, r *http.Request) (authnapp.AccountSession, bool) {
	c, err := r.Cookie(h.cookieName(accountCookie))
	if err != nil || c.Value == "" {
		return authnapp.AccountSession{}, false
	}
	s, err := h.accounts.AuthenticateAccount(r.Context(), c.Value)
	if err != nil {
		if !errors.Is(err, authnapp.ErrUnauthenticated) {
			h.log.ErrorContext(r.Context(), "web.account_session_error", pclog.Err(err))
		}
		http.SetCookie(w, h.AccountSessionCookie(""))
		return authnapp.AccountSession{}, false
	}
	s.IP = h.clientIP(r)
	return s, true
}

// orgPicker lists the account's orgs.
func (h *Handler) orgPicker(w http.ResponseWriter, r *http.Request, s authnapp.AccountSession) {
	if !authnapp.PickerFresh(s) {
		// HR-353, D88: an old account session picks nothing; a fresh
		// sign-in brings the picker back.
		http.SetCookie(w, h.AccountSessionCookie(""))
		http.Redirect(w, r, authnapp.LoginPath, http.StatusSeeOther)
		return
	}
	ms, err := h.accounts.Memberships(r.Context(), s)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.render(w, http.StatusOK, "org_picker.html", page{Title: "Choose an organization", Orgs: ms, SelfServe: h.selfServe})
}

// pickOrg opens one of the account's orgs and ends the account session.
func (h *Handler) pickOrg(w http.ResponseWriter, r *http.Request, s authnapp.AccountSession) {
	org, err := ids.Parse[ids.Org](r.PathValue("org"))
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "not_pickable")
		return
	}
	out, err := h.accounts.PickOrg(r.Context(), s, org, authnapp.ClientMeta{UserAgent: r.UserAgent(), IP: h.clientIP(r)})
	switch {
	case errors.Is(err, authnapp.ErrPickerStale):
		// HR-353, D88: past the picker's window the pick becomes a fresh
		// sign-in to the same org, landing where the pick would have.
		http.SetCookie(w, h.AccountSessionCookie(""))
		q := url.Values{"org": {org.String()}, "next": {authnapp.AccountPath}}
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_again", "sign_in": authnapp.LoginPath + "?" + q.Encode()})
		return
	case errors.Is(err, authnapp.ErrNotPickable):
		h.jsonError(w, http.StatusNotFound, "not_pickable")
		return
	case err != nil:
		h.log.ErrorContext(r.Context(), "web.pick_org", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	case out.Reason != "":
		h.jsonError(w, http.StatusForbidden, "not_pickable")
		return
	}
	http.SetCookie(w, h.OrgSessionCookie(out.Secret))
	http.SetCookie(w, h.AccountSessionCookie(""))
	h.writeJSON(w, http.StatusOK, map[string]string{"next": out.Next, "org": out.Org.String()})
}

func (h *Handler) accountSignOut(w http.ResponseWriter, r *http.Request, s authnapp.AccountSession) {
	if err := h.accounts.EndAccountSession(r.Context(), s, "LOGOUT"); err != nil {
		h.log.ErrorContext(r.Context(), "web.account_logout", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	http.SetCookie(w, h.AccountSessionCookie(""))
	h.writeJSON(w, http.StatusOK, map[string]bool{"signed_out": true})
}

// invite starts a sign-in without an org that accepts the invitation in
// the link (HR-352): GET /invite/{token}[?idp=<name>]. The token is kept
// only as a hash; the page itself shows nothing about the invitation.
func (h *Handler) invite(w http.ResponseWriter, r *http.Request) {
	red, err := h.b.Start(r.Context(), authnapp.BrowserStart{
		Provider: r.URL.Query().Get("idp"), Invitation: r.PathValue("token"), ClientIP: h.clientIP(r),
	})
	switch {
	case errors.Is(err, authnapp.ErrSignInUnavailable):
		h.render(w, http.StatusNotFound, "error.html", page{
			Title:   "Invitation",
			Message: "This invitation link cannot be used here. Ask for a new invitation, or accept it with pclaw login --invitation.",
		})
		return
	case errors.Is(err, authnapp.ErrSignInBusy):
		h.render(w, http.StatusServiceUnavailable, "error.html", page{Title: "Invitation", Message: "Too many sign-ins are in progress. Try again in a few minutes."})
		return
	case err != nil:
		h.fail(w, r, err)
		return
	}
	h.setCookie(w, loginCookie, red.Binding, authnapp.LoginRequestTTL, http.SameSiteLaxMode)
	http.Redirect(w, r, red.URL, http.StatusSeeOther)
}

// accountSignedIn finishes a sign-in that opened an account session.
func (h *Handler) accountSignedIn(w http.ResponseWriter, out authnapp.BrowserSignIn) {
	http.SetCookie(w, h.AccountSessionCookie(out.Secret))
	h.render(w, http.StatusOK, "continue.html", page{Title: "Signed in", Next: authnapp.OrgPickerPath})
}
