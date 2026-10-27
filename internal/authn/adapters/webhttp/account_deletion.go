// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// AccountDeletion confirms the single-use fresh callback and starts the
// durable journal. Connect never calls it.
type AccountDeletion interface {
	Confirm(context.Context, ids.UUID, ids.UUID) error
}
type accountLinkReader interface {
	UserAccount(context.Context, ids.OrgID, ids.UUID) (ids.UUID, bool, error)
}

// MountAccountDeletion installs the canonical server page after accounts.
func (h *Handler) MountAccountDeletion(mux *http.ServeMux, d AccountDeletion) {
	for _, route := range []Route{
		{Method: http.MethodGet, Path: authnapp.AccountDeletePath, Session: true},
		{Method: http.MethodPost, Path: authnapp.AccountDeletePath + "/reauth", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: authnapp.AccountDeletePath, Session: true, CSRF: true},
	} {
		h.routes = append(h.routes, route)
		mux.HandleFunc(route.Method+" "+route.Path, h.limited(func(w http.ResponseWriter, r *http.Request) {
			if route.CSRF && !h.csrfOK(r) {
				h.jsonError(w, http.StatusForbidden, "csrf")
				return
			}
			var account, session ids.UUID
			var provider string
			fresh := false
			ac, _ := r.Cookie(h.AccountCookieName())
			oc, _ := r.Cookie(h.SessionCookieName())
			if ac != nil && ac.Value != "" && oc != nil && oc.Value != "" {
				h.jsonError(w, http.StatusUnauthorized, "ambiguous_credential")
				return
			}
			switch {
			case ac != nil && h.accounts != nil:
				s, ok := h.accountSession(w, r)
				if !ok {
					h.jsonError(w, http.StatusUnauthorized, "unauthenticated")
					return
				}
				account, session, provider = s.Account, s.Session, s.Provider
				fresh = s.DeletionReauthenticatedAt != nil && !s.DeletionReauthenticatedAt.Before(s.Now.Add(-5*time.Minute))
			case oc != nil:
				s, ok := h.session(w, r)
				if !ok {
					h.jsonError(w, http.StatusUnauthorized, "unauthenticated")
					return
				}
				reader, ok := h.accounts.(accountLinkReader)
				if !ok {
					h.jsonError(w, http.StatusServiceUnavailable, "accounts_disabled")
					return
				}
				id, ok, err := reader.UserAccount(r.Context(), s.Org, s.Principal.ID)
				if err != nil {
					h.fail(w, r, err)
					return
				}
				if !ok {
					h.jsonError(w, http.StatusForbidden, "account_required")
					return
				}
				account, provider = id, s.Provider
			default:
				h.jsonError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			switch {
			case r.URL.Path == authnapp.AccountDeletePath+"/reauth":
				red, err := h.b.Start(r.Context(), authnapp.BrowserStart{Provider: provider, Next: authnapp.AccountDeletePath, DeletionAccount: account, ClientIP: h.clientIP(r)})
				if err != nil {
					h.fail(w, r, err)
					return
				}
				h.setCookie(w, loginCookie, red.Binding, authnapp.LoginRequestTTL, http.SameSiteLaxMode)
				h.writeJSON(w, http.StatusOK, map[string]string{"next": red.URL})
			case r.Method == http.MethodGet:
				h.render(w, http.StatusOK, "account_deletion.html", page{Title: "Delete your account", SteppedUp: fresh})
			default:
				if !fresh || session.IsZero() {
					h.jsonError(w, http.StatusForbidden, "reauth_required")
					return
				}
				if err := d.Confirm(r.Context(), account, session); err != nil {
					if pcerr.ReasonOf(err) == "DELETION_AWAITING_SECURITY_COPY" {
						http.SetCookie(w, h.AccountSessionCookie(""))
						http.SetCookie(w, h.OrgSessionCookie(""))
						h.writeJSON(w, http.StatusAccepted, map[string]string{"next": "/signed-out"})
						return
					}
					switch {
					case errors.Is(err, accounts.ErrLastAdmin):
						h.jsonError(w, http.StatusConflict, "last_org_admin")
					case errors.Is(err, accounts.ErrReauth):
						h.jsonError(w, http.StatusForbidden, "reauth_required")
					default:
						h.fail(w, r, err)
					}
					return
				}
				http.SetCookie(w, h.AccountSessionCookie(""))
				http.SetCookie(w, h.OrgSessionCookie(""))
				h.writeJSON(w, http.StatusOK, map[string]string{"next": "/signed-out"})
			}
		}))
	}
}
