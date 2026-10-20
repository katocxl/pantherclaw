// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"log/slog"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// SessionRoute mounts an extension route (internal/extension) that needs a
// browser session, on the same foundation as the pages: page headers, the
// rate limit and, with csrf, the CSRF check before the session is looked
// up (HR-151). A request without a valid session gets a JSON 401: an
// extension route never redirects to sign-in. The caller validated pattern
// (HR-341).
func (h *Handler) SessionRoute(mux *http.ServeMux, pattern string, csrf bool,
	next func(http.ResponseWriter, *http.Request, authnapp.BrowserSession),
) {
	mux.HandleFunc(pattern, h.limited(func(w http.ResponseWriter, r *http.Request) {
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
			h.jsonError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		next(w, r, s)
	}))
}
