// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream

import (
	"context"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// WithBrowserSessions lets the console open the stream with its session
// cookie (HR-344), under the same rules as a cookie-authenticated Connect
// call: POST /v1/operations/stream from a page of the public origin
// (Sec-Fetch-Site same-origin, or Origin equal to it), with PC-CSRF: 1 and
// a JSON body (ignored; the resume point is Last-Event-ID or after). A
// cookie on GET, or with a bearer credential, is refused; the bearer
// stream stays GET only. No CORS header is sent and no credential is read
// from the URL. It returns h.
func (h *Handler) WithBrowserSessions(s *webguard.Sessions) *Handler {
	h.sessions = s
	return h
}

// maxBrowserBody bounds the console's (ignored) request body.
const maxBrowserBody = 4 << 10

// authenticate resolves the stream's credential, answering the refusal
// itself when it returns false. reauth checks the credential again;
// expires is when it stops (zero: only the recheck ends it).
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (
	c tenancy.Caller, reauth func(context.Context) (tenancy.Caller, error), expires time.Time, ok bool,
) {
	authz := r.Header.Get("Authorization")
	cookie, hasCookie := "", false
	if h.sessions != nil {
		cookie, hasCookie = h.sessions.Cookie(r.Header.Values("Cookie"))
	}
	switch {
	case authz != "" && hasCookie:
		http.Error(w, "AMBIGUOUS_CREDENTIAL: send either a bearer credential or the browser session, not both",
			http.StatusUnauthorized)
		return c, nil, expires, false
	case hasCookie:
		return h.browser(w, r, cookie)
	case r.Method != http.MethodGet:
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return c, nil, expires, false
	}
	bearer, found := strings.CutPrefix(authz, "Bearer ")
	if !found || bearer == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return c, nil, expires, false
	}
	c, err := h.auth.Authenticate(r.Context(), bearer)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "invalid or expired credentials", http.StatusUnauthorized)
		return c, nil, expires, false
	}
	if exp, ok := h.expiry(bearer); ok {
		expires = exp
	}
	return c, func(ctx context.Context) (tenancy.Caller, error) { return h.auth.Authenticate(ctx, bearer) }, expires, true
}

// browser authenticates the console's cookie stream: the request checks
// run before the session is looked up; a rotated secret replaces the
// cookie before the stream starts, and rechecks never rotate it again.
func (h *Handler) browser(w http.ResponseWriter, r *http.Request, cookie string) (
	tenancy.Caller, func(context.Context) (tenancy.Caller, error), time.Time, bool,
) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || err != nil || mt != "application/json" ||
		r.Header.Get(webguard.CSRFHeader) != "1" || !webguard.SameOrigin(r.Header.Get, h.sessions.PublicOrigin()) {
		h.log.WarnContext(r.Context(), "operations.stream_browser_refused")
		http.Error(w, "BROWSER_REQUEST_REFUSED: a browser session is accepted only on a same-origin POST with PC-CSRF: 1",
			http.StatusForbidden)
		return tenancy.Caller{}, nil, time.Time{}, false
	}
	_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, maxBrowserBody))
	s, err := h.sessions.Auth.Authenticate(r.Context(), cookie)
	if err != nil {
		http.Error(w, "invalid or expired session", http.StatusUnauthorized)
		return tenancy.Caller{}, nil, time.Time{}, false
	}
	if s.Rotated != "" {
		w.Header().Add("Set-Cookie", h.sessions.SetCookie(s.Rotated))
		cookie = s.Rotated
	}
	reauth := func(ctx context.Context) (tenancy.Caller, error) {
		rs, err := h.sessions.Auth.Recheck(ctx, cookie)
		return rs.Caller, err
	}
	return s.Caller, reauth, time.Time{}, true
}
