// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package webguard holds the browser-session cookie and the cross-site
// request checks shared by the server pages (webhttp), the Connect API
// (rpcauth) and the live operations stream, so the three take the cookie
// under the same rules (HR-150, HR-151, HR-342, HR-344).
package webguard

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// CSRFHeader must accompany every request a browser session authenticates
// outside a plain page load.
const CSRFHeader = "PC-CSRF"

// SessionCookieBase is the session cookie's name before the __Host-
// prefix.
const SessionCookieBase = "pc_session"

// CookieName returns a cookie's name: __Host- cookies on https; the plain
// name only for an http loopback development URL, where Secure cookies
// cannot be set.
func CookieName(base string, secure bool) string {
	if secure {
		return "__Host-" + base
	}
	return base
}

// Origin returns the scheme and host of an absolute http(s) URL and
// whether it is https.
func Origin(publicURL string) (origin string, secure bool, err error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", false, errors.New("webguard: public URL must be an absolute http(s) URL")
	}
	return u.Scheme + "://" + u.Host, u.Scheme == "https", nil
}

// SameOrigin reports whether a request comes from a page of origin:
// Sec-Fetch-Site same-origin (with a matching Origin when one is sent), or,
// from a browser without Fetch Metadata, an Origin equal to origin.
// Cross-site, same-site (another subdomain) and none (a typed URL) are
// refused. get reads a request header.
func SameOrigin(get func(string) string, origin string) bool {
	o := get("Origin")
	switch get("Sec-Fetch-Site") {
	case "same-origin":
		return o == "" || o == origin
	case "":
		return o == origin // no Fetch Metadata: the Origin must prove the page
	default:
		return false
	}
}

// Authenticator resolves session cookies (authn/app.Browser).
type Authenticator interface {
	Authenticate(ctx context.Context, cookie string) (authnapp.BrowserSession, error)
	// Recheck checks a session again without rotating its secret.
	Recheck(ctx context.Context, cookie string) (authnapp.BrowserSession, error)
}

// Sessions is the browser-session cookie of one server.
type Sessions struct {
	Auth   Authenticator
	origin string
	secure bool
}

// NewSessions returns the cookie rules for publicURL.
func NewSessions(auth Authenticator, publicURL string) (*Sessions, error) {
	if auth == nil {
		return nil, errors.New("webguard: authenticator required")
	}
	o, secure, err := Origin(publicURL)
	if err != nil {
		return nil, err
	}
	return &Sessions{Auth: auth, origin: o, secure: secure}, nil
}

// PublicOrigin is the only origin whose pages may use the cookie.
func (s *Sessions) PublicOrigin() string { return s.origin }

// CookieName is the session cookie's name.
func (s *Sessions) CookieName() string { return CookieName(SessionCookieBase, s.secure) }

// Cookie returns the session cookie's value among Cookie header lines.
func (s *Sessions) Cookie(lines []string) (string, bool) {
	name := s.CookieName()
	for _, line := range lines {
		cs, err := http.ParseCookie(line)
		if err != nil {
			continue
		}
		for _, c := range cs {
			if c.Name == name && c.Value != "" {
				return c.Value, true
			}
		}
	}
	return "", false
}

// SetCookie is the Set-Cookie line that replaces the session cookie with
// secret (after a rotation), with the attributes of HR-150.
func (s *Sessions) SetCookie(secret string) string {
	c := &http.Cookie{ //nolint:gosec // G124: Secure is set whenever the public URL is https; HttpOnly and SameSite always
		Name: s.CookieName(), Value: secret, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(authnapp.BrowserSessionLifetime / time.Second),
	}
	return c.String()
}
