// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package oauthhttp serves the OAuth 2.0 endpoints (RFC 6749, 7523, 8414,
// 8628 shape) outside the Connect API: the token endpoint and the
// authorization-server metadata. Requests are parsed strictly: form bodies
// only, bounded size, no repeated parameters, no HTTP Basic client
// authentication (only private_key_jwt). Responses are never cached.
package oauthhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

// MaxFormBytes bounds a token request body.
const MaxFormBytes = 16 << 10

// Grant types.
const (
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantRefreshToken      = "refresh_token"
)

// TokenGrants implements the grants of the token endpoint.
type TokenGrants interface {
	ClientCredentials(ctx context.Context, clientID, assertionType, assertion string) (authnapp.TokenResponse, error)
}

// Handler serves the OAuth endpoints.
type Handler struct {
	grants  TokenGrants
	issuer  string
	limiter *httpx.Limiter
	extra   map[string]func(context.Context, url.Values) (authnapp.TokenResponse, error)
}

// New returns the handler. limiter bounds requests per client IP.
func New(grants TokenGrants, issuer string, limiter *httpx.Limiter) *Handler {
	return &Handler{grants: grants, issuer: issuer, limiter: limiter, extra: map[string]func(context.Context, url.Values) (authnapp.TokenResponse, error){}}
}

// HandleGrant adds a grant type to the token endpoint (device code, refresh
// token).
func (h *Handler) HandleGrant(grantType string, fn func(context.Context, url.Values) (authnapp.TokenResponse, error)) {
	h.extra[grantType] = fn
}

// Mount installs the endpoints on mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST "+authnapp.TokenPath, h.token)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.metadata)
}

// ParseForm reads an application/x-www-form-urlencoded body strictly: no
// query string, bounded size, every parameter at most once.
func ParseForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return nil, authnapp.ErrInvalidRequest
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxFormBytes))
	if err != nil {
		return nil, authnapp.ErrInvalidRequest
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, authnapp.ErrInvalidRequest
	}
	for _, v := range form {
		if len(v) != 1 {
			return nil, authnapp.ErrInvalidRequest
		}
	}
	return form, nil
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if !h.limiter.AllowRequest(r) {
		telemetry.RateLimited(r.Context(), telemetry.ScopeSignIn)
		WriteError(w, &authnapp.OAuthError{Code: "slow_down", Description: "too many requests", Status: http.StatusTooManyRequests})
		return
	}
	if r.Header.Get("Authorization") != "" {
		// Only private_key_jwt is supported; client secrets never exist.
		WriteError(w, authnapp.ErrInvalidClient)
		return
	}
	form, err := ParseForm(w, r)
	if err != nil {
		WriteError(w, err)
		return
	}
	var res authnapp.TokenResponse
	switch gt := form.Get("grant_type"); gt {
	case GrantClientCredentials:
		res, err = h.grants.ClientCredentials(r.Context(), form.Get("client_id"), form.Get("client_assertion_type"), form.Get("client_assertion"))
	default:
		fn, ok := h.extra[gt]
		if !ok {
			WriteError(w, authnapp.ErrUnsupportedGrantType)
			return
		}
		res, err = fn(r.Context(), form)
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, res)
}

// WriteError writes an OAuth error response. Anything that is not an
// OAuthError is a server error and reveals nothing.
func WriteError(w http.ResponseWriter, err error) {
	var oe *authnapp.OAuthError
	if !errors.As(err, &oe) {
		oe = &authnapp.OAuthError{Code: "server_error", Description: "internal error", Status: http.StatusInternalServerError}
	}
	if oe.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_client"`)
	}
	WriteJSON(w, oe.Status, map[string]string{"error": oe.Code, "error_description": oe.Description})
}

// WriteJSON writes a JSON response that is never cached.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"error":"server_error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// metadata serves RFC 8414 authorization-server metadata, so standard OAuth
// client libraries can find the token endpoint and the supported methods.
func (h *Handler) metadata(w http.ResponseWriter, _ *http.Request) {
	grants := append([]string{GrantClientCredentials}, slices.Sorted(maps.Keys(h.extra))...)
	WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                h.issuer,
		"token_endpoint":                        h.issuer + authnapp.TokenPath,
		"grant_types_supported":                 grants,
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"EdDSA", "ES256"},
		"response_types_supported":                         []string{},
	})
}
