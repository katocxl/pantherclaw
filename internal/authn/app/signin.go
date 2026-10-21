// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/subtle"
	"net/url"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
)

// The callback URL is shared by the CLI device flow and browser sign-in,
// so a provider needs one redirect URI; the state's prefix tells the two
// apart (G0 M5 design decision 6).

// IsBrowserState reports whether a callback's state belongs to a browser
// sign-in (pcl_, or pcm_ without an org) rather than a device login (pcs_).
func IsBrowserState(params url.Values) bool {
	s := params.Get("state")
	return strings.HasPrefix(s, string(credential.LoginState)+"_") || strings.HasPrefix(s, string(credential.AccountLoginState)+"_")
}

// authTimeSkew is the clock difference tolerated on auth_time.
const authTimeSkew = time.Minute

// pendingSignIn is what a consumed sign-in state carried.
type pendingSignIn struct {
	provider    string
	bindingHash []byte
	nonce       *string
	nonceHash   []byte
	verifier    *string
	// maxAge is set when the request asked for a recent sign-in.
	maxAge time.Duration
}

// signInFailure says why a callback failed: reason is the stable code shown
// to the person (IDP_ERROR or LOGIN_FAILED), detail goes to the log.
type signInFailure struct {
	reason, detail string
	err            error
}

// verifySignIn checks a provider callback against its consumed state, in
// this order: the provider that was asked (mix-up), the browser binding
// cookie (login CSRF), a provider error, the RFC 9207 iss parameter, the
// code exchange with PKCE and the ID token, the nonce, and, when max_age was
// requested, an auth_time no older than max_age (HR-152). The state must
// already be consumed (single use).
func verifySignIn(ctx context.Context, idp IdP, redirectURI, providerName string, params url.Values, binding string,
	p pendingSignIn, now time.Time,
) (IDClaims, *signInFailure) {
	fail := func(reason, detail string, err error) (IDClaims, *signInFailure) {
		return IDClaims{}, &signInFailure{reason: reason, detail: detail, err: err}
	}
	if p.provider != providerName {
		return fail("LOGIN_FAILED", "provider mix-up", nil)
	}
	if binding == "" || subtle.ConstantTimeCompare(credential.HashString(binding), p.bindingHash) != 1 {
		return fail("LOGIN_FAILED", "browser binding", nil)
	}
	if params.Get("error") != "" {
		return fail("IDP_ERROR", "provider error", nil)
	}
	needIss, err := idp.RequireIssParam(ctx)
	if err != nil {
		return fail("LOGIN_FAILED", "provider metadata", err)
	}
	if iss := params.Get("iss"); (iss == "" && needIss) || (iss != "" && iss != idp.Issuer()) {
		return fail("LOGIN_FAILED", "iss mismatch (RFC 9207)", nil)
	}
	claims, err := idp.Exchange(ctx, params.Get("code"), deref(p.verifier), redirectURI)
	if err != nil {
		return fail("LOGIN_FAILED", "code exchange or ID token", err)
	}
	switch {
	case p.nonceHash != nil:
		// Sign-ins without an org keep only the nonce's hash (D41).
		if subtle.ConstantTimeCompare(credential.HashString(claims.Nonce), p.nonceHash) != 1 {
			return fail("LOGIN_FAILED", "nonce", nil)
		}
	case p.nonce == nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(*p.nonce)) != 1:
		return fail("LOGIN_FAILED", "nonce", nil)
	}
	if p.maxAge > 0 && (claims.AuthTime.IsZero() || claims.AuthTime.Before(now.Add(-p.maxAge-authTimeSkew))) {
		return fail("LOGIN_FAILED", "auth_time missing or older than max_age", nil)
	}
	return claims, nil
}
