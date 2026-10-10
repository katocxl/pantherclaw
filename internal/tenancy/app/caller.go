// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the tenancy use cases: the hierarchy (F573), users,
// invitations and role bindings (F581). Every use case reads the caller
// from the context (set by the authentication interceptor), runs in a tenant
// transaction for the caller's org, checks the permission at the exact
// scope of the resource, and audits every change in the same transaction
// (F585).
package app

import (
	"context"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Credential names how a caller authenticated.
type Credential string

// Credentials.
const (
	CredAccessToken Credential = "access_token"
	CredAPIKey      Credential = "api_key"
	// CredBrowserSession is a browser session of PantherClaw's own pages
	// (G0 M5).
	CredBrowserSession Credential = "browser_session"
)

// Caller is an authenticated principal with its current bindings.
type Caller struct {
	domain.Subject
	Credential Credential
	// Session is the CLI session a user's access token belongs to, or the
	// browser session of a page request (zero for API keys and service
	// accounts): the human session an approval response records (G0 M5
	// part 2, HR-172).
	Session ids.UUID
}

// Actor returns the audit actor for the caller.
func (c Caller) Actor() evdomain.Actor {
	return evdomain.Actor{Type: string(c.Principal.Kind), ID: c.Principal.ID.String()}
}

type callerKey struct{}

// WithCaller returns ctx carrying c. Only the authentication interceptor
// (and tests) call it.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// ErrNoCaller is returned when a use case runs without an authenticated
// caller; it is a wiring error and never reaches a client as anything but
// "authentication required".
var ErrNoCaller = pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "authentication required")

// CallerFrom returns the authenticated caller.
func CallerFrom(ctx context.Context) (Caller, error) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	if !ok || c.Org.IsZero() || c.Principal.ID.IsZero() {
		return Caller{}, ErrNoCaller
	}
	return c, nil
}
