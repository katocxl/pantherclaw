// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports are the outside world of IdP-native agent access (G0 M26
// D400, D402).
package ports

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// AssertionVerifier verifies an assertion against an issuer the org trusts.
// It checks the signature with the issuer's published keys and every claim
// rule of the assertion format; replay, the client binding and the grant are
// the use case's. A refused assertion is domain.ErrAssertion; an issuer that
// can't be reached refuses too.
type AssertionVerifier interface {
	Verify(ctx context.Context, raw string, issuer domain.Issuer, now time.Time) (domain.Assertion, error)
}

// Discovery reads an issuer's metadata before a person files it, over HTTPS
// through the egress guard. It says only whether it is acceptable, so it is
// no probe of what the server can reach (HR-483).
type Discovery interface {
	Check(ctx context.Context, issuerURL string) error
}

// ClientMetadata is a Client ID Metadata Document's content that the
// authorization endpoint uses. It is UNTRUSTED display text and redirect
// URIs; its key material is never read (D408.2).
type ClientMetadata struct {
	ClientID     string
	Name         string
	RedirectURIs []string
	// DPoPBound is the document's "dpop_bound_access_tokens": the client
	// asks that every token it gets be DPoP-bound (G0 M30 D911).
	DPoPBound bool
}

// Client kinds an access token names.
const (
	ClientAssertion = "assertion"
	ClientMcp       = "mcp"
)

// AccessClaims are what a pap-mcp+jwt says (D402, D408.1): one run of one
// agent's client instance, at one protected resource.
type AccessClaims struct {
	Org         ids.OrgID
	Environment ids.UUID
	Agent       ids.UUID
	Instance    ids.UUID
	Run         ids.UUID
	// Connection and Resource are the one gateway server the token is for.
	Connection string
	Resource   string
	// ClientKind and Client name the binding or allow-listed client the
	// Authority re-checks on every call.
	ClientKind string
	Client     ids.UUID
	// Scope is the run's narrowed operations; empty is the whole grant.
	Scope []string
	// JKT is the thumbprint of the DPoP key the token is bound to (cnf.jkt);
	// empty is a bearer token (G0 M30 D912).
	JKT string
}

// Minter signs access tokens with the mcp_tokens keys.
type Minter interface {
	Mint(ctx context.Context, c AccessClaims, now time.Time) (token string, expires time.Time, err error)
}

// ClientDocuments fetches a client's metadata document over HTTPS through
// the egress guard, size-capped and cached.
type ClientDocuments interface {
	Fetch(ctx context.Context, clientURL string) (ClientMetadata, error)
}
