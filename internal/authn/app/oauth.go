// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// AssertionType is the only client_assertion_type accepted (RFC 7523).
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// OAuthError is an RFC 6749 §5.2 error. Description never carries the
// detailed reason (that is logged).
type OAuthError struct {
	Code        string
	Description string
	Status      int
}

func (e *OAuthError) Error() string { return "oauth: " + e.Code }

// OAuth errors.
var (
	ErrInvalidRequest       = &OAuthError{Code: "invalid_request", Description: "the request is malformed", Status: 400}
	ErrInvalidClient        = &OAuthError{Code: "invalid_client", Description: "client authentication failed", Status: 401}
	ErrInvalidGrant         = &OAuthError{Code: "invalid_grant", Description: "the grant is invalid, expired or revoked", Status: 400}
	ErrUnsupportedGrantType = &OAuthError{Code: "unsupported_grant_type", Description: "unsupported grant_type", Status: 400}
	ErrSlowDown             = &OAuthError{Code: "slow_down", Description: "poll more slowly", Status: 400}
)

// TokenResponse is a successful token response (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitzero"`
	// Scope is the granted scope when it differs from the requested one
	// (RFC 6749 §5.1); IdP-native access tokens always carry it.
	Scope string `json:"scope,omitzero"`
	// RunID names the run an IdP-native access token is bound to (G0 M26
	// D400).
	RunID string `json:"run_id,omitzero"`
}

// OAuth implements the token endpoint grants.
type OAuth struct {
	pool      *db.Pool
	tokens    *token.Service
	issuer    string
	audiences []string
	clock     clock.Clock
	log       *slog.Logger
}

// NewOAuth returns the token endpoint use cases. issuer is the server's
// public URL; client assertions may name it or the token endpoint as aud.
func NewOAuth(pool *db.Pool, tokens *token.Service, issuer string, clk clock.Clock, log *slog.Logger) *OAuth {
	if log == nil {
		log = pclog.Discard()
	}
	return &OAuth{
		pool: pool, tokens: tokens, issuer: issuer, audiences: []string{issuer, issuer + TokenPath},
		clock: clk, log: log,
	}
}

// Endpoint paths, relative to the issuer.
const (
	TokenPath               = "/oauth2/token" //nolint:gosec // G101: an endpoint path, not a credential
	DeviceAuthorizationPath = "/oauth2/device_authorization"
	RevocationPath          = "/oauth2/revoke"
)

// failOAuth logs the detailed reason and returns the generic OAuth error.
func (o *OAuth) failOAuth(ctx context.Context, e *OAuthError, reason string, attrs ...slog.Attr) error {
	o.log.LogAttrs(ctx, slog.LevelWarn, "authn.token_failed",
		append([]slog.Attr{slog.String("error", e.Code), slog.String("reason", reason)}, attrs...)...)
	return e
}

// ClientCredentials implements the client-credentials grant for service
// accounts authenticated with private_key_jwt (RFC 7523, SB-2): the
// assertion is verified against the account's registered key with its
// pinned algorithm, its jti is recorded only after the signature verified
// (HR-090 ordering) and a replay is refused. The access token is bound to
// the key, so revoking the key revokes the token.
func (o *OAuth) ClientCredentials(ctx context.Context, clientID, assertionType, compact string) (TokenResponse, error) {
	if assertionType != AssertionType || compact == "" {
		return TokenResponse{}, o.failOAuth(ctx, ErrInvalidClient, "assertion_missing")
	}
	org, sa, err := credential.ParseClientID[td.ServiceAccount](clientID)
	if err != nil {
		return TokenResponse{}, o.failOAuth(ctx, ErrInvalidClient, "client_id_malformed")
	}
	kid, err := assertion.KeyID(compact)
	if err != nil {
		return TokenResponse{}, o.failOAuth(ctx, ErrInvalidClient, "assertion_malformed")
	}
	var out TokenResponse
	err = o.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			return err
		}
		k, err := q.AssertionKey(ctx, org, sa.UUID(), kid)
		switch {
		case db.IsNoRows(err):
			return reject("key_unknown")
		case err != nil:
			return err
		case td.AccountState(k.AccountState) != td.Enabled:
			return reject("service_account_disabled")
		case k.KeyState != "ACTIVE":
			return reject("key_revoked")
		case !k.Live:
			return reject("key_expired")
		}
		pk, err := assertion.ParsePublicJWK(assertion.Alg(k.Alg), k.PublicJwk)
		if err != nil {
			return err // a stored key that no longer parses is an internal error
		}
		v, err := assertion.Verify(compact, pk, assertion.Expect{ClientID: clientID, Audiences: o.audiences, Now: o.clock.Now()})
		if err != nil {
			return reject("assertion_invalid")
		}
		n, err := q.InsertAuthReplay(ctx, dbq.InsertAuthReplayParams{
			OrgID: org, Issuer: "sa:" + sa.String(), Jti: v.JTI, ExpiresAt: v.ExpiresAt,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return reject("assertion_replayed")
		}
		at, _, err := o.tokens.Issue(token.Grant{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: sa.UUID()}, Session: k.ID, ClientID: clientID,
		}, o.clock.Now())
		if err != nil {
			return err
		}
		out = TokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int(token.TTL.Seconds())}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "authn.token_issued", Actor: evdomain.Actor{Type: string(td.KindServiceAccount), ID: sa.String()},
			Outcome: audit.Success, Object: &audit.Object{Type: "service_account", ID: sa.String()},
			Details: map[string]string{"grant": "client_credentials", "key": k.ID.String()},
		})
		return err
	})
	var f failure
	if errors.As(err, &f) {
		return TokenResponse{}, o.failOAuth(ctx, ErrInvalidClient, f.reason, slog.String("org", org.String()))
	}
	return out, err
}
