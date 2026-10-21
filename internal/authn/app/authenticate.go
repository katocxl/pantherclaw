// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the authentication use cases (SB-2, ADR-0016): turning
// a bearer credential into an authenticated caller on every request, the
// OAuth token endpoint grants and the CLI device flow.
package app

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrUnauthenticated is the only error a client sees for a bad credential,
// whatever the reason (the reason is logged): no oracle for which part of a
// credential was wrong.
var ErrUnauthenticated = pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "invalid or expired credentials")

// MaxBearerLen bounds a bearer credential before any parsing.
const MaxBearerLen = 8 << 10

// Authenticator authenticates bearer credentials: PantherClaw access tokens
// and pck_ API keys.
type Authenticator struct {
	pool   *db.Pool
	tokens *token.Service
	env    credential.Env
	clock  clock.Clock
	log    *slog.Logger
}

// NewAuthenticator returns an Authenticator. env is the API key environment
// this deployment accepts (keys of other environments are refused).
func NewAuthenticator(pool *db.Pool, tokens *token.Service, env credential.Env, clk clock.Clock, log *slog.Logger) (*Authenticator, error) {
	if pool == nil || tokens == nil || !env.Valid() || clk == nil {
		return nil, errors.New("authn: pool, token service, API key environment and clock are required")
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Authenticator{pool: pool, tokens: tokens, env: env, clock: clk, log: log}, nil
}

// failure is a rejected credential with its log reason.
type failure struct{ reason string }

func (f failure) Error() string { return "authn: " + f.reason }

func reject(reason string) error { return failure{reason: reason} }

// Authenticate resolves bearer to a caller. It verifies the credential, then,
// in one tenant transaction for the credential's org, checks that the org,
// the principal and its session, key or API key are all still active, and
// loads the principal's role bindings. Every failure returns
// ErrUnauthenticated; the reason is logged without the credential.
func (a *Authenticator) Authenticate(ctx context.Context, bearer string) (tapp.Caller, error) {
	var c tapp.Caller
	var err error
	switch {
	case len(bearer) == 0 || len(bearer) > MaxBearerLen:
		err = reject("malformed")
	case strings.HasPrefix(bearer, string(credential.APIKey)+"_"):
		c, err = a.apiKey(ctx, bearer)
	default:
		c, err = a.accessToken(ctx, bearer)
	}
	if err != nil {
		var f failure
		if errors.As(err, &f) || errors.Is(err, token.ErrInvalid) {
			a.log.WarnContext(ctx, "authn.failed", slog.String(pclog.KeyOutcome, "rejected"), slog.String("reason", reasonOf(err)))
			return tapp.Caller{}, ErrUnauthenticated
		}
		return tapp.Caller{}, err // database or internal failure: not the client's fault
	}
	return c, nil
}

func reasonOf(err error) string {
	var f failure
	if errors.As(err, &f) {
		return f.reason
	}
	return "token_invalid"
}

func (a *Authenticator) apiKey(ctx context.Context, bearer string) (tapp.Caller, error) {
	tok, err := credential.Parse(credential.APIKey, bearer)
	if err != nil {
		return tapp.Caller{}, reject("api_key_malformed")
	}
	if tok.Env() != a.env {
		return tapp.Caller{}, reject("api_key_wrong_environment")
	}
	var c tapp.Caller
	err = a.pool.InTenantTx(ctx, tok.Org(), func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, tok.Org()); err != nil {
			return err
		}
		k, err := q.AuthAPIKey(ctx, tok.Org(), tok.Hash())
		switch {
		case db.IsNoRows(err):
			return reject("api_key_unknown")
		case err != nil:
			return err
		case k.KeyState != "ACTIVE":
			return reject("api_key_revoked")
		case !k.Live:
			return reject("api_key_expired")
		case td.AccountState(k.AccountState) != td.Enabled:
			return reject("service_account_disabled")
		}
		if k.Touch {
			if err := q.TouchAPIKey(ctx, tok.Org(), k.ID); err != nil {
				return err
			}
		}
		p := td.PrincipalRef{Kind: td.KindServiceAccount, ID: k.ServiceAccountID}
		bs, err := tapp.Bindings(ctx, q, tok.Org(), p)
		if err != nil {
			return err
		}
		scopes := make([]td.Permission, len(k.Scopes))
		for i, s := range k.Scopes {
			scopes[i] = td.Permission(s)
		}
		c = tapp.Caller{
			Subject:    td.Subject{Org: tok.Org(), Principal: p, Bindings: bs, Scopes: scopes},
			Credential: tapp.CredAPIKey, CredentialID: k.ID,
		}
		return nil
	})
	return c, err
}

func (a *Authenticator) accessToken(ctx context.Context, bearer string) (tapp.Caller, error) {
	v, err := a.tokens.Verify(bearer, a.clock.Now())
	if err != nil {
		return tapp.Caller{}, err
	}
	var c tapp.Caller
	err = a.pool.InTenantTx(ctx, v.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, v.Org); err != nil {
			return err
		}
		switch v.Principal.Kind {
		case td.KindUser:
			s, err := q.AuthUserSession(ctx, v.Org, v.Principal.ID, v.Session)
			switch {
			case db.IsNoRows(err):
				return reject("session_unknown")
			case err != nil:
				return err
			case td.AccountState(s.UserState) != td.Enabled:
				return reject("user_disabled")
			case s.SessionState != "ACTIVE":
				return reject("session_revoked")
			case !s.Live:
				return reject("session_expired")
			}
		case td.KindServiceAccount:
			s, err := q.AuthServiceAccountKey(ctx, v.Org, v.Principal.ID, v.Session)
			switch {
			case db.IsNoRows(err):
				return reject("key_unknown")
			case err != nil:
				return err
			case td.AccountState(s.AccountState) != td.Enabled:
				return reject("service_account_disabled")
			case s.KeyState != "ACTIVE":
				return reject("key_revoked")
			case !s.Live:
				return reject("key_expired")
			}
		default:
			return reject("principal_kind")
		}
		bs, err := tapp.Bindings(ctx, q, v.Org, v.Principal)
		if err != nil {
			return err
		}
		c = tapp.Caller{
			Subject:    td.Subject{Org: v.Org, Principal: v.Principal, Bindings: bs},
			Credential: tapp.CredAccessToken,
		}
		if v.Principal.Kind == td.KindUser {
			c.Session = v.Session
		} else {
			c.CredentialID = v.Session // the service account's key
		}
		return nil
	})
	return c, err
}

func orgActive(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	state, err := q.OrgState(ctx, org)
	switch {
	case db.IsNoRows(err):
		return reject("org_unknown")
	case err != nil:
		return err
	case state != "ACTIVE":
		return reject("org_inactive")
	}
	return nil
}
