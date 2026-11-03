// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ExternalStart is a stored sign-in for a protocol verified outside this
// package (G0 M26 D405, SAML).
type ExternalStart struct {
	State, Binding string
	Expires        time.Time
}

// StartExternal stores a sign-in with the same rules as Start: single use,
// bound to this browser by Binding, only for a next page ValidReturnPath
// accepts (HR-152), and capped per org. requestID is what the provider must
// answer to.
func (b *Browser) StartExternal(ctx context.Context, org ids.OrgID, provider, requestID, next, clientIP string) (ExternalStart, error) {
	if next == "" {
		next = AccountPath
	}
	if !ValidReturnPath(next) {
		return ExternalStart{}, ErrSignInUnavailable
	}
	state, err := credential.New(credential.LoginState, "", org)
	if err != nil {
		return ExternalStart{}, err
	}
	binding, err := credential.Secret()
	if err != nil {
		return ExternalStart{}, err
	}
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			return ErrSignInUnavailable
		}
		n, err := q.InsertLoginRequest(ctx, dbq.InsertLoginRequestParams{
			OrgID: org.UUID(), ID: ids.NewV7(), StateHash: state.Hash(), BindingHash: credential.HashString(binding),
			Nonce: requestID, Provider: provider, NextPath: next, RequestedIp: trim(clientIP, 64),
			TtlSeconds: int32(LoginRequestTTL / time.Second), MaxOpen: maxOpenLoginRequests,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrSignInBusy
		}
		return nil
	})
	if err != nil {
		return ExternalStart{}, err
	}
	return ExternalStart{State: state.Reveal(), Binding: binding, Expires: b.clock.Now().Add(LoginRequestTTL)}, nil
}

// ConsumeExternal takes a stored sign-in once, whatever follows. It is
// ErrBadCallback when the sign-in is unknown, used, expired, of another
// provider or of another browser.
func (b *Browser) ConsumeExternal(ctx context.Context, org ids.OrgID, provider, stateValue, binding string) (requestID, next string, err error) {
	state, err := credential.Parse(credential.LoginState, stateValue)
	if err != nil || state.Org() != org {
		return "", "", ErrBadCallback
	}
	var row dbq.ConsumeLoginStateRow
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		row, err = dbq.New(tx).ConsumeLoginState(ctx, org, state.Hash())
		return notFoundAs(err, ErrBadCallback)
	})
	if err != nil {
		return "", "", err
	}
	if row.Provider != provider || row.Nonce == nil || binding == "" ||
		subtle.ConstantTimeCompare(row.BindingHash, credential.HashString(binding)) != 1 {
		return "", "", ErrBadCallback
	}
	return *row.Nonce, row.NextPath, nil
}

// FinishExternal opens a session for an identity another protocol verified.
// A refusal is out.Reason, logged as for an OpenID sign-in.
func (b *Browser) FinishExternal(ctx context.Context, org ids.OrgID, provider string, claims IDClaims, next string, meta ClientMeta) (BrowserSignIn, error) {
	if !ValidReturnPath(next) {
		return BrowserSignIn{}, errors.New("authn: an external sign-in's next page was not validated")
	}
	out, err := b.openSession(ctx, org, claims, provider, next, false, meta)
	if err != nil {
		return BrowserSignIn{}, err
	}
	if out.Reason != "" {
		b.log.LogAttrs(ctx, slog.LevelWarn, "authn.browser_login_denied", slog.String("reason", out.Reason),
			slog.String("org", org.String()), slog.String("provider", provider))
	}
	return out, nil
}
