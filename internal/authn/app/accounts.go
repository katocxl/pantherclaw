// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Sign-in without an org (G0 UI D8, HR-348..353).
const (
	// OrgPickerPath is the server-rendered org picker after a sign-in
	// without an org that found several memberships.
	OrgPickerPath = "/login/orgs"
	// InvitePath is the browser invitation page: /invite/{token}.
	InvitePath = "/invite"
	// PickerFreshness is how soon after its sign-in an account session may
	// pick an org (HR-353, D88: switching orgs later is a fresh sign-in).
	PickerFreshness = 15 * time.Minute
	// maxOpenAccountLoginRequests caps the pending sign-ins without an org.
	maxOpenAccountLoginRequests = 50_000
	// MaxAccountSessions is the most active account sessions per account.
	MaxAccountSessions = 10
)

// Session kinds of a browser sign-in's result.
const (
	SessionOrg     = "org"
	SessionAccount = "account"
)

// ErrNotPickable: the org is not one of the account's.
var ErrNotPickable = errors.New("authn: this organization cannot be opened from this session")

// ErrPickerStale: the account session signed in more than PickerFreshness
// ago; picking an org now takes a fresh sign-in (HR-353, D88).
var ErrPickerStale = errors.New("authn: this sign-in is too old to open an organization")

// PickerFresh reports whether s may still pick an org (HR-353).
func PickerFresh(s AccountSession) bool {
	return !s.CreatedAt.Before(s.Now.Add(-PickerFreshness))
}

// WithAccounts enables sign-in without an org: store resolves accounts,
// invites accepts invitations carried by a sign-in, and selfServe opens an
// account session for an account without an org (else NOT_A_MEMBER).
func (b *Browser) WithAccounts(store *accounts.Store, invites *accounts.Invitations, selfServe bool) *Browser {
	b.accounts, b.invites, b.selfServe = store, invites, selfServe
	return b
}

// AccountsEnabled reports whether sign-in without an org is available.
func (b *Browser) AccountsEnabled() bool { return b.accounts != nil }

func accountRouting() ids.OrgID { return ids.PlatformOrg }

// startAccount records a pending sign-in without an org; invitation, when
// set, is an invitation token to accept after it (only its hash is kept).
func (b *Browser) startAccount(ctx context.Context, idp IdP, next, invitation, clientIP string, recent bool) (Redirect, error) {
	if b.accounts == nil {
		return Redirect{}, ErrSignInUnavailable
	}
	var invOrg *ids.UUID
	var invHash []byte
	if invitation != "" {
		tok, err := credential.Parse(credential.Invitation, invitation)
		if err != nil {
			return Redirect{}, ErrSignInUnavailable
		}
		u := tok.Org().UUID()
		invOrg, invHash = &u, tok.Hash()
	}
	state, err := credential.New(credential.AccountLoginState, "", accountRouting())
	if err != nil {
		return Redirect{}, err
	}
	nonce, err1 := credential.Secret()
	verifier, err2 := credential.Secret()
	binding, err3 := credential.Secret()
	if err := errors.Join(err1, err2, err3); err != nil {
		return Redirect{}, err
	}
	req := AuthRequest{State: state.Reveal(), Nonce: nonce, Verifier: verifier, RedirectURI: b.redirectURI(idp.Name())}
	var maxAge *int32
	if recent {
		req.MaxAge = RecentSignIn
		s := int32(RecentSignIn / time.Second)
		maxAge = &s
	}
	err = b.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		n, err := dbq.New(tx).InsertAccountLoginRequest(ctx, dbq.InsertAccountLoginRequestParams{
			ID: ids.NewV7(), StateHash: state.Hash(), BindingHash: credential.HashString(binding),
			NonceHash: credential.HashString(nonce), PkceVerifier: verifier, Provider: idp.Name(), NextPath: next,
			MaxAge: maxAge, RequestedIp: trim(clientIP, 64), TtlSeconds: int32(LoginRequestTTL / time.Second),
			InvitationOrgID: invOrg, InvitationTokenHash: invHash, MaxOpen: maxOpenAccountLoginRequests,
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
		return Redirect{}, err
	}
	u, err := idp.AuthCodeURL(ctx, req)
	if err != nil {
		return Redirect{}, err
	}
	return Redirect{URL: u, Binding: binding}, nil
}

// accountCallback completes a sign-in without an org: the state is
// consumed first, the callback verified like any sign-in, the account
// resolved by (issuer, subject) and then, in order: a carried invitation is
// accepted and its org opened; one membership opens that org; several, or
// none with self-serve on, open an account session (the picker, or
// creating an org); none without self-serve is NOT_A_MEMBER.
func (b *Browser) accountCallback(ctx context.Context, idp IdP, providerName string, params url.Values, binding string,
	meta ClientMeta,
) (BrowserSignIn, error) {
	if b.accounts == nil {
		return BrowserSignIn{}, ErrBadCallback
	}
	state, err := credential.Parse(credential.AccountLoginState, params.Get("state"))
	if err != nil || state.Org() != accountRouting() {
		return BrowserSignIn{}, ErrBadCallback
	}
	var row dbq.ConsumeAccountLoginStateRow
	err = b.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		row, err = dbq.New(tx).ConsumeAccountLoginState(ctx, state.Hash())
		return notFoundAs(err, ErrBadCallback)
	})
	if err != nil {
		return BrowserSignIn{}, err
	}
	refuse := func(reason, detail string, err error) (BrowserSignIn, error) {
		attrs := []slog.Attr{slog.String("reason", reason), slog.String("provider", providerName), slog.String("flow", "account")}
		if detail != "" {
			attrs = append(attrs, slog.String("detail", detail))
		}
		if err != nil {
			attrs = append(attrs, pclog.Err(err))
		}
		b.log.LogAttrs(ctx, slog.LevelWarn, "authn.browser_login_denied", attrs...)
		return BrowserSignIn{Reason: reason}, nil
	}
	pending := pendingSignIn{provider: row.Provider, bindingHash: row.BindingHash, nonceHash: row.NonceHash, verifier: row.PkceVerifier}
	if pending.nonceHash == nil {
		pending.nonceHash = []byte{} // never matches: a consumed row has no nonce
	}
	if row.MaxAge != nil {
		pending.maxAge = time.Duration(*row.MaxAge) * time.Second
	}
	claims, failed := verifySignIn(ctx, idp, b.redirectURI(providerName), providerName, params, binding, pending, b.clock.Now())
	if failed != nil {
		return refuse(failed.reason, failed.detail, failed.err)
	}
	acct, err := b.accounts.Resolve(ctx, accounts.Identity{
		Issuer: claims.Issuer, Subject: claims.Subject, Email: claims.Email,
		EmailVerified: claims.EmailVerified || idp.TrustEmail(), Name: claims.Name,
	}, meta.IP)
	if err != nil {
		return BrowserSignIn{}, err
	}
	authTime := claims.AuthTime
	recent := row.MaxAge != nil
	if row.InvitationOrgID != nil && row.InvitationTokenHash != nil {
		if b.invites == nil {
			return refuse("INVITATION_INVALID", "invitations not served", nil)
		}
		org, err := ids.FromUUID[ids.Org](*row.InvitationOrgID)
		if err != nil {
			return refuse("INVITATION_INVALID", "invitation org", nil)
		}
		got, err := b.invites.AcceptHash(ctx, acct.ID, org, row.InvitationTokenHash, meta.IP)
		if err != nil {
			if reason := reasonOfCode(err); reason != "" {
				return refuse(reason, "", nil)
			}
			return BrowserSignIn{}, err
		}
		return b.OpenOrgSession(ctx, got.Org, got.User, acct.ID, providerName, authTime, recent, meta, AccountPath)
	}
	ms, err := b.accounts.Memberships(ctx, acct.ID)
	if err != nil {
		return BrowserSignIn{}, err
	}
	switch {
	case len(ms) == 1:
		return b.OpenOrgSession(ctx, ms[0].Org, ms[0].User, acct.ID, providerName, authTime, recent, meta, row.NextPath)
	case len(ms) == 0 && !b.selfServe:
		return refuse("NOT_A_MEMBER", "account without an org", nil)
	}
	secret, id, err := b.openAccountSession(ctx, acct.ID, providerName, authTime, meta)
	if err != nil {
		return BrowserSignIn{}, err
	}
	next := row.NextPath
	if len(ms) > 1 {
		next = OrgPickerPath
	}
	return BrowserSignIn{Session: id, Secret: secret, Next: next, Kind: SessionAccount, Account: acct.ID}, nil
}

// reasonOfCode returns the stable reason of a refusal error from the
// account use cases, "" for an internal error.
func reasonOfCode(err error) string {
	for _, e := range []error{
		accounts.ErrInvitationInvalid, accounts.ErrEmailMismatch, accounts.ErrAlreadyMember, accounts.ErrMemberLimit,
	} {
		if errors.Is(err, e) {
			var r interface{ Reason() string }
			if errors.As(e, &r) {
				return r.Reason()
			}
		}
	}
	return ""
}

// OpenOrgSession opens a browser session in org for the account's user
// there (after a sign-in without an org, the org picker, an accepted
// invitation or a created org). The user must be enabled; it is linked to
// the account (HR-348 trigger) and the sign-in is recorded.
func (b *Browser) OpenOrgSession(ctx context.Context, org ids.OrgID, user, account ids.UUID, providerName string,
	authTime time.Time, recent bool, meta ClientMeta, next string,
) (BrowserSignIn, error) {
	secret, err := credential.New(credential.BrowserSession, "", org)
	if err != nil {
		return BrowserSignIn{}, err
	}
	if !ValidReturnPath(next) {
		next = AccountPath
	}
	out := BrowserSignIn{Org: org, Next: next, Kind: SessionOrg, Account: account}
	err = b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := orgActive(ctx, q, org); err != nil {
			out.Reason = "NOT_A_MEMBER"
			return nil //nolint:nilerr // an inactive org is the person's answer, not a failure
		}
		u, err := q.GetUser(ctx, org, user)
		switch {
		case db.IsNoRows(err):
			out.Reason = "NOT_A_MEMBER"
			return nil
		case err != nil:
			return err
		case td.AccountState(u.State) != td.Enabled:
			out.Reason = "USER_DISABLED"
			return nil
		}
		if !account.IsZero() {
			if err := accounts.LinkUser(ctx, tx, account, u.ID); err != nil {
				return err
			}
		}
		bs, err := tapp.Bindings(ctx, q, org, td.PrincipalRef{Kind: td.KindUser, ID: u.ID})
		if err != nil {
			return err
		}
		if err := q.EndDeadBrowserSessions(ctx, org, u.ID, int32(BrowserSessionIdle/time.Second)); err != nil {
			return err
		}
		if _, err := q.EndExcessBrowserSessions(ctx, org, u.ID, MaxBrowserSessions-1); err != nil {
			return err
		}
		var at *time.Time
		if !authTime.IsZero() {
			at = &authTime
		}
		out.Session = ids.NewV7()
		if _, err := q.InsertBrowserSession(ctx, dbq.InsertBrowserSessionParams{
			OrgID: org, ID: out.Session, UserID: u.ID, SecretHash: secret.Hash(), Provider: providerName, AuthTime: at,
			RolesDigest: rolesDigest(bs), UserAgent: td.SanitizeClaim(meta.UserAgent, 256), ClientIp: trim(meta.IP, 64),
			TtlSeconds: int32(BrowserSessionLifetime / time.Second),
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "authn.login", Actor: evdomain.Actor{Type: string(td.KindUser), ID: u.ID.String()}, Outcome: audit.Success,
			Object:  &audit.Object{Type: "browser_session", ID: out.Session.String()},
			Details: map[string]string{"method": "browser_account", "provider": providerName, "recent": boolString(recent)},
		})
		return err
	})
	if err != nil {
		return BrowserSignIn{}, err
	}
	if out.Reason != "" {
		b.log.WarnContext(ctx, "authn.browser_login_denied", slog.String("reason", out.Reason), slog.String("org", org.String()))
		return BrowserSignIn{Org: org, Reason: out.Reason}, nil
	}
	out.Secret = secret.Reveal()
	return out, nil
}

// openAccountSession starts an account session (HR-350).
func (b *Browser) openAccountSession(ctx context.Context, account ids.UUID, providerName string, authTime time.Time,
	meta ClientMeta,
) (string, ids.UUID, error) {
	secret, err := credential.New(credential.AccountSession, "", accountRouting())
	if err != nil {
		return "", ids.UUID{}, err
	}
	id := ids.NewV7()
	err = b.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		if _, err := q.EndExcessAccountSessions(ctx, account, MaxAccountSessions-1); err != nil {
			return err
		}
		var at *time.Time
		if !authTime.IsZero() {
			at = &authTime
		}
		if _, err := q.InsertAccountSession(ctx, dbq.InsertAccountSessionParams{
			ID: id, AccountID: account, SecretHash: secret.Hash(), Provider: providerName, AuthTime: at,
			UserAgent: td.SanitizeClaim(meta.UserAgent, 256), ClientIp: trim(meta.IP, 64),
			TtlSeconds: int32(BrowserSessionLifetime / time.Second),
		}); err != nil {
			return err
		}
		return q.InsertAccountEvent(ctx, dbq.InsertAccountEventParams{
			AccountID: account, Kind: "SESSION_STARTED", ClientIp: trim(meta.IP, 64), Detail: id.String(),
		})
	})
	if err != nil {
		return "", ids.UUID{}, err
	}
	return secret.Reveal(), id, nil
}

// AccountSession is a caller authenticated by an account session cookie.
type AccountSession struct {
	accounts.Caller
	Email         string
	EmailVerified bool
	DisplayName   string
	CreatedAt     time.Time
	// Now is the database clock at authentication.
	Now time.Time
}

// AuthenticateAccount resolves an account session cookie (HR-150 limits
// by the database clock). Every failure is ErrUnauthenticated.
func (b *Browser) AuthenticateAccount(ctx context.Context, cookie string) (AccountSession, error) {
	if b.accounts == nil {
		return AccountSession{}, ErrUnauthenticated
	}
	tok, err := credential.Parse(credential.AccountSession, cookie)
	if err != nil || tok.Org() != accountRouting() {
		return b.accountAuthFailed(ctx, "session_malformed")
	}
	var out AccountSession
	reason := ""
	err = b.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		s, err := q.AccountSessionBySecret(ctx, tok.Hash(), int32(RotationGrace/time.Second), int32(BrowserSessionIdle/time.Second))
		switch {
		case db.IsNoRows(err):
			reason = "session_unknown"
			return nil
		case err != nil:
			return err
		case s.State != "ACTIVE":
			reason = "session_ended"
			return nil
		case !s.Current:
			reason = "session_secret_reused"
			_, err := q.EndAccountSession(ctx, ptrString("REUSE"), s.ID)
			return err
		case !s.WithinLifetime:
			reason = "session_expired"
			_, err := q.EndAccountSession(ctx, ptrString("EXPIRED"), s.ID)
			return err
		case !s.WithinIdle:
			reason = "session_idle"
			_, err := q.EndAccountSession(ctx, ptrString("IDLE"), s.ID)
			return err
		}
		out = AccountSession{
			Caller: accounts.Caller{Account: s.AccountID, Session: s.ID, Provider: s.Provider},
			Email:  s.Email, EmailVerified: s.EmailVerified, DisplayName: s.DisplayName, CreatedAt: s.CreatedAt, Now: s.DbNow,
		}
		if s.AuthTime != nil {
			out.AuthTime = *s.AuthTime
		}
		if s.Touch {
			return q.TouchAccountSession(ctx, s.ID)
		}
		return nil
	})
	if err != nil {
		return AccountSession{}, err
	}
	if reason != "" {
		return b.accountAuthFailed(ctx, reason)
	}
	return out, nil
}

func (b *Browser) accountAuthFailed(ctx context.Context, reason string) (AccountSession, error) {
	b.log.WarnContext(ctx, "authn.account_session_rejected", slog.String(pclog.KeyOutcome, "rejected"), slog.String("reason", reason))
	return AccountSession{}, ErrUnauthenticated
}

// EndAccountSession ends an account session (sign-out, or after it picked
// an org or created one).
func (b *Browser) EndAccountSession(ctx context.Context, s AccountSession, reason string) error {
	return b.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		n, err := q.EndAccountSession(ctx, &reason, s.Session)
		if err != nil || n == 0 {
			return err
		}
		return q.InsertAccountEvent(ctx, dbq.InsertAccountEventParams{
			AccountID: s.Account, Kind: "SESSION_ENDED", Detail: reason + " " + s.Session.String(),
		})
	})
}

// Memberships lists the account session's orgs (the picker).
func (b *Browser) Memberships(ctx context.Context, s AccountSession) ([]accounts.Membership, error) {
	return b.accounts.Memberships(ctx, s.Account)
}

// PickOrg opens org for an account session that signed in moments ago
// (HR-353) and ends the account session.
func (b *Browser) PickOrg(ctx context.Context, s AccountSession, org ids.OrgID, meta ClientMeta) (BrowserSignIn, error) {
	if !PickerFresh(s) {
		return BrowserSignIn{}, ErrPickerStale
	}
	ms, err := b.accounts.Memberships(ctx, s.Account)
	if err != nil {
		return BrowserSignIn{}, err
	}
	for _, m := range ms {
		if m.Org == org {
			out, err := b.OpenOrgSession(ctx, org, m.User, s.Account, s.Provider, s.AuthTime, false, meta, AccountPath)
			if err != nil || out.Reason != "" {
				return out, err
			}
			return out, b.EndAccountSession(ctx, s, "ORG_SELECTED")
		}
	}
	return BrowserSignIn{}, ErrNotPickable
}

func ptrString(s string) *string { return &s }

// UserAccount returns the account org's user is linked to, if any.
func (b *Browser) UserAccount(ctx context.Context, org ids.OrgID, user ids.UUID) (ids.UUID, bool, error) {
	var out ids.UUID
	err := b.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		u, err := dbq.New(tx).GetUser(ctx, org, user)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		if u.AccountID != nil && td.AccountState(u.State) == td.Enabled {
			out = *u.AccountID
		}
		return nil
	}, db.ReadOnly())
	return out, !out.IsZero(), err
}
