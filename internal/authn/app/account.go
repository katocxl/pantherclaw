// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Account errors (API).
var (
	// ErrUsersOnly: service accounts and API keys have no sessions or keys.
	ErrUsersOnly = pcerr.New(pcerr.PermissionDenied, "USERS_ONLY", "only people have sessions and security keys")
	// ErrNoSuchSession: the session is not the user's (or does not exist).
	ErrNoSuchSession = pcerr.New(pcerr.NotFound, "SESSION_NOT_FOUND", "session not found")
	// ErrNoSuchKey: the key is not the user's (or does not exist).
	ErrNoSuchKey = pcerr.New(pcerr.NotFound, "SECURITY_KEY_NOT_FOUND", "security key not found")
)

// SessionKind says how a session was created.
type SessionKind string

// Session kinds.
const (
	SessionBrowser SessionKind = "browser"
	SessionCLI     SessionKind = "cli"
)

// SessionView is one browser or CLI session in an account listing.
type SessionView struct {
	ID        ids.UUID
	Kind      SessionKind
	Device    string // user agent or CLI device name: untrusted
	Address   string // browser sessions: untrusted
	Active    bool
	EndReason string
	CreatedAt time.Time
	LastSeen  *time.Time
	ExpiresAt time.Time
}

// Account implements AccountService: people's own sessions and keys, and
// their administration (HR-150, HR-155, T-043: an administrator can sign a
// person out or remove a key, never act as them or add a key for them).
type Account struct {
	pool   *db.Pool
	wa     *WebAuthn // nil when security keys are off
	notify SecurityNotifier
}

// NewAccount returns the account use cases; wa and notify may be nil.
func NewAccount(pool *db.Pool, wa *WebAuthn, notify SecurityNotifier) *Account {
	return &Account{pool: pool, wa: wa, notify: notify}
}

// self returns the caller when it is a person.
func self(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if c.Principal.Kind != td.KindUser {
		return c, ErrUsersOnly
	}
	return c, nil
}

// admin returns the caller when it holds perm at org scope, and checks that
// the target user exists in the org.
func (a *Account) admin(ctx context.Context, perm td.Permission, user ids.UUID) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	err = a.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).GetUser(ctx, c.Org, user)
		return notFoundAs(err, tapp.ErrUserNotFound)
	}, db.ReadOnly())
	return c, err
}

// ListMySessions lists the caller's sessions.
func (a *Account) ListMySessions(ctx context.Context) ([]SessionView, error) {
	c, err := self(ctx)
	if err != nil {
		return nil, err
	}
	return a.sessions(ctx, c.Org, c.Principal.ID)
}

// ListUserSessions lists a user's sessions (user.read).
func (a *Account) ListUserSessions(ctx context.Context, user ids.UUID) ([]SessionView, error) {
	c, err := a.admin(ctx, td.PermUserRead, user)
	if err != nil {
		return nil, err
	}
	return a.sessions(ctx, c.Org, user)
}

func (a *Account) sessions(ctx context.Context, org ids.OrgID, user ids.UUID) ([]SessionView, error) {
	var out []SessionView
	err := a.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		browser, err := q.ListUserBrowserSessions(ctx, int32(BrowserSessionIdle/time.Second), org, user)
		if err != nil {
			return err
		}
		for _, s := range browser {
			seen := s.LastSeenAt
			out = append(out, SessionView{
				ID: s.ID, Kind: SessionBrowser, Device: s.UserAgent, Address: s.ClientIp, Active: s.Live,
				EndReason: deref(s.EndReason), CreatedAt: s.CreatedAt, LastSeen: &seen, ExpiresAt: s.ExpiresAt,
			})
		}
		cli, err := q.ListUserCLISessions(ctx, org, user)
		if err != nil {
			return err
		}
		for _, s := range cli {
			out = append(out, SessionView{
				ID: s.ID, Kind: SessionCLI, Device: s.DeviceName, Active: s.Live, EndReason: deref(s.RevokeReason),
				CreatedAt: s.CreatedAt, LastSeen: s.RefreshedAt, ExpiresAt: s.ExpiresAt,
			})
		}
		return nil
	}, db.ReadOnly())
	slices.SortFunc(out, func(x, y SessionView) int { return y.CreatedAt.Compare(x.CreatedAt) })
	if len(out) > 100 {
		out = out[:100]
	}
	return out, err
}

// RevokeMySession ends one of the caller's browser or CLI sessions.
func (a *Account) RevokeMySession(ctx context.Context, id ids.UUID) error {
	c, err := self(ctx)
	if err != nil {
		return err
	}
	return a.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		reason := "REVOKED"
		kind := "browser_session"
		n, err := q.EndUserBrowserSession(ctx, dbq.EndUserBrowserSessionParams{Reason: &reason, OrgID: c.Org, ID: id, UserID: c.Principal.ID})
		if err != nil {
			return err
		}
		if n == 0 {
			kind = "cli_session"
			if n, err = q.RevokeUserCLISession(ctx, dbq.RevokeUserCLISessionParams{Reason: &reason, OrgID: c.Org, ID: id, UserID: c.Principal.ID}); err != nil {
				return err
			}
		}
		if n == 0 {
			b, err1 := q.UserBrowserSessionExists(ctx, c.Org, id, c.Principal.ID)
			l, err2 := q.UserCLISessionExists(ctx, c.Org, id, c.Principal.ID)
			if err1 != nil || err2 != nil {
				return firstErr(err1, err2)
			}
			if !b && !l {
				return ErrNoSuchSession
			}
			return nil // already ended
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.AuthnSessionEnded, Actor: c.Actor(), Outcome: audit.Success, ReasonCode: reason,
			Object: &audit.Object{Type: kind, ID: id.String()},
		})
		return err
	})
}

// RevokeUserSessions ends every session of a user (user.manage), audits
// it and tells the user.
func (a *Account) RevokeUserSessions(ctx context.Context, user ids.UUID) (int, error) {
	c, err := a.admin(ctx, td.PermUserManage, user)
	if err != nil {
		return 0, err
	}
	var total int64
	err = a.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		reason := "ADMIN_REVOKED"
		b, err := q.EndAllUserBrowserSessions(ctx, &reason, c.Org, user)
		if err != nil {
			return err
		}
		l, err := q.RevokeAllUserCLISessions(ctx, &reason, c.Org, user)
		if err != nil {
			return err
		}
		total = b + l
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.AuthnSessionsRevoked, Actor: c.Actor(), Outcome: audit.Success, ReasonCode: reason,
			Object:  &audit.Object{Type: "user", ID: user.String()},
			Details: map[string]string{"browser": strconv.FormatInt(b, 10), "cli": strconv.FormatInt(l, 10)},
		}); err != nil {
			return err
		}
		if total == 0 || a.notify == nil {
			return nil
		}
		return a.notify.SecurityNotice(ctx, tx, SecurityNotice{
			Org: c.Org, User: user, Type: "security.sessions_revoked", Count: int(total), Actor: c.Actor(),
		})
	})
	return int(total), err
}

// ListMyKeys lists the caller's keys.
func (a *Account) ListMyKeys(ctx context.Context) ([]CredentialInfo, error) {
	c, err := self(ctx)
	if err != nil {
		return nil, err
	}
	if a.wa == nil {
		return nil, nil // security keys are off in this deployment
	}
	return a.wa.ListUserCredentials(ctx, c.Org, c.Principal.ID)
}

// ListUserKeys lists a user's keys (user.read).
func (a *Account) ListUserKeys(ctx context.Context, user ids.UUID) ([]CredentialInfo, error) {
	c, err := a.admin(ctx, td.PermUserRead, user)
	if err != nil {
		return nil, err
	}
	if a.wa == nil {
		return nil, nil
	}
	return a.wa.ListUserCredentials(ctx, c.Org, user)
}

// RemoveUserKey removes a user's key (user.manage), audited, and tells the
// user. Adding a key is never possible for someone else.
func (a *Account) RemoveUserKey(ctx context.Context, user, key ids.UUID) error {
	c, err := a.admin(ctx, td.PermUserManage, user)
	if err != nil {
		return err
	}
	if a.wa == nil {
		return ErrNoSuchKey
	}
	err = a.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return a.wa.remove(ctx, tx, dbq.New(tx), c.Org, user, key, "ADMIN_REMOVED", c.Actor())
	})
	if errors.Is(err, ErrCredentialNotFound) {
		return ErrNoSuchKey
	}
	return err
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
