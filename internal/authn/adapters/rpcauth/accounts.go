// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth

import (
	"context"
	"log/slog"
	"net/http"
	"slices"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/accounts"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Hosted accounts on the API (G0 UI D8; HR-350): an account session (the
// account cookie, no org) may call only the allow-listed procedures, with
// the same browser-request checks as an org session (HR-342); and an org
// browser session may list its account's orgs and accept invitations for
// it, the account procedures that are not CreateOrg.

// AccountSessions authenticates account cookies and finds the account of
// an org user (authn/app.Browser).
type AccountSessions interface {
	AuthenticateAccount(ctx context.Context, cookie string) (authnapp.AccountSession, error)
	UserAccount(ctx context.Context, org ids.OrgID, user ids.UUID) (ids.UUID, bool, error)
}

// accountOnly are the procedures' requirements that belong to an account,
// not to a role (declarable only).
var accountOnly = []td.Permission{td.PermOrgsCreate, td.PermOrgsListMine, td.PermInvitationsAccept, td.PermAccountDelete, td.PermDeletionRecordsRead}

// WithAccountSessions accepts account sessions (cookie cookieName) and
// gives org browser sessions their account for the account procedures.
func WithAccountSessions(a AccountSessions, cookieName, publicOrigin string) Option {
	return func(o *options) {
		o.accounts, o.accountCookie, o.accountOrigin = a, cookieName, publicOrigin
	}
}

// accountCookieValue returns the account cookie among Cookie header lines.
func (o *options) accountCookieValue(lines []string) (string, bool) {
	if o.accounts == nil {
		return "", false
	}
	for _, line := range lines {
		cs, err := http.ParseCookie(line)
		if err != nil {
			continue
		}
		for _, c := range cs {
			if c.Name == o.accountCookie && c.Value != "" {
				return c.Value, true
			}
		}
	}
	return "", false
}

// accountCall authenticates an account session for an allow-listed
// procedure and puts its caller in the context; there is no org caller,
// so every org-scoped use case refuses it.
func (o *options) accountCall(ctx context.Context, info *connect.CallInfo, spec connect.Spec, cookie string) (context.Context, error) {
	if !accounts.AllowedProcedure(spec.Procedure) {
		return nil, td.ErrPermissionDenied(td.PermAuthenticated)
	}
	if !browserRequestOK(info, spec, o.accountOrigin) {
		o.log.WarnContext(ctx, "rpc.browser_request_refused", slog.String("procedure", spec.Procedure), slog.String("session", "account"))
		return nil, ErrBrowserRequest
	}
	s, err := o.accounts.AuthenticateAccount(ctx, cookie)
	if err != nil {
		return nil, errAuthRequired
	}
	c := s.Caller
	c.IP = httpx.ClientIPFrom(ctx) // the trusted-proxy-aware address (D85)
	return accounts.WithCaller(audit.WithAuthKind(ctx, "account_session"), c), nil
}

// orgAccountCall lets an org browser session call an account procedure
// other than CreateOrg for the account its user is linked to.
func (o *options) orgAccountCall(ctx context.Context, c tapp.Caller, perm td.Permission) (context.Context, bool, error) {
	if o.accounts == nil || !slices.Contains(accountOnly, perm) {
		return ctx, false, nil
	}
	if perm == td.PermOrgsCreate || c.Credential != tapp.CredBrowserSession || !c.Human() {
		return nil, true, td.ErrPermissionDenied(perm)
	}
	account, ok, err := o.accounts.UserAccount(ctx, c.Org, c.Principal.ID)
	if err != nil {
		return nil, true, err
	}
	if !ok {
		return nil, true, td.ErrPermissionDenied(perm)
	}
	ctx = accounts.WithCaller(ctx, accounts.Caller{Account: account, Session: c.Session, IP: httpx.ClientIPFrom(ctx)})
	return tapp.WithCaller(ctx, c), true, nil
}
