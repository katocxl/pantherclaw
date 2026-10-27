// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Support sessions on the API (G0 M13 D32, D38; HR-385, HR-387, HR-388):
// the console's session cookie may hold a support session instead of a
// browser session. It goes through the same browser-request checks
// (HR-342), is authenticated by the support service, which records the
// call in the org's audit ledger first, and may call read procedures only:
// a support session never changes anything, whatever a permission would
// allow.

// SupportSessions authenticates support session cookies (support.Service).
type SupportSessions interface {
	Authenticate(ctx context.Context, cookie, procedure string) (tapp.Caller, error)
}

// ErrSupportReadOnly refuses a support session's call to a procedure that
// is not a read (HR-387).
var ErrSupportReadOnly = pcerr.New(pcerr.PermissionDenied, "SUPPORT_READ_ONLY", "a support session can only read")

// WithSupportSessions accepts support sessions in the console's cookie;
// readOnly says which procedures they may call.
func WithSupportSessions(s SupportSessions, readOnly func(procedure string) bool) Option {
	return func(o *options) { o.support, o.supportReadOnly = s, readOnly }
}

// BreakGlassCalls adds the holder's currently active emergency role and
// records the call before the permission check (HR-389).
type BreakGlassCalls interface {
	BreakGlassCall(context.Context, tapp.Caller, string) (tapp.Caller, error)
}

// WithBreakGlass audits calls under an emergency activation. It applies
// independently of the hosted support staff feature.
func WithBreakGlass(b BreakGlassCalls) Option { return func(o *options) { o.breakGlass = b } }

// WithSupportAndBreakGlass configures both M13 authentication paths.
func WithSupportAndBreakGlass(s interface {
	SupportSessions
	BreakGlassCalls
}, readOnly func(string) bool,
) Option {
	return func(o *options) {
		WithSupportSessions(s, readOnly)(o)
		WithBreakGlass(s)(o)
	}
}

// isSupportCookie reports whether the cookie holds a support session.
func isSupportCookie(v string) bool {
	_, err := credential.Parse(credential.SupportSession, v)
	return err == nil
}

// supportCall authenticates a support session's console call.
func (o *options) supportCall(ctx context.Context, info *connect.CallInfo, spec connect.Spec, cookie string) (context.Context, tapp.Caller, error) {
	if !browserRequestOK(info, spec, o.sessions.PublicOrigin()) {
		o.log.WarnContext(ctx, "rpc.browser_request_refused", slog.String("procedure", spec.Procedure), slog.String("session", "support"))
		return nil, tapp.Caller{}, ErrBrowserRequest
	}
	c, err := o.support.Authenticate(ctx, cookie, spec.Procedure)
	if err != nil {
		return nil, tapp.Caller{}, errAuthRequired
	}
	if o.supportReadOnly == nil || !o.supportReadOnly(spec.Procedure) {
		return nil, tapp.Caller{}, ErrSupportReadOnly
	}
	return audit.WithAuthKind(ctx, string(tapp.CredSupportSession)), c, nil
}
