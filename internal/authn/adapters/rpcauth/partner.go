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

// Partner sessions on the API (G0 M38 D1101; HR-811..813): the console's
// session cookie may hold a partner session of an MSSP partner person
// inside a customer org. It goes through the same browser-request checks
// as a support session (HR-342), is authenticated by the partners service,
// which re-checks the link and records the call in the customer's audit log
// first, and may call read procedures and PartnerService.ProposeRollout
// only, whatever a permission would allow.

// PartnerSessions authenticates partner session cookies (partners.Service).
type PartnerSessions interface {
	Authenticate(ctx context.Context, cookie, procedure string) (tapp.Caller, error)
}

// ErrPartnerReadOnly refuses a partner session's call to a procedure that
// is neither a read nor a proposal (HR-811).
var ErrPartnerReadOnly = pcerr.New(pcerr.PermissionDenied, "PARTNER_READ_ONLY",
	"a partner session can only read and propose rollouts")

// WithPartnerSessions accepts partner sessions in the console's cookie;
// mayCall says which procedures they may call.
func WithPartnerSessions(s PartnerSessions, mayCall func(procedure string) bool) Option {
	return func(o *options) { o.partner, o.partnerMayCall = s, mayCall }
}

// isPartnerCookie reports whether the cookie holds a partner session.
func isPartnerCookie(v string) bool {
	_, err := credential.Parse(credential.PartnerSession, v)
	return err == nil
}

// partnerCall authenticates a partner session's console call. The
// procedure is checked before the session is authenticated, so a refused
// call never counts as a partner call.
func (o *options) partnerCall(ctx context.Context, info *connect.CallInfo, spec connect.Spec, cookie string) (context.Context, tapp.Caller, error) {
	if !browserRequestOK(info, spec, o.sessions.PublicOrigin()) {
		o.log.WarnContext(ctx, "rpc.browser_request_refused", slog.String("procedure", spec.Procedure), slog.String("session", "partner"))
		return nil, tapp.Caller{}, ErrBrowserRequest
	}
	if o.partnerMayCall == nil || !o.partnerMayCall(spec.Procedure) {
		return nil, tapp.Caller{}, ErrPartnerReadOnly
	}
	c, err := o.partner.Authenticate(ctx, cookie, spec.Procedure)
	if err != nil {
		return nil, tapp.Caller{}, errAuthRequired
	}
	return audit.WithAuthKind(ctx, string(tapp.CredPartnerSession)), c, nil
}
