// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rpcauth connects authentication to the RPC interceptor chain
// (platform/rpc, step 5): it authenticates the bearer credential, or the
// browser session cookie of the console, refuses procedures whose
// declared permission the caller holds nowhere, and puts the caller into
// the context for the use cases, which check the exact scope again.
//
// The session cookie is taken only from a page of the server's own origin
// (Sec-Fetch-Site same-origin, or Origin equal to the public origin), with
// the PC-CSRF: 1 header, as a POST of a unary Connect call with a JSON or
// binary protobuf body (application/json or application/proto). A cookie
// on a GET call is refused, no CORS header is ever sent, and a call
// carrying both a bearer credential and the cookie is refused as
// AMBIGUOUS_CREDENTIAL (HR-342, HR-343). Events such a call audits carry
// auth_kind=browser_session (HR-347).
package rpcauth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Authenticator resolves a bearer credential (authn/app.Authenticator).
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (tapp.Caller, error)
}

// Errors of the cookie path.
var (
	// ErrAmbiguousCredential: a bearer credential and the session cookie
	// in one call (HR-343).
	ErrAmbiguousCredential = pcerr.New(pcerr.Unauthenticated, "AMBIGUOUS_CREDENTIAL",
		"send either a bearer credential or the browser session, not both")
	// ErrBrowserRequest: the cookie came without the same-origin proof, the
	// PC-CSRF header, a POST or a unary Connect body (HR-342).
	ErrBrowserRequest = pcerr.New(pcerr.PermissionDenied, "BROWSER_REQUEST_REFUSED",
		"a browser session is accepted only on a same-origin POST with PC-CSRF: 1")
	errAuthRequired = pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "authentication required")
)

// New returns the API's rpc.Authenticator. perms maps every non-public
// procedure to its declared permission; a procedure missing from it is
// refused (fail closed). Procedures declaring a gateway permission are
// delegated to gateway, which may be nil (they are then refused).
func New(a Authenticator, perms map[string]td.Permission, gateway rpc.Authenticator, opts ...Option) rpc.Authenticator {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.log == nil {
		o.log = pclog.Discard()
	}
	return func(ctx context.Context, info *connect.CallInfo, spec connect.Spec) (context.Context, error) {
		perm, ok := perms[spec.Procedure]
		if !ok || perm == td.PermPublic {
			return nil, connect.NewError(connect.CodePermissionDenied, "permission denied")
		}
		if perm.Workload() || perm == td.PermGatewayEnroll {
			// WorkloadService is authenticated by PAP/1: each handler verifies
			// the request proof (and workload token) itself before doing
			// anything (internal/identity/adapters/workloadrpc). Gateway
			// enrollment is authenticated by the single-use enrollment token
			// in the request, which its handler verifies (HR-180). No
			// principal is put in the context, so no use case for people or
			// services can run from here.
			return ctx, nil
		}
		if perm.Gateway() {
			if gateway == nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
			}
			return gateway(ctx, info, spec)
		}
		hd := info.RequestHeader()
		authz := hd.Get("Authorization")
		cookie, hasCookie := "", false
		if o.sessions != nil {
			cookie, hasCookie = o.sessions.Cookie(hd.Values("Cookie"))
		}
		accountCookie, hasAccount := o.accountCookieValue(hd.Values("Cookie"))
		var c tapp.Caller
		switch {
		case authz != "" && (hasCookie || hasAccount):
			return nil, ErrAmbiguousCredential
		case hasAccount && !hasCookie:
			// An account session (G0 UI D8): the allow list only (HR-350).
			return o.accountCall(ctx, info, spec, accountCookie)
		case hasCookie && isSupportCookie(cookie):
			if o.support == nil {
				return nil, errAuthRequired
			}
			var err error
			if ctx, c, err = o.supportCall(ctx, info, spec, cookie); err != nil {
				return nil, err
			}
		case hasCookie:
			var err error
			if c, err = o.browser(ctx, info, spec, cookie); err != nil {
				return nil, err
			}
			ctx = audit.WithAuthKind(ctx, string(tapp.CredBrowserSession))
		default:
			bearer, ok := strings.CutPrefix(authz, "Bearer ")
			if !ok || bearer == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, "authentication required")
			}
			var err error
			if c, err = a.Authenticate(ctx, bearer); err != nil {
				return nil, err
			}
		}
		if actx, handled, err := o.orgAccountCall(ctx, c, perm); handled {
			return actx, err
		}
		if perm != td.PermAuthenticated && !c.CanAnywhere(perm) {
			if o.refusals != nil && perm.HumanOnly() && (!c.Human() || c.Credential == tapp.CredAPIKey) {
				// A service, workload or API key calling a person's procedure is
				// what pc.authority.self_issue and self_approve look for (G0 M10
				// D67). The refusal never waits on or fails with the audit.
				o.refusals.HumanOnlyRefused(ctx, c, spec.Procedure, perm)
			}
			return nil, td.ErrPermissionDenied(perm)
		}
		if o.gate != nil {
			// The plan gate (G0 UI D9, D43, HR-356) runs after the
			// permission check, so it reveals nothing to a caller who may
			// not call the procedure anyway.
			if err := o.gate(ctx, c, spec.Procedure); err != nil {
				return nil, err
			}
		}
		return tapp.WithCaller(ctx, c), nil
	}
}

// PlanGate refuses a procedure the caller's org's plan does not allow.
type PlanGate func(ctx context.Context, c tapp.Caller, procedure string) error

// WithPlanGate checks every authenticated org call against the plan gate.
// Gateway, workload and public procedures never reach it (HR-357).
func WithPlanGate(g PlanGate) Option { return func(o *options) { o.gate = g } }

// browser authenticates the session cookie of a console call (HR-342): the
// request checks run before the session is looked up. A rotated secret
// replaces the cookie on the response; the lookup itself refreshes the
// idle limit (HR-150).
func (o *options) browser(ctx context.Context, info *connect.CallInfo, spec connect.Spec, cookie string) (tapp.Caller, error) {
	if !browserRequestOK(info, spec, o.sessions.PublicOrigin()) {
		o.log.WarnContext(ctx, "rpc.browser_request_refused", slog.String("procedure", spec.Procedure),
			slog.String("sec_fetch_site", trunc(info.RequestHeader().Get("Sec-Fetch-Site"), 32)))
		return tapp.Caller{}, ErrBrowserRequest
	}
	s, err := o.sessions.Auth.Authenticate(ctx, cookie)
	if err != nil {
		return tapp.Caller{}, errAuthRequired
	}
	if s.Rotated != "" {
		info.ResponseHeader().Add("Set-Cookie", o.sessions.SetCookie(s.Rotated))
	}
	return s.Caller, nil
}

// browserRequestOK is the request half of HR-342: same origin, PC-CSRF: 1,
// a POST, and a unary Connect call with a JSON or binary body, which is
// exactly Content-Type application/json or application/proto.
func browserRequestOK(info *connect.CallInfo, spec connect.Spec, origin string) bool {
	hd := info.RequestHeader()
	if !webguard.SameOrigin(hd.Get, origin) || hd.Get(webguard.CSRFHeader) != "1" {
		return false
	}
	si, ok := info.TransportInfo.(*connecthttp.ServerInfo)
	if !ok || si.HTTPMethod() != http.MethodPost {
		return false
	}
	return info.Protocol == connect.ProtocolNameConnect && spec.StreamType == connect.StreamTypeUnary &&
		(info.Codec == connect.CodecNameJSON || info.Codec == connect.CodecNameProto)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Option configures New.
type Option func(*options)

type options struct {
	refusals RefusalRecorder
	gate     PlanGate
	sessions *webguard.Sessions
	// Hosted accounts (accounts.go).
	accounts      AccountSessions
	accountCookie string
	accountOrigin string
	// Support sessions (support.go).
	support         SupportSessions
	supportReadOnly func(procedure string) bool
	log             *slog.Logger
}

// RefusalRecorder records a non-human caller refused a human-only
// procedure. It must not block the refusal for long or fail it.
type RefusalRecorder interface {
	HumanOnlyRefused(ctx context.Context, c tapp.Caller, procedure string, perm td.Permission)
}

// WithRefusals records human-only refusals through r (G0 M10 D67).
func WithRefusals(r RefusalRecorder) Option { return func(o *options) { o.refusals = r } }

// WithBrowserSessions accepts the console's session cookie under the
// rules of HR-342 and HR-343; log records refused browser requests.
func WithBrowserSessions(s *webguard.Sessions, log *slog.Logger) Option {
	return func(o *options) { o.sessions, o.log = s, log }
}
