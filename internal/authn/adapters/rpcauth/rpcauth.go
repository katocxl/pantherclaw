// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rpcauth connects authentication to the RPC interceptor chain
// (platform/rpc, step 5): it authenticates the bearer credential, refuses
// procedures whose declared permission the caller holds nowhere, and puts
// the caller into the context for the use cases, which check the exact
// scope again.
package rpcauth

import (
	"context"
	"strings"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Authenticator resolves a bearer credential (authn/app.Authenticator).
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (tapp.Caller, error)
}

// New returns the API's rpc.Authenticator. perms maps every non-public
// procedure to its declared permission; a procedure missing from it is
// refused (fail closed). Procedures declaring a gateway permission are
// delegated to gateway, which may be nil (they are then refused).
func New(a Authenticator, perms map[string]td.Permission, gateway rpc.Authenticator, opts ...Option) rpc.Authenticator {
	var o options
	for _, opt := range opts {
		opt(&o)
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
		bearer, ok := strings.CutPrefix(info.RequestHeader().Get("Authorization"), "Bearer ")
		if !ok || bearer == "" {
			return nil, connect.NewError(connect.CodeUnauthenticated, "authentication required")
		}
		c, err := a.Authenticate(ctx, bearer)
		if err != nil {
			return nil, err
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
		return tapp.WithCaller(ctx, c), nil
	}
}

// Option configures New.
type Option func(*options)

type options struct{ refusals RefusalRecorder }

// RefusalRecorder records a non-human caller refused a human-only
// procedure. It must not block the refusal for long or fail it.
type RefusalRecorder interface {
	HumanOnlyRefused(ctx context.Context, c tapp.Caller, procedure string, perm td.Permission)
}

// WithRefusals records human-only refusals through r (G0 M10 D67).
func WithRefusals(r RefusalRecorder) Option { return func(o *options) { o.refusals = r } }
