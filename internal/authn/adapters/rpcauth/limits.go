// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"connectrpc.com/connect/v2"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// API rate limits (G0 M13 D8, HR-375): every authenticated org call is
// counted per organization and per credential in one-minute windows, after
// the permission check and before the plan gate. Gateway, workload,
// gateway-enrollment and public procedures return before this layer, so
// enforcement is never throttled. The server counts in leased chunks of the
// shared store, so the limits hold across replicas (G0 M19 D201, HR-490).
// Procedures the plan gate classes safety or allow (containment,
// revocations, WhoAmI) skip the per-org limit and are counted per
// credential only (D27). A counter error refuses the call, except for
// those procedures, which a broken counter never locks out (D201).

// APIWindow is the API limits' window.
const APIWindow = time.Minute

// Scopes of the API counters.
const (
	scopeAPIOrg        = "api.org"
	scopeAPICredential = "api.credential" //nolint:gosec // G101: a counter scope name, not a credential
)

// ErrRateLimited refuses a call over an API limit; the response carries
// Retry-After.
var ErrRateLimited = pcerr.New(pcerr.ResourceExhausted, "RATE_LIMITED", "too many requests; retry after the time in Retry-After")

// APILimits are the per-minute limits of authenticated org calls.
type APILimits struct {
	// PerOrg bounds one organization's calls a minute.
	PerOrg int
	// PerCredential bounds one credential's calls a minute: an API key, a
	// service-account key, or a person's CLI or browser session.
	PerCredential int
	// Limiter counts the calls: ratelimit.Leased over the shared store in
	// the server, ratelimit.NewMemory when nil (tests).
	Limiter ratelimit.Limiter
	// OrgExempt reports procedures that skip the per-org limit (still
	// counted per credential): the plan gate's safety and allow classes,
	// so credentials flooding an org never lock its people out of
	// containment (G0 M13 D27). Nil exempts nothing.
	OrgExempt func(procedure string) bool
	// Exports reports export procedures; each org may call them at most
	// PerOrgExportsPerHour times an hour, counted in Shared (G0 M13 D45).
	// Nil or 0 leaves the cap off.
	Exports              func(procedure string) bool
	PerOrgExportsPerHour int
	// Shared counts the export cap across replicas (the Postgres store);
	// a Memory limiter when nil. A counter error refuses (HR-376).
	Shared ratelimit.Limiter
	// Log records counter errors (optional).
	Log *slog.Logger
}

// scopeAPIExport is the shared counter's scope of an org's exports an hour.
const scopeAPIExport = "api.export"

// ExportWindow is the export cap's window.
const ExportWindow = time.Hour

// WithAPILimits limits every authenticated org call (HR-375). Limits of 0
// leave that limit off.
func WithAPILimits(l APILimits) Option {
	if l.Limiter == nil {
		l.Limiter = ratelimit.NewMemory(nil)
	}
	if l.Shared == nil {
		l.Shared = ratelimit.NewMemory(nil)
	}
	return func(o *options) { o.limits = &l }
}

// credentialKey names the credential of a call: the key for API keys and
// service-account keys (one bucket whether the key is used directly or
// through its access token, D28), the session for a person's access token
// or browser session, the principal otherwise.
func credentialKey(c tapp.Caller) string {
	switch {
	case !c.CredentialID.IsZero():
		return "key:" + c.CredentialID.String()
	case !c.Session.IsZero():
		return string(c.Credential) + ":" + c.Session.String()
	default:
		return string(c.Credential) + ":" + string(c.Principal.Kind) + ":" + c.Principal.ID.String()
	}
}

// limit counts one call of c; over a limit it sets Retry-After and
// returns ErrRateLimited. The credential is counted first, so a credential
// over its own limit does not use up its org's; an org-exempt procedure
// is counted per credential only.
func (l *APILimits) limit(ctx context.Context, info *connect.CallInfo, c tapp.Caller, procedure string) error {
	if l == nil {
		return nil
	}
	org := c.Org.String()
	perOrg := l.PerOrg
	exempt := l.OrgExempt != nil && l.OrgExempt(procedure)
	if exempt {
		perOrg = 0
	}
	for _, k := range []struct {
		scope, key string
		limit      int
	}{
		{scopeAPICredential, org + "/" + credentialKey(c), l.PerCredential},
		{scopeAPIOrg, org, perOrg},
	} {
		if k.limit <= 0 {
			continue
		}
		d, err := l.Limiter.Take(ctx, k.scope, k.key, APIWindow, 1, k.limit)
		if err != nil {
			// The shared counter is unavailable: refuse (HR-376, HR-490),
			// except a safety or allow procedure (D27, D201).
			if l.Log != nil {
				l.Log.ErrorContext(ctx, "rpc.rate_unavailable", slog.String("procedure", procedure),
					slog.Bool("admitted", exempt), pclog.Err(err))
			}
			if exempt {
				continue
			}
			info.ResponseHeader().Set("Retry-After", "60")
			return ErrRateLimited
		}
		if !d.Allowed {
			info.ResponseHeader().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(d.RetryAfter)))
			return ErrRateLimited
		}
	}
	if l.Exports == nil || l.PerOrgExportsPerHour <= 0 || !l.Exports(procedure) {
		return nil
	}
	// The export cap holds across replicas: it is counted in the shared
	// store, outside any transaction (D45, D28), and fails closed.
	d, err := l.Shared.Take(ctx, scopeAPIExport, org, ExportWindow, 1, l.PerOrgExportsPerHour)
	if err != nil {
		if l.Log != nil {
			l.Log.ErrorContext(ctx, "rpc.export_rate_unavailable", slog.String("procedure", procedure), pclog.Err(err))
		}
		info.ResponseHeader().Set("Retry-After", "60")
		return ErrRateLimited
	}
	if !d.Allowed {
		info.ResponseHeader().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(d.RetryAfter)))
		return ErrRateLimited
	}
	return nil
}
