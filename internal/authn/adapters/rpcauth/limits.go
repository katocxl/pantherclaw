// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth

import (
	"context"
	"strconv"
	"time"

	"connectrpc.com/connect/v2"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// API rate limits (G0 M13 D8, HR-375): every authenticated org call is
// counted per organization and per credential in one-minute windows, after
// the permission check and before the plan gate. Gateway, workload,
// gateway-enrollment and public procedures return before this layer, so
// enforcement is never throttled. The counters are in memory: the limits
// hold per replica. Procedures the plan gate classes safety or allow
// (containment, revocations, WhoAmI) skip the per-org limit and are
// counted per credential only (D27).

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
	// Limiter counts the calls (ratelimit.NewMemory when nil).
	Limiter ratelimit.Limiter
	// OrgExempt reports procedures that skip the per-org limit (still
	// counted per credential): the plan gate's safety and allow classes,
	// so credentials flooding an org never lock its people out of
	// containment (G0 M13 D27). Nil exempts nothing.
	OrgExempt func(procedure string) bool
}

// WithAPILimits limits every authenticated org call (HR-375). Limits of 0
// leave that limit off.
func WithAPILimits(l APILimits) Option {
	if l.Limiter == nil {
		l.Limiter = ratelimit.NewMemory(nil)
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
	if l.OrgExempt != nil && l.OrgExempt(procedure) {
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
			return err
		}
		if !d.Allowed {
			info.ResponseHeader().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(d.RetryAfter)))
			return ErrRateLimited
		}
	}
	return nil
}
