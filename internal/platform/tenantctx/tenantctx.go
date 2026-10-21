// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package tenantctx carries the org a piece of work is for, so that code
// without an authenticated caller (jobs, inbound webhooks) can still read
// that org's entitlements (G0 UI D9: per-org plans behind every gate).
// It is a hint for entitlement lookups only; it never authorizes anything.
package tenantctx

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type key struct{}

// WithOrg returns ctx carrying org.
func WithOrg(ctx context.Context, org ids.OrgID) context.Context {
	return context.WithValue(ctx, key{}, org)
}

// Org returns the org ctx carries.
func Org(ctx context.Context) (ids.OrgID, bool) {
	org, ok := ctx.Value(key{}).(ids.OrgID)
	return org, ok && !org.IsZero()
}
