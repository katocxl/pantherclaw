// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Device scan limits (G0 M24 D246). A device scope is cheap to make up, so
// the cap per scope bounds nothing across scopes: these do.
const (
	// DefaultNewDeviceScopesPerKey is how many device scopes one key may start
	// an hour.
	DefaultNewDeviceScopesPerKey = 1000
	// DefaultOpenDeviceScopesPerOrg is how many device scopes of an org may
	// have an open discovery.
	DefaultOpenDeviceScopesPerOrg = 20_000

	deviceLimitWindow = time.Hour
	// The limit names, as the audit record gives them.
	limitNewPerKey  = "new_device_scopes_per_key_per_hour"
	limitOpenPerOrg = "open_device_scopes_per_org"
)

// ErrScanDeviceLimit refuses a new device scope past a limit. Scopes already
// known go on.
var ErrScanDeviceLimit = pcerr.New(pcerr.ResourceExhausted, "SCAN_DEVICE_LIMIT",
	"this organization or key has reached its limit of device scans")

type deviceLimits struct {
	limiter               ratelimit.Limiter
	newPerKey, openPerOrg int
}

// WithDeviceLimits sets the limits on device scans; a value below 1 keeps the
// default.
func (inv *Inventory) WithDeviceLimits(newPerKey, openPerOrg int) *Inventory {
	if newPerKey >= 1 {
		inv.devices.newPerKey = newPerKey
	}
	if openPerOrg >= 1 {
		inv.devices.openPerOrg = openPerOrg
	}
	return inv
}

// checkDeviceScope refuses a device scope the org has not seen when it would
// pass a limit. It counts outside any transaction: the limiter must not wait
// for a connection while one is held.
func (inv *Inventory) checkDeviceScope(ctx context.Context, mode ScanMode) error {
	if !domain.DeviceScope(mode.Scope) {
		return nil
	}
	var known, full bool
	var org, key string
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := mode.permitted(c); err != nil {
			return err
		}
		var err error
		if known, err = q.DeviceScopeKnown(ctx, c.Org, &mode.Scope); err != nil || known {
			return err
		}
		open, err := q.CountOpenDeviceScopes(ctx, c.Org)
		if err != nil {
			return err
		}
		full = open >= int64(inv.devices.openPerOrg)
		org, key = c.Org.String(), c.Principal.String()
		if !c.CredentialID.IsZero() {
			key = c.CredentialID.String()
		}
		return nil
	})
	if err != nil || known {
		return err
	}
	if full {
		return inv.refuseDeviceScope(ctx, mode, org, limitOpenPerOrg)
	}
	d, err := inv.devices.limiter.Take(ctx, "scan.device_scope", org+":"+key, deviceLimitWindow, 1, inv.devices.newPerKey)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return inv.refuseDeviceScope(ctx, mode, org, limitNewPerKey)
	}
	return nil
}

// refuseDeviceScope refuses the scan and audits the first refusal of each
// limit in each window, so refusing costs the audit log almost nothing.
func (inv *Inventory) refuseDeviceScope(ctx context.Context, mode ScanMode, org, limit string) error {
	d, err := inv.devices.limiter.Take(ctx, "scan.device_limit_audit", org+":"+limit, deviceLimitWindow, 1, 1)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return ErrScanDeviceLimit
	}
	err = inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, _ *dbq.Queries, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "agents.scan_device_limit", Actor: c.Actor(), Outcome: audit.Denied,
			Object: &audit.Object{Type: "scan_scope", ID: mode.Scope}, Details: map[string]string{"limit": limit},
		})
		return err
	})
	if err != nil {
		return err
	}
	return ErrScanDeviceLimit
}
