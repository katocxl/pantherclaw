// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// PackageGate is the Gate as package activation uses it (definitions'
// ActivationGate): the package store has no transaction of its own to
// hand over, so the activation runs in one this opens.
type PackageGate struct {
	Pool *db.Pool
	Gate *Gate
}

// Activate runs activate unless the org protects TOOL_MEANING (or, failing
// that, CONSEQUENCE_RULES: rules ship in package versions), when the
// activation waits for a distinct publisher (D42a (2)).
func (p PackageGate) Activate(ctx context.Context, author tenancy.Caller, name, version string, activate func(context.Context, db.TenantTx) error) error {
	var held *PendingError
	err := p.Pool.InTenantTx(ctx, author.Org, func(ctx context.Context, tx db.TenantTx) error {
		// A person marked compromised activates nothing (D43, HR-293).
		if err := p.Gate.refuseCompromised(ctx, tx, author.Principal.ID); err != nil {
			return err
		}
		var err error
		held, err = p.Gate.Hold(ctx, tx, author, Change{
			Category: ToolMeaning, Surface: SurfacePackageActivate, Subject: name + "@" + version,
			Summary:  map[string]string{"package": name, "version": version, "to": "ACTIVE"},
			Widening: []string{"package_activation"},
			Payload:  struct{ Name, Version string }{name, version},
		}, func(ctx context.Context) error { return activate(ctx, tx) }, ConsequenceRules)
		return err
	})
	if err == nil && held != nil {
		return held
	}
	return err
}
