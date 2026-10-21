// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"net/http"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// TestHR359_ExtensionValidateSeesConfigOnlyAndMountSeesTheCore (D86): the
// core hands Validate (before the database exists) only the config fields
// and Mount every core port, as RunWith composes them for a hosted server
// (accounts on, billing external).
func TestHR359_ExtensionValidateSeesConfigOnlyAndMountSeesTheCore(t *testing.T) {
	cfg := uiWebConfig()
	cfg.Deployment, cfg.Billing.Mode, cfg.Billing.RequirePlan, cfg.Signup.SelfServe = "production", "external", true, true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var atValidate, atMount extension.Deps
	ext := extension.Set{
		Validate: func(d extension.Deps) error { atValidate = d; return nil },
		Mount:    func(d extension.Deps) ([]extension.Route, error) { atMount = d; return nil, nil },
	}
	xdeps := extensionDeps(&cfg, nil)
	if err := validateExtension(ext, xdeps); err != nil {
		t.Fatal(err)
	}
	if atValidate.Plans != nil || atValidate.Accounts != nil || atValidate.BillingLinks != nil || atValidate.Authz != nil ||
		atValidate.Audit != nil {
		t.Errorf("Validate saw Mount-only fields: %+v", atValidate)
	}
	if atValidate.Deployment != extension.DeploymentProduction || atValidate.PublicURL == "" || atValidate.Clock == nil {
		t.Errorf("Validate lacks the config fields: %+v", atValidate)
	}

	d := dbtest.New(t)
	pool := d.AppPool(t)
	ents, err := entitlements.New(pool, entitlements.LicenceFunc(func(context.Context) (billing.Entitlements, error) {
		return billing.CommunityEntitlements(), nil
	}), cfg.billingMode(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ui := newUITenancy(&cfg, pool, ents)
	if err := mountExtension(http.NewServeMux(), ext, ui.extensionDeps(xdeps), nil, nil); err != nil {
		t.Fatal(err)
	}
	if atMount.Plans == nil || atMount.Accounts == nil || atMount.BillingLinks == nil || atMount.Authz == nil || atMount.Audit == nil {
		t.Errorf("Mount lacks a core port: %+v", atMount)
	}
	if atMount.Deployment != extension.DeploymentProduction {
		t.Errorf("Mount deployment = %q", atMount.Deployment)
	}
}
