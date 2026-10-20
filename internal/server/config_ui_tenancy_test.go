// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR359_ProductionRefusesBillingModeOff: billing mode off (every org
// DEV, every feature) is a development seam; production refuses it at
// start-up with DEPLOYMENT_CONFIG, and the extension's own Validate errors
// stop start-up too.
func TestHR359_ProductionRefusesBillingModeOff(t *testing.T) {
	for _, tc := range []struct {
		deployment, mode string
		ok               bool
	}{
		{"development", "off", true}, {"staging", "off", true}, {"production", "off", false},
		{"production", "external", true}, {"production", "", true}, {"production", "licence", true},
		{"development", "fake", false}, {"production", "OFF", false},
	} {
		c := uiWebConfig()
		c.Deployment, c.Billing.Mode = tc.deployment, tc.mode
		err := c.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s with billing.mode %q: %v", tc.deployment, tc.mode, err)
		}
		if tc.deployment == "production" && tc.mode == "off" && (err == nil || !strings.Contains(err.Error(), "DEPLOYMENT_CONFIG")) {
			t.Errorf("production + off: %v, want DEPLOYMENT_CONFIG", err)
		}
	}
	c := uiWebConfig()
	c.Deployment = "production"
	err := validateExtension(extension.Set{Validate: func(extension.Deps) error { return errors.New("fake billing in production") }},
		extensionDeps(&c, nil))
	if err == nil || !strings.Contains(err.Error(), "DEPLOYMENT_CONFIG") {
		t.Errorf("extension Validate error: %v", err)
	}
}

// TestT166_TestSeamsNeverReachProduction: the plan gate needs real plans,
// self-serve needs hosted billing, and a self-hosted production server
// keeps the licence (no seam is on by default).
func TestT166_TestSeamsNeverReachProduction(t *testing.T) {
	c := uiWebConfig()
	if c.billingMode() != entitlements.ModeLicence || c.Signup.SelfServe || c.Billing.RequirePlan {
		t.Fatalf("defaults: mode %s self_serve %v require_plan %v", c.billingMode(), c.Signup.SelfServe, c.Billing.RequirePlan)
	}
	for name, mutate := range map[string]func(*Config){
		"require_plan without external": func(c *Config) { c.Billing.RequirePlan = true },
		"self_serve with the licence":   func(c *Config) { c.Signup.SelfServe = true },
		"negative limit":                func(c *Config) { c.Signup.MaxOrgsPerAccount = -1 },
		"terms version":                 func(c *Config) { c.Signup.TermsVersion = "v1; drop" },
	} {
		c := uiWebConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c.Deployment, c.Billing.Mode, c.Billing.RequirePlan, c.Signup.SelfServe = "production", "external", true, true
	if err := c.Validate(); err != nil {
		t.Errorf("hosted production refused: %v", err)
	}
}

// TestHR357_GatewayAndWorkloadProceduresAreNeverPlanGated: whatever the
// plan, the authentication layer never asks the plan gate about a gateway
// or workload procedure, and an org caller's call does reach it.
func TestHR357_GatewayAndWorkloadProceduresAreNeverPlanGated(t *testing.T) {
	asked := 0
	refuse := func(context.Context, tapp.Caller, string) error {
		asked++
		return entitlements.ErrPlanRequired
	}
	gateway := func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		return ctx, nil
	}
	org := ids.New[ids.Org]()
	authn := fakeBearer{c: tapp.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}}}}
	auth := rpcauth.New(authn, procedurePermissions, gateway, rpcauth.WithPlanGate(refuse))
	for proc, perm := range procedurePermissions {
		if !perm.Gateway() && !perm.Workload() && perm != td.PermGatewayEnroll {
			continue
		}
		info := &connect.CallInfo{}
		if _, err := auth(context.Background(), info, connect.Spec{Procedure: proc}); errors.Is(err, entitlements.ErrPlanRequired) {
			t.Errorf("%s was plan-gated", proc)
		}
	}
	if asked != 0 {
		t.Errorf("the gate was asked %d times about gateway or workload procedures", asked)
	}
	info := &connect.CallInfo{}
	info.RequestHeader().Set("Authorization", "Bearer x")
	if _, err := auth(context.Background(), info, connect.Spec{Procedure: "/pantherclaw.v1.TenancyService/CreateTeam"}); !errors.Is(err, entitlements.ErrPlanRequired) {
		t.Errorf("an org change was not gated: %v", err)
	}
	if !accounts.AllowedProcedure("/pantherclaw.v1.TenancyService/CreateOrg") {
		t.Error("CreateOrg is not on the account allow list")
	}
}

type fakeBearer struct{ c tapp.Caller }

func (f fakeBearer) Authenticate(context.Context, string) (tapp.Caller, error) { return f.c, nil }
