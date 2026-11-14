// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR796_CreateCustomRuleRefusesExtensionIDs: an ext.<publisher> rule id
// is accepted by the parser and refused by the ordinary create path. Only
// a bundle install stores one (G0 M37 D1082a).
func TestHR796_CreateCustomRuleRefusesExtensionIDs(t *testing.T) {
	f := newFixture(t, billing.Business)
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	det := &reflexapp.Detections{Pool: f.p, Env: env, Ents: ents{billing.Business}}
	ctx := f.as(td.RoleSecurityAdmin)
	ext := strings.Replace(customRule, "id: org.kill_watch", "id: ext.acme.kill_watch", 1)
	if _, err := det.CreateCustomRule(ctx, ext); err == nil || !strings.Contains(err.Error(), "ext.") {
		t.Fatalf("extension id: %v", err)
	}
	if _, err := det.CreateCustomRule(ctx, customRule); err != nil {
		t.Fatalf("an org. rule: %v", err)
	}
}
