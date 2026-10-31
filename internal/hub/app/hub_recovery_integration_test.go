// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/hub/app"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Covers: F842, F845

// crash leaves an install as a worker that died after its draft committed
// would: PENDING, long ago.
func (w *world) crash(name string) {
	w.t.Helper()
	w.exec(`UPDATE pc.hub_installs SET status = 'PENDING', result_kind = '', result_ref = '', installed_at = now() - interval '10 minutes'
		WHERE name = $1`, name)
}

// TestD130_RetryFindsTheDraftACrashLeft: a retry after a crash finishes as
// done on the draft that exists, and makes no second one.
func TestD130_RetryFindsTheDraftACrashLeft(t *testing.T) {
	w := newWorld(t, billing.Business)
	ctx := w.admin()
	var policyBody domain.PolicyTemplateBody
	if err := json.Unmarshal([]byte(`{"rules":[{"id":"hub-no-curl","per":"org","kind":"FORBID","summary":"no curl",
		"operations":["shell.command.run"],"when":"action.params.command.startsWith('curl')","reason":"NO_CURL"}]}`), &policyBody); err != nil {
		t.Fatal(err)
	}
	policy, pe := w.item("pc.coding.no-curl", "1.0.0", domain.KindPolicyTemplate, policyBody)
	rule, re := w.item("pc.detect.watch", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: customRule})
	auto, ae := w.item("pc.auto.hello", "1.0.0", domain.KindAutomation, domain.AutomationBody{
		AutomationName: "hello", Purpose: "Say hello.", WorkKind: "AGENT_WORK", Definition: definition(),
	})
	pkg, pke := w.item("pc.shell", manifestVersion(t, w.pkgRaw), domain.KindToolPackage, domain.ToolPackageBody{PackageYAML: string(w.pkgRaw), TargetsJWS: w.targets})
	doc := w.index(1, pe, re, ae, pke)
	for name, c := range map[string]struct {
		raw   []byte
		name  string
		count string
	}{
		"policy":     {policy, pe.Name, "SELECT count(*) FROM pc.policy_versions WHERE state = 'DRAFT'"},
		"rule":       {rule, re.Name, "SELECT count(*) FROM pc.custom_detection_rules"},
		"automation": {auto, ae.Name, "SELECT count(*) FROM pc.automations"},
		"package":    {pkg, pke.Name, "SELECT count(*) FROM pc.package_versions"},
	} {
		t.Run(name, func(t *testing.T) {
			first, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: c.raw})
			if err != nil {
				t.Fatal(err)
			}
			before := w.count(c.count)
			w.crash(c.name)
			again, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: c.raw})
			if err != nil {
				t.Fatal(err)
			}
			if again.Install.Status != app.StatusInstalled || again.Install.ResultRef != first.Install.ResultRef {
				t.Fatalf("retry %+v, first %+v", again.Install, first.Install)
			}
			if n := w.count(c.count); n != before {
				t.Fatalf("a second draft: %d, was %d", n, before)
			}
		})
	}
}

// TestD130_WhatCannotBeProvedStaysFailed: another automation holds the name,
// so nothing proves this item's draft exists. The install stays FAILED with
// the reason, retried or not.
func TestD130_WhatCannotBeProvedStaysFailed(t *testing.T) {
	w := newWorld(t, billing.Business)
	ctx := w.admin()
	first, fe := w.item("pc.auto.hello", "1.0.0", domain.KindAutomation, domain.AutomationBody{
		AutomationName: "hello", Purpose: "Say hello.", WorkKind: "AGENT_WORK", Definition: definition(),
	})
	other, oe := w.item("pc.auto.other", "1.0.0", domain.KindAutomation, domain.AutomationBody{
		AutomationName: "hello", Purpose: "Say hello.", WorkKind: "AGENT_WORK", Definition: strings.ReplaceAll(definition(), `"hello"`, `"goodbye"`),
	})
	doc := w.index(1, fe, oe)
	if _, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: first}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: other}); !errors.Is(err, autoapp.ErrNameTaken) {
		t.Fatalf("name taken: %v", err)
	}
	w.crash(oe.Name)
	if _, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: other}); !errors.Is(err, autoapp.ErrNameTaken) {
		t.Fatalf("retry: %v", err)
	}
	if n := w.count("SELECT count(*) FROM pc.hub_installs WHERE name = $1 AND status = 'FAILED'", oe.Name); n != 1 {
		t.Fatalf("failed installs: %d", n)
	}
}

// TestD130_OnlyTheClaimFinishes: a worker that was reclaimed cannot end the
// install of the one that took over.
func TestD130_OnlyTheClaimFinishes(t *testing.T) {
	w := newWorld(t, billing.Business)
	ctx := w.admin()
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, e := w.item("pc.detect.watch", "1.0.0", domain.KindDetectionRule, domain.DetectionRuleBody{Content: customRule})
	v, err := domain.Verify(w.index(1, e), w.svc.Roots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	begin := app.Begin{Index: v, Entry: e, InstalledBy: c.Principal.String()}
	stale, _, err := w.svc.Store.Begin(ctx, w.org, c, begin)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.svc.Store.Begin(ctx, w.org, c, begin); !errors.Is(err, app.ErrBusy) {
		t.Fatalf("in progress: %v", err)
	}
	w.crash(e.Name)
	fresh, _, err := w.svc.Store.Begin(ctx, w.org, c, begin)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Reclaimed || fresh.Claim == stale.Claim {
		t.Fatalf("reclaim %+v after %+v", fresh, stale)
	}
	done := app.Finish{ID: stale.ID, Claim: stale.Claim, Status: app.StatusInstalled, ResultKind: app.ResultCustomRule, ResultRef: "stale"}
	if _, err := w.svc.Store.Finish(ctx, w.org, c, done); !errors.Is(err, app.ErrBusy) {
		t.Fatalf("stale worker: %v", err)
	}
	done.Claim, done.ResultRef = fresh.Claim, "fresh"
	out, err := w.svc.Store.Finish(ctx, w.org, c, done)
	if err != nil || out.ResultRef != "fresh" {
		t.Fatalf("claim holder: %+v %v", out, err)
	}
}

// TestD135_ReplacedIsReturnedAndAudited: a template that changes a published
// rule says so, and one that adds a rule says nothing.
func TestD135_ReplacedIsReturnedAndAudited(t *testing.T) {
	w := newWorld(t, billing.Business)
	ctx := w.admin()
	body := func(id, reason string) domain.PolicyTemplateBody {
		t.Helper()
		var b domain.PolicyTemplateBody
		if err := json.Unmarshal([]byte(`{"rules":[{"id":"`+id+`","per":"org","kind":"FORBID","summary":"no sudo",
			"operations":["shell.command.run"],"when":"action.params.command.startsWith('sudo')","reason":"`+reason+`"}]}`), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	changes, ce := w.item("pc.coding.changes", "1.0.0", domain.KindPolicyTemplate, body("no-root", "NO_ROOT_AT_ALL"))
	adds, ae := w.item("pc.coding.adds", "1.0.0", domain.KindPolicyTemplate, body("hub-new", "NEW"))
	doc := w.index(1, ce, ae)
	res, err := w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: changes})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Replaced, []string{"no-root"}) {
		t.Fatalf("replaced %v", res.Replaced)
	}
	res, err = w.svc.Install(ctx, app.Input{IndexJWS: doc, Item: adds})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Replaced) != 0 {
		t.Fatalf("replaced %v", res.Replaced)
	}
	if n := w.count(`SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.hub.item_installed' AND convert_from(body, 'UTF8') LIKE '%"replaced":"1"%'`); n != 1 {
		t.Fatalf("audited: %d", n)
	}
}
