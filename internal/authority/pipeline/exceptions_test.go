// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"encoding/hex"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

const exceptionID = "01920000-0000-7000-8000-0000000000e1"

// noOver20 is an exceptable prohibition every refund over 20 USD matches.
func noOver20() pdomain.Rule {
	return pdomain.Rule{
		ID: "no-over-20", Kind: pdomain.Forbid, Summary: "no refunds over 20 USD", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("20.00", "USD")`, Reason: "REFUND_OVER_20", Exceptable: true,
	}
}

// excepted is a fixture whose published policy has noOver20 and an active
// exception waiving it for refunds.
func excepted(t *testing.T) *fx {
	t.Helper()
	f := newFx(t)
	r := noOver20()
	if err := f.w.SetPolicy([]pdomain.Rule{r}, nil); err != nil {
		t.Fatal(err)
	}
	d := pdomain.RuleDigest(r)
	f.w.SetExceptions([]pdomain.Exception{{
		ID: exceptionID, Bundle: "org-policy", Rule: r.ID, RuleDigest: hex.EncodeToString(d[:]), Operations: []string{"payments.refund.create"},
		ExpiresAt: now.Add(time.Hour),
	}})
	return f
}

// waivedItem returns the checklist's WAIVED item, if any.
func waivedItem(ev *pipeline.Evaluation) (pipeline.Item, bool) {
	for _, it := range ev.Checklist {
		if it.Status == pipeline.StatusWaived {
			return it, true
		}
	}
	return pipeline.Item{}, false
}

// TestHR235_ExceptionAppliedIsNamedInTheChecklist: the waived rule
// restricts nothing, and the decision's checklist (so its receipt) names
// the exception; without the exception the rule denies.
func TestHR235_ExceptionAppliedIsNamedInTheChecklist(t *testing.T) {
	f := excepted(t)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	it, ok := waivedItem(ev)
	if !ok || it.Code != pdomain.ReasonExceptionApplied || it.Detail != exceptionID || it.Level != "policy org-policy@1 rule no-over-20" ||
		it.Step != pipeline.StepBoundaries {
		t.Fatalf("waived item %+v in %+v", it, ev.Checklist)
	}
	f.w.SetExceptions(nil)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, "REFUND_OVER_20")
}

// TestHR235_GrantIsNeverWaived: the grant's own limit still denies.
func TestHR235_GrantIsNeverWaived(t *testing.T) {
	f := excepted(t)
	ev := f.call(f.run, "create_refund", refund("ch_1", "150.00"))
	expect(t, ev, adomain.Deny, gdomain.ReasonGrantLimitExceeded)
	expect(t, f.call(f.newRun(gdomain.GrantID{}), "create_refund", refund("ch_1", "30.00")), adomain.Deny, gdomain.ReasonNoGrant)
}

// TestHR235_EnvelopeIsNeverWaived: a guardrail outside of which the action
// falls still denies.
func TestHR235_EnvelopeIsNeverWaived(t *testing.T) {
	f := excepted(t)
	env := gdomain.Envelope{ID: gdomain.NewEnvelopeID(), Org: org, Revision: 1, Scope: gdomain.Scope{Kind: gdomain.ScopeTeam, ID: f.team}, Name: "payments"}
	b, _ := gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.get"]}`))
	env.Bounds = b
	if err := f.w.Grants.PutEnvelope(t.Context(), org, env, false, testEvent()); err != nil {
		t.Fatal(err)
	}
	fresh := f.newGrant(grantBounds)
	f.w.Grants.Put(fresh)
	expect(t, f.call(f.newRun(fresh.ID), "create_refund", refund("ch_1", "30.00")), adomain.Deny, gdomain.ReasonOutsideGuardrail)
}

// TestHR235_ContainmentIsNeverWaived: the kill switch and a suspended agent
// still deny.
func TestHR235_ContainmentIsNeverWaived(t *testing.T) {
	f := excepted(t)
	f.w.Cont.KillSwitch = true
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, adomain.ReasonKillSwitch)
	f.w.Cont.KillSwitch = false
	f.w.AddAgent(f.agent, pipeline.Agent{State: "SUSPENDED", TeamID: f.team})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, pipeline.ReasonAgentSuspended)
}

// TestHR235_IdentityIsNeverWaived: an action whose verified identity is not
// the run's agent, or whose instance differs, still denies.
func TestHR235_IdentityIsNeverWaived(t *testing.T) {
	f := excepted(t)
	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "30.00"))
	req.Identity.AgentID = ids.NewV7()
	expect(t, f.eval(req), adomain.Deny, pipeline.ReasonRunMismatch)
	req = f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "30.00"))
	req.Identity.InstanceID = ids.NewV7()
	expect(t, f.eval(req), adomain.Deny, pipeline.ReasonRunMismatch)
}

// TestHR235_BudgetIsNeverWaived: an exhausted budget still denies.
func TestHR235_BudgetIsNeverWaived(t *testing.T) {
	f := excepted(t)
	root := f.grant
	limits, err := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "50.00", "period": "none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	root.Revision, root.Limits = 2, limits
	f.w.Grants.Put(root)
	first := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, first, adomain.Allow, pipeline.ReasonGrantCovers)
	f.w.Reserve(first)
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, gdomain.ReasonBudgetExhausted)
}

// TestHR235_StaleOrMissingFactIsNeverWaived: a required fact that is
// missing or stale is still CANNOT_AUTHORIZE (F096).
func TestHR235_StaleOrMissingFactIsNeverWaived(t *testing.T) {
	f := excepted(t)
	expect(t, f.call(f.run, "create_refund", refund("ch_404", "30.00")), adomain.CannotAuthorize, fdomain.ReasonFactMissing)
	f.putFact("ch_old", true, now.Add(-10*time.Minute))
	expect(t, f.call(f.run, "create_refund", refund("ch_old", "30.00")), adomain.CannotAuthorize, fdomain.ReasonFactStale)
}

// TestHR235_CoverageAndRouteModeAreNeverWaived: an action on a route the
// definition does not know stays CANNOT_AUTHORIZE, and a waived decision
// keeps its route's mode.
func TestHR235_CoverageAndRouteModeAreNeverWaived(t *testing.T) {
	f := excepted(t)
	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "30.00"))
	req.Action.Action.Route = "payments-refund-get"
	expect(t, f.eval(req), adomain.CannotAuthorize, pipeline.ReasonRouteUnknown)

	gw := ids.NewV7()
	c := connection(gw)
	c.Modes = map[string]string{"payments-refund": pipeline.ModeMonitor}
	f.w.PutConnection(c)
	ev := f.on(gw, c.ID, "create_refund", refund("ch_1", "30.00"))
	if _, ok := waivedItem(ev); !ok || ev.Mode != pipeline.ModeMonitor || !ev.MonitorPermit() {
		t.Fatalf("mode %s, checklist %+v", ev.Mode, ev.Checklist)
	}
	c.Modes = map[string]string{"payments-refund": pipeline.ModeEnforce}
	f.w.PutConnection(c)
	if ev := f.on(gw, c.ID, "create_refund", refund("ch_1", "30.00")); ev.Mode != pipeline.ModeEnforce || ev.MonitorPermit() {
		t.Fatalf("mode %s", ev.Mode)
	}
}

// TestHR235_OnlyAKnownConsequenceIsWaived (D33, HR-206): an exception that
// lists a consequence's operation waives an exceptable rule on a predicted
// consequence as it would on the action; on an unknown consequence, which
// could be any of its outcomes, nothing is waived.
func TestHR235_OnlyAKnownConsequenceIsWaived(t *testing.T) {
	noPayouts := pdomain.Rule{
		ID: "no-payouts", Kind: pdomain.Forbid, Summary: "no payouts from refunds", Operations: []string{"payments.payout.trigger"},
		When: "true", Reason: "NO_PAYOUTS", Exceptable: true,
	}
	f := newFxWith(t, payoutPackage, "")
	f.payoutRun(false)
	if err := f.w.SetPolicy([]pdomain.Rule{noPayouts}, nil); err != nil {
		t.Fatal(err)
	}
	d := pdomain.RuleDigest(noPayouts)
	f.w.SetExceptions([]pdomain.Exception{{
		ID: exceptionID, Bundle: "org-policy", Rule: noPayouts.ID, RuleDigest: hex.EncodeToString(d[:]),
		Operations: []string{"payments.payout.trigger"}, ExpiresAt: now.Add(time.Hour),
	}})
	// Unknown: no payout schedule is known for ch_1.
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Deny, "NO_PAYOUTS")
	f.payouts("ch_1", scheduled, time.Second)
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	if it, ok := waivedItem(ev); ev.Decision != adomain.Allow || !ok || it.Detail != exceptionID {
		t.Fatalf("a predicted payout: %s %+v", ev.Decision, ev.Checklist)
	}
}
