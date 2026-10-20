// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"slices"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// scopableReads lets payments.refund.get enforce a data scope.
func scopableReads(raw []byte) []byte {
	return bytes.Replace(raw, []byte("  - operation: payments.refund.get\n    summary: Read one refund\n    access: read\n"),
		[]byte("  - operation: payments.refund.get\n    summary: Read one refund\n    access: read\n    scoping: [records, classes]\n"), 1)
}

const scopedBounds = `{
  "operations": ["payments.refund.create", "payments.refund.get"],
  "targets": {"payments.charge": {"prefixes": ["ch_"]}, "payments.refund": {"ids": ["re_1", "re_2"]}},
  "scope": {"payments.refund.get": {"records": {"key": "customer", "values": ["cus_1", "cus_2"]}, "classes": {"ids": ["public", "internal", "pii"]}}}
}`

// scopedRun gives the agent a grant with a data scope on refund reads,
// through a connection held as access says, and returns its run.
func (f *fx) scopedRun(access string) ids.UUID {
	f.t.Helper()
	f.w.PutConnection(pipeline.Connection{
		ID: f.conn, Gateway: f.gateway, Kind: "http", Package: f.pkg.Name, State: "ACTIVE", AccessMode: access,
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	g := f.newGrant(scopedBounds)
	f.w.Grants.Put(g)
	return f.newRun(g.ID)
}

func scopeObligations(ev *pipeline.Evaluation) []pdomain.Obligation {
	return slices.DeleteFunc(slices.Clone(ev.Obligations), func(o pdomain.Obligation) bool {
		return o.Kind != pdomain.RecordScope && o.Kind != pdomain.DataClasses
	})
}

// TestHR302_ADataScopeBecomesObligations: a grant's data scope and the
// policy's data scope rules meet in one record_scope and one data_classes
// obligation the gateway applies to the answer, each the intersection;
// rules only tighten, and an action without any scope gets none (G0 M14
// D11).
func TestHR302_ADataScopeBecomesObligations(t *testing.T) {
	f := newFxWith(t, scopableReads, "")
	ev := f.call(f.run, "get_refund", `{"refund":"re_1"}`)
	if len(scopeObligations(ev)) != 0 {
		t.Fatalf("no scope, obligations %+v", ev.Obligations)
	}
	run := f.scopedRun("pantherclaw_held")
	ev = f.call(run, "get_refund", `{"refund":"re_1"}`)
	expect(t, ev, adomain.AllowWithObligations, pipeline.ReasonDataScope)
	obs := scopeObligations(ev)
	if len(obs) != 2 || obs[0].Param != "customer" || !slices.Equal(obs[0].Values, []string{"cus_1", "cus_2"}) ||
		!slices.Equal(obs[1].Values, []string{"internal", "pii", "public"}) {
		t.Fatalf("grant scope: %+v", obs)
	}
	if err := f.w.SetPolicy([]pdomain.Rule{
		{
			ID: "one-customer", Kind: pdomain.Constrain, Summary: "one customer", Operations: []string{"payments.refund.get"}, When: "true",
			Reason: "ONE_CUSTOMER", Constraint: &pdomain.Constraint{Kind: pdomain.RecordScope, Param: "customer", Values: []string{"cus_2", "cus_9"}},
		},
		{
			ID: "no-pii", Kind: pdomain.Constrain, Summary: "no pii", Operations: []string{"payments.refund.get"}, When: "true",
			Reason: "NO_PII", Constraint: &pdomain.Constraint{Kind: pdomain.DataClasses, Values: []string{"public", "internal"}},
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	obs = scopeObligations(f.call(run, "get_refund", `{"refund":"re_1"}`))
	if len(obs) != 2 || !slices.Equal(obs[0].Values, []string{"cus_2"}) || !slices.Equal(obs[1].Values, []string{"internal", "public"}) ||
		obs[0].Rule != pipeline.ScopeRule {
		t.Fatalf("grant and rules: %+v", obs)
	}
}

// TestHR302_AScopeTheRouteCannotEnforceCannotAuthorize: a data scope on a
// definition that does not declare it can enforce it, through a
// connection whose credential the agent holds, or on a cooperative
// channel, is CANNOT_AUTHORIZE SCOPE_UNSUPPORTED: never answered unscoped
// (G0 M14 D11).
func TestHR302_AScopeTheRouteCannotEnforceCannotAuthorize(t *testing.T) {
	f := newFx(t)
	expect(t, f.call(f.scopedRun("pantherclaw_held"), "get_refund", `{"refund":"re_1"}`), adomain.CannotAuthorize, pipeline.ReasonScopeUnsupported)

	f = newFxWith(t, scopableReads, "")
	expect(t, f.call(f.scopedRun("agent_held"), "get_refund", `{"refund":"re_1"}`), adomain.CannotAuthorize, pipeline.ReasonScopeUnsupported)

	run := f.scopedRun("pantherclaw_held")
	req := f.parse(run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	req.Action.Action.Channel = "sdk"
	expect(t, f.eval(req), adomain.CannotAuthorize, pipeline.ReasonScopeUnsupported)
}

// requiredDestinations makes refunds require a destination set.
func requiredDestinations(raw []byte) []byte {
	return bytes.Replace(raw, []byte("    constraints:\n      - kind: amount_max\n        param: amount\n"),
		[]byte("    constraints:\n      - kind: amount_max\n        param: amount\n      - kind: destination_set\n        required: true\n"), 1)
}

// TestM14_ARequiredSetMustBeBound: a definition that requires a
// destination set is DENIED DESTINATION_SET_REQUIRED unless a grant or
// guardrail of the chain lists destinations (G0 M14 D78).
func TestM14_ARequiredSetMustBeBound(t *testing.T) {
	f := newFxWith(t, requiredDestinations, "")
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "10.00")), adomain.Deny, pipeline.ReasonDestinationSetRequired)
	g := f.newGrant(`{
  "operations": ["payments.refund.create"],
  "targets": {"payments.charge": {"prefixes": ["ch_"]}},
  "destinations": {"ids": ["acct_1"]},
  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}
}`)
	f.w.Grants.Put(g)
	expect(t, f.call(f.newRun(g.ID), "create_refund", refund("ch_1", "10.00")), adomain.Allow, pipeline.ReasonGrantCovers)
}

// TestM14_ARequiredSetMayBeBoundByAGuardrail: a destination set the agent's
// guardrail lists satisfies a required set as one the grant lists does
// (D78 grant or envelope, D103).
func TestM14_ARequiredSetMayBeBoundByAGuardrail(t *testing.T) {
	f := newFxWith(t, requiredDestinations, "")
	b, err := gdomain.DecodeBounds([]byte(`{"destinations": {"ids": ["acct_1"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.w.Grants.PutEnvelope(t.Context(), org, gdomain.Envelope{
		ID: gdomain.NewEnvelopeID(), Org: org, Revision: 1, Scope: gdomain.Scope{Kind: gdomain.ScopeTeam, ID: f.team}, Name: "payees", Bounds: b,
	}, false, testEvent()); err != nil {
		t.Fatal(err)
	}
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "10.00")), adomain.Allow, pipeline.ReasonGrantCovers)
}
