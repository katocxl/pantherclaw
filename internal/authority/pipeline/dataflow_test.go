// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Covers: F123

var slackChannel = actionir.Destination{Kind: "external", ID: "C0PUBLIC"}

// dataFlowFx is the refund fixture with a public connection whose refund
// route runs in mode: a refund through it is an external disclosure (D74).
func dataFlowFx(t *testing.T, mode string) (*fx, ids.UUID, pipeline.Connection) {
	t.Helper()
	f := newFx(t)
	gw := ids.NewV7()
	c := connection(gw)
	c.DestinationClass = "public"
	c.Modes = map[string]string{"payments-refund": mode}
	f.w.PutConnection(c)
	return f, gw, c
}

// disclose evaluates a refund in run through c, with dests as the
// action's destinations.
func (f *fx) disclose(run, gw ids.UUID, c pipeline.Connection, dests ...actionir.Destination) *pipeline.Evaluation {
	f.t.Helper()
	req := f.parse(run, ids.NewV7(), "create_refund", refund("ch_1", "10.00"))
	a := req.Action.Action
	a.Connection, a.Destinations = c.ID.String(), append([]actionir.Destination{}, dests...)
	p, err := actionir.Encode(a)
	if err != nil {
		f.t.Fatal(err)
	}
	req.Action, req.Gateway = p, gw.String()
	return f.eval(req)
}

func sensitiveRead(run ids.UUID, class string) pipeline.SensitiveRead {
	return pipeline.SensitiveRead{TransactionID: ids.NewV7(), RunID: run, Operation: "payments.refund.get", Class: class, At: now}
}

func withFlows(f *fx, flows ...gdomain.FlowAllowance) {
	f.grant.Flows = flows
	f.w.Grants.Put(f.grant)
}

func itemOf(ev *pipeline.Evaluation, code string) (pipeline.Item, bool) {
	i := slices.IndexFunc(ev.Checklist, func(it pipeline.Item) bool { return it.Code == code })
	if i < 0 {
		return pipeline.Item{}, false
	}
	return ev.Checklist[i], true
}

// TestHR430_ReadClassFromDeclarationsObligationsAndFacts: an allowed read
// records the strictest class its definition declares, capped by the
// decision's data_classes obligation (or, for a scoped read, the strictest
// class the obligation allows), raised and never lowered by a
// classification fact; only ALLOW and ALLOW_WITH_OBLIGATIONS record it.
func TestHR430_ReadClassFromDeclarationsObligationsAndFacts(t *testing.T) {
	read := &defs.Definition{Access: defs.AccessRead, Response: &defs.ResponseSpec{Format: "json", Fields: []defs.ResponseField{
		{Path: "email", Class: "pii"}, {Path: "token", Class: "secret"}, {Path: "note", Class: "internal"},
	}}}
	classes := func(v ...string) []pdomain.Obligation {
		return []pdomain.Obligation{{Kind: pdomain.DataClasses, Values: v}}
	}
	scoped := &defs.Definition{Access: defs.AccessRead, Scoping: []string{"classes"}}
	for name, c := range map[string]struct {
		d          *defs.Definition
		obligs     []pdomain.Obligation
		classified string
		want       string
	}{
		"declared":                       {read, nil, "", "secret"},
		"capped by the obligation":       {read, classes("public", "internal", "pii"), "", "pii"},
		"an obligation never raises":     {&defs.Definition{Access: defs.AccessRead, Response: &defs.ResponseSpec{Fields: []defs.ResponseField{{Path: "a", Class: "internal"}}}}, classes("secret"), "", "internal"},
		"scoped: the strictest allowed":  {scoped, classes("internal", "pii"), "", "pii"},
		"scoped without an obligation":   {scoped, nil, "", ""},
		"raised by a fact":               {read, classes("internal"), "pii", "pii"},
		"a fact never lowers":            {read, nil, "public", "secret"},
		"a fact classifies the unknown":  {&defs.Definition{Access: defs.AccessRead}, nil, "pii", "pii"},
		"not a class raises nothing":     {&defs.Definition{Access: defs.AccessRead}, nil, "confidential", ""},
		"a write records no read class":  {&defs.Definition{Access: defs.AccessWrite, Response: read.Response}, nil, "secret", ""},
		"nothing declared, nothing said": {&defs.Definition{Access: defs.AccessRead}, nil, "", ""},
	} {
		if got := pipeline.ReadClass(c.d, c.obligs, c.classified); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	for _, d := range []adomain.Decision{adomain.Allow, adomain.AllowWithObligations} {
		if got := (&pipeline.Evaluation{Decision: d, ReadClass: "pii"}).RecordedReadClass(); got != "pii" {
			t.Errorf("%s records %q", d, got)
		}
	}
	for _, d := range []adomain.Decision{adomain.Deny, adomain.RequireApproval, adomain.CannotAuthorize, adomain.RequireStepUp} {
		if got := (&pipeline.Evaluation{Decision: d, ReadClass: "pii"}).RecordedReadClass(); got != "" {
			t.Errorf("%s records %q", d, got)
		}
	}
}

// TestHR431_ExternalDisclosureAfterASensitiveReadIsHeld: a public post
// after a pii read in the run tree needs approval (DATA_FLOW_HOLD); a
// flow of the grant that covers the class and the destination lets it
// through; an action without destinations never matches a flow; with no
// sensitive read, or through an internal destination, nothing applies.
func TestHR431_ExternalDisclosureAfterASensitiveReadIsHeld(t *testing.T) {
	f, gw, c := dataFlowFx(t, pipeline.ModeEnforce)
	expect(t, f.disclose(f.run, gw, c, slackChannel), adomain.Allow, pipeline.ReasonGrantCovers)

	f.w.AddSensitiveRead(sensitiveRead(f.run, "pii"))
	ev := f.disclose(f.run, gw, c, slackChannel)
	expect(t, ev, adomain.RequireApproval, pipeline.ReasonDataFlowHold)
	it, _ := itemOf(ev, pipeline.ReasonDataFlowHold)
	if it.Level != pipeline.DataFlowLevel || !strings.Contains(it.Detail, "pii") {
		t.Fatalf("hold item: %+v", it)
	}
	if len(ev.Requirements) != 1 || ev.Requirements[0].Source.Level != pipeline.DataFlowLevel || ev.Requirements[0].Source.Reason != pipeline.ReasonDataFlowHold {
		t.Fatalf("requirement: %+v", ev.Requirements)
	}

	withFlows(f, gdomain.FlowAllowance{Classes: []string{"pii"}, Destinations: []actionir.Destination{slackChannel}})
	ev = f.disclose(f.run, gw, c, slackChannel)
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	if _, ok := itemOf(ev, pipeline.ReasonDataFlowAllowed); !ok {
		t.Fatal("a covering flow is not shown")
	}
	// Another destination, no destination, or a class the flow lacks.
	expect(t, f.disclose(f.run, gw, c, actionir.Destination{Kind: "external", ID: "C0OTHER"}), adomain.RequireApproval, pipeline.ReasonDataFlowHold)
	expect(t, f.disclose(f.run, gw, c), adomain.RequireApproval, pipeline.ReasonDataFlowHold)
	f.w.AddSensitiveRead(sensitiveRead(f.run, "secret"))
	expect(t, f.disclose(f.run, gw, c, slackChannel), adomain.RequireApproval, pipeline.ReasonDataFlowHold)

	internal := connection(gw)
	internal.DestinationClass = "internal"
	f.w.PutConnection(internal)
	expect(t, f.disclose(f.run, gw, internal, slackChannel), adomain.Allow, pipeline.ReasonGrantCovers)

	// Reads never count as disclosure.
	ev = f.on(gw, c.ID, "get_refund", `{"refund":"re_1"}`)
	if _, ok := itemOf(ev, pipeline.ReasonDataFlowHold); ok {
		t.Fatal("a read was held as a disclosure")
	}
}

// TestHR431_UnreadableHistoryIsMissingEvidence: when the read history
// cannot be read, an external disclosure cannot be allowed.
func TestHR431_UnreadableHistoryIsMissingEvidence(t *testing.T) {
	f, gw, c := dataFlowFx(t, pipeline.ModeEnforce)
	f.w.Fail = map[string]bool{"SensitiveReads": true}
	expect(t, f.disclose(f.run, gw, c, slackChannel), adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable)
}

// TestT190_ReadsCountAcrossTheRunTree: pii read in a child run holds a
// public post in its parent and in a sibling; another tree is unaffected.
func TestT190_ReadsCountAcrossTheRunTree(t *testing.T) {
	f, gw, c := dataFlowFx(t, pipeline.ModeEnforce)
	child, sibling, other := f.newRun(f.grant.ID), f.newRun(f.grant.ID), f.newRun(f.grant.ID)
	f.w.SetParentRun(child, f.run)
	f.w.SetParentRun(sibling, f.run)
	f.w.AddSensitiveRead(sensitiveRead(child, "pii"))

	expect(t, f.disclose(f.run, gw, c, slackChannel), adomain.RequireApproval, pipeline.ReasonDataFlowHold)
	expect(t, f.disclose(sibling, gw, c, slackChannel), adomain.RequireApproval, pipeline.ReasonDataFlowHold)
	expect(t, f.disclose(other, gw, c, slackChannel), adomain.Allow, pipeline.ReasonGrantCovers)
}

// TestHR433_MonitorModeRecordsTheWouldHold: through a monitor-mode route
// the permit is issued, and the evaluation says an enforce-mode route
// would have held it for the data flow.
func TestHR433_MonitorModeRecordsTheWouldHold(t *testing.T) {
	f, gw, c := dataFlowFx(t, pipeline.ModeMonitor)
	ev := f.disclose(f.run, gw, c, slackChannel)
	if _, ok := ev.Would(); ok {
		t.Fatal("a would-hold without a sensitive read")
	}
	f.w.AddSensitiveRead(sensitiveRead(f.run, "secret"))
	ev = f.disclose(f.run, gw, c, slackChannel)
	would, ok := ev.Would()
	if !ev.MonitorPermit() || !ok || would != "HOLD: "+pipeline.ReasonDataFlowHold {
		t.Fatalf("monitor %v would %q %v", ev.MonitorPermit(), would, ok)
	}
	f2, gw2, c2 := dataFlowFx(t, pipeline.ModeEnforce)
	f2.w.AddSensitiveRead(sensitiveRead(f2.run, "secret"))
	if _, ok := f2.disclose(f2.run, gw2, c2, slackChannel).Would(); ok {
		t.Fatal("an enforce-mode evaluation reports a would-hold")
	}
}

// TestHR434_TheHoldNamesClassesAndTransactionsNeverContent: the hold's
// detail names the classes and the read transactions, and nothing of the
// action's parameters; read history holds only ids, classes and times.
func TestHR434_TheHoldNamesClassesAndTransactionsNeverContent(t *testing.T) {
	f, gw, c := dataFlowFx(t, pipeline.ModeEnforce)
	r := sensitiveRead(f.run, "pii")
	f.w.AddSensitiveRead(r)
	ev := f.disclose(f.run, gw, c, slackChannel)
	it, ok := itemOf(ev, pipeline.ReasonDataFlowHold)
	if !ok || !strings.Contains(it.Detail, r.TransactionID.String()) || !strings.Contains(it.Detail, "pii") {
		t.Fatalf("hold detail: %+v", it)
	}
	for _, v := range []string{"ch_1", "10.00", "duplicate", slackChannel.ID} {
		if strings.Contains(it.Detail, v) {
			t.Fatalf("the hold detail carries %q: %s", v, it.Detail)
		}
	}
}
