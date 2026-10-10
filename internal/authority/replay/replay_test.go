// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package replay_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// source is a replay.Source over a scenario's world. It counts its reads;
// it has nothing to write with.
type source struct {
	s        *pipelinetest.Scenario
	versions map[ids.UUID]*pdomain.Bundle
	bundles  map[string]*pdomain.Bundle
	missing  map[string]bool // reads that find nothing
	reads    int
}

func newSource(s *pipelinetest.Scenario) *source {
	return &source{s: s, versions: map[ids.UUID]*pdomain.Bundle{}, bundles: map[string]*pdomain.Bundle{}, missing: map[string]bool{}}
}

func (x *source) Receipt(_ context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (string, error) {
	x.reads++
	if r := x.s.W.Receipt(txn, evaluation); r != "" && org == x.s.Org {
		return r, nil
	}
	return "", replay.ErrNotFound
}

func (x *source) Inputs(_ context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (recording.Sealed, error) {
	x.reads++
	if in := x.s.W.Inputs(txn, evaluation); in != nil && org == x.s.Org && !x.missing["inputs"] {
		return *in, nil
	}
	return recording.Sealed{}, replay.ErrNotFound
}

func (x *source) Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (*defs.Definition, error) {
	x.reads++
	p, err := x.s.W.Definition(ctx, org, pin)
	if err != nil || x.missing["definition"] {
		return nil, replay.ErrNotFound
	}
	return p.Definition, nil
}

func (x *source) Bundle(_ context.Context, _ ids.OrgID, bundle string, version int) (*pdomain.Bundle, error) {
	x.reads++
	if b := x.bundles[fmt.Sprintf("%s@%d", bundle, version)]; b != nil && !x.missing["bundle"] {
		return b, nil
	}
	return nil, replay.ErrNotFound
}

func (x *source) PolicyVersion(_ context.Context, _ ids.OrgID, id ids.UUID) (*pdomain.Bundle, error) {
	x.reads++
	if b := x.versions[id]; b != nil {
		return b, nil
	}
	return nil, replay.ErrNotFound
}

func (x *source) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	x.reads++
	return map[string]fdomain.Type{"payments.charge.refundable": fdomain.TypeBoolean}, nil
}

var catalog = map[string]fdomain.Type{"payments.charge.refundable": fdomain.TypeBoolean}

// publish publishes rules as the world's policy and keeps its bundle for
// the source, as policy_versions does.
func publish(t *testing.T, s *pipelinetest.Scenario, x *source, rules ...pdomain.Rule) {
	t.Helper()
	if err := s.W.SetPolicy(rules, catalog); err != nil {
		t.Fatal(err)
	}
	p, _ := s.W.Policy(t.Context(), s.Org)
	x.bundles[p.Version] = p.Compiled.Bundle
}

// propose stores a draft policy version and returns its id.
func propose(x *source, version int, rules ...pdomain.Rule) ids.UUID {
	id := ids.NewV7()
	x.versions[id] = &pdomain.Bundle{ID: "org-policy", Version: version, Rules: rules}
	return id
}

var (
	holdOver50 = pdomain.Rule{
		ID: "hold", Kind: pdomain.RequireApproval, Summary: "over 50 needs approval", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("50", "USD")`, Reason: "REFUND_OVER_50", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
	forbidOver20 = pdomain.Rule{
		ID: "no-large-refunds", Kind: pdomain.Forbid, Summary: "no refunds over 20", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("20", "USD")`, Reason: "REFUND_TOO_LARGE",
	}
)

type fixture struct {
	s      *pipelinetest.Scenario
	src    *source
	engine *replay.Engine
	run    ids.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	sealer := s.KeepInputs()
	src := newSource(s)
	return &fixture{s: s, src: src, engine: &replay.Engine{Source: src, Inputs: sealer}, run: s.Run(g.ID, s.Alice)}
}

func (f *fixture) refund(charge, amount string) finalize.Result {
	return f.s.Authorize(f.s.Request(f.run, ids.NewV7(), "create_refund", pipelinetest.Refund(charge, amount)))
}

func (f *fixture) replay(t *testing.T, r finalize.Result, proposed *ids.UUID) *replay.Outcome {
	t.Helper()
	out, err := f.engine.Replay(t.Context(), f.s.Org, r.TransactionID, r.Evaluation, proposed)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHR197_AnUnchangedReplayReproducesTheOriginalDecision: decisions of
// every kind replay to the same decision, decisive reason and basis, with
// no differences (F504).
func TestHR197_AnUnchangedReplayReproducesTheOriginalDecision(t *testing.T) {
	f := newFixture(t)
	publish(t, f.s, f.src, holdOver50)
	for name, r := range map[string]finalize.Result{
		"allowed":       f.refund("ch_1", "30.00"),
		"held":          f.refund("ch_2", "70.00"),
		"denied":        f.refund("ch_3", "500.00"),
		"fact missing":  f.refund("ch_9", "10.00"),
		"repeat parked": f.refund("ch_1", "30.00"),
	} {
		out := f.replay(t, r, nil)
		if !out.Complete || !out.Reproduced || !out.SameDecision || len(out.Differences) > 0 || out.Decision != r.Decision ||
			out.BasisDigest != r.BasisDigest || out.Policy != "org-policy@1" || out.Proposed {
			t.Errorf("%s: outcome = %+v, original %s %s", name, out, r.Decision, decisive(r))
		}
	}
}

func decisive(r finalize.Result) string {
	for _, x := range r.Reasons {
		if x.Decisive {
			return x.Code
		}
	}
	return ""
}

// TestHR197_AProposedPolicyThatDeniesShowsTheDifferingRule: under a
// proposed version with a FORBID rule, the allowed refund is denied, and
// the difference names the boundaries check, the rule and the policy
// change (F505, F506).
func TestHR197_AProposedPolicyThatDeniesShowsTheDifferingRule(t *testing.T) {
	f := newFixture(t)
	publish(t, f.s, f.src, holdOver50)
	ok := f.refund("ch_1", "30.00")
	if ok.Decision != adomain.Allow {
		t.Fatalf("original: %+v", ok)
	}
	draft := propose(f.src, 2, holdOver50, forbidOver20)
	out := f.replay(t, ok, &draft)
	if !out.Complete || out.Decision != adomain.Deny || out.Reason != "REFUND_TOO_LARGE" || out.SameDecision || out.Reproduced ||
		!out.Proposed || out.Policy != "org-policy@2" || out.Original.Decision != adomain.Allow {
		t.Fatalf("outcome = %+v", out)
	}
	i := slices.IndexFunc(out.Differences, func(d replay.Difference) bool { return d.Step == pipeline.StepBoundaries })
	if i < 0 {
		t.Fatalf("differences = %+v", out.Differences)
	}
	d := out.Differences[i]
	if d.Check != "boundaries" || !slices.Equal(d.Rules, []string{"no-large-refunds"}) ||
		!slices.ContainsFunc(d.Inputs, func(s string) bool {
			return strings.Contains(s, "org-policy@1 replaced by proposed policy org-policy@2")
		}) {
		t.Fatalf("difference = %+v", d)
	}
	// A proposed policy that changes nothing for this action: same decision.
	same := propose(f.src, 3, holdOver50)
	if out := f.replay(t, ok, &same); !out.Complete || !out.SameDecision || out.Reproduced || len(out.Differences) > 0 {
		t.Fatalf("an equivalent proposal: %+v", out)
	}
}

// TestHR197_ANewRequirementNeedsReadsTheEvaluationNeverMade: a proposed
// policy that holds the action needs the approval request reads, which the
// original never made: the replay is incomplete and says which, never a
// guess (F507).
func TestHR197_ANewRequirementNeedsReadsTheEvaluationNeverMade(t *testing.T) {
	f := newFixture(t)
	ok := f.refund("ch_1", "70.00") // no policy published
	draft := propose(f.src, 1, holdOver50)
	out := f.replay(t, ok, &draft)
	if out.Complete || out.Reproduced || out.Decision == adomain.Allow ||
		!slices.ContainsFunc(out.Incomplete, func(l replay.Limitation) bool {
			return l.Code == replay.IncompleteInputUnavailable && l.Step == pipeline.StepRequirements
		}) {
		t.Fatalf("outcome = %+v", out)
	}
	if !slices.ContainsFunc(out.Notes, func(n string) bool { return strings.Contains(n, "current fact types") }) {
		t.Fatalf("notes = %v", out.Notes)
	}
}

// TestHR197_RemovedOrTruncatedInputsGiveAnIncompleteReplay: missing,
// truncated or unreadable inputs, another pipeline version, a definition
// or policy version gone: each is an incomplete replay with its reason,
// and none presents a decision as reproduced (F507).
func TestHR197_RemovedOrTruncatedInputsGiveAnIncompleteReplay(t *testing.T) {
	f := newFixture(t)
	publish(t, f.s, f.src, holdOver50)
	ok := f.refund("ch_1", "30.00")
	check := func(name, code string, step int) {
		t.Helper()
		out := f.replay(t, ok, nil)
		if out.Complete || out.Reproduced || !slices.ContainsFunc(out.Incomplete, func(l replay.Limitation) bool {
			return l.Code == code && (step == 0 || l.Step == step)
		}) {
			t.Errorf("%s: outcome = %+v", name, out)
		}
	}
	f.src.missing["inputs"] = true
	check("removed inputs", replay.IncompleteInputsMissing, 0)
	f.src.missing["inputs"] = false

	sealed := f.s.W.Inputs(ok.TransactionID, 1)
	keep := *sealed
	sealed.Truncated, sealed.Inputs = true, nil
	check("truncated inputs", replay.IncompleteInputsTruncated, 0)
	*sealed = keep
	sealed.Pipeline = pipeline.Version + 1
	check("another pipeline version", replay.IncompletePipelineVersion, 0)
	*sealed = keep
	sealed.Inputs = slices.Clone(keep.Inputs)
	sealed.Inputs[len(sealed.Inputs)-1] ^= 1
	check("tampered inputs", replay.IncompleteInputsUnreadable, 0)
	*sealed = keep

	f.src.missing["definition"] = true
	check("a definition gone", replay.IncompleteInputUnavailable, pipeline.StepScope)
	f.src.missing["definition"] = false
	f.src.missing["bundle"] = true
	check("a policy version gone", replay.IncompleteInputUnavailable, pipeline.StepFacts)
	f.src.missing["bundle"] = false

	if out := f.replay(t, ok, nil); !out.Reproduced {
		t.Fatalf("restored: %+v", out)
	}
	// An evaluation that does not exist, and a proposed version that does
	// not exist, are not found.
	if _, err := f.engine.Replay(t.Context(), f.s.Org, ok.TransactionID, 2, nil); err == nil {
		t.Fatal("an evaluation without a receipt replayed")
	}
	missing := ids.NewV7()
	if _, err := f.engine.Replay(t.Context(), f.s.Org, ok.TransactionID, 1, &missing); err == nil {
		t.Fatal("an unknown proposed version replayed")
	}
}

// TestHR197_ReplayHoldsNoStoreAndWritesNothing: the engine's ports only
// read (no method of theirs writes, finalizes, reserves, dispatches or
// signs); replaying leaves the world's transactions, receipts, permits,
// claims and budgets as they were (F508).
func TestHR197_ReplayHoldsNoStoreAndWritesNothing(t *testing.T) {
	reads := map[string]bool{"Receipt": true, "Inputs": true, "Definition": true, "Bundle": true, "PolicyVersion": true, "Catalog": true, "Open": true}
	e := reflect.TypeFor[replay.Engine]()
	store := reflect.TypeFor[finalize.Store]()
	for i := range e.NumField() {
		ft := e.Field(i).Type
		if ft.Kind() != reflect.Interface || ft.Implements(store) {
			t.Fatalf("Engine.%s is %s: an engine holds read ports only", e.Field(i).Name, ft)
		}
		for m := range ft.NumMethod() {
			if name := ft.Method(m).Name; !reads[name] {
				t.Errorf("Engine.%s has method %s, not a read", e.Field(i).Name, name)
			}
		}
	}

	f := newFixture(t)
	publish(t, f.s, f.src, holdOver50)
	ok := f.refund("ch_1", "30.00")
	held := f.refund("ch_2", "70.00")
	before := snapshot(f, ok, held)
	draft := propose(f.src, 2, forbidOver20)
	for _, r := range []finalize.Result{ok, held} {
		f.replay(t, r, nil)
		f.replay(t, r, &draft)
	}
	if after := snapshot(f, ok, held); after != before {
		t.Fatalf("a replay changed the world:\nbefore %s\nafter  %s", before, after)
	}
	if f.src.reads == 0 {
		t.Fatal("the replays read nothing")
	}
}

// snapshot is what a replay must not change: the stored transactions, the
// receipts and inputs of the evaluations, the permit's state, the claims
// and the budgets.
func snapshot(f *fixture, results ...finalize.Result) string {
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "%s/%d receipt=%d inputs=%v permit=%s evaluation2=%v;", r.TransactionID, r.Evaluation,
			len(f.s.W.Receipt(r.TransactionID, r.Evaluation)), f.s.W.Inputs(r.TransactionID, r.Evaluation) != nil,
			f.s.W.PermitState(r.PermitID), f.s.W.Receipt(r.TransactionID, r.Evaluation+1) != "")
	}
	fmt.Fprintf(&b, "events=%v", f.s.W.SecurityEvents())
	return b.String()
}

// TestT074_OutcomesCarryNoInputValues: an outcome holds decisions and
// checklists, never the recorded values (the task label, the key
// thumbprint, the canonical action), which need evidence.read_restricted
// (design decision 11).
func TestT074_OutcomesCarryNoInputValues(t *testing.T) {
	f := newFixture(t)
	publish(t, f.s, f.src, holdOver50)
	r := f.refund("ch_1", "70.00")
	draft := propose(f.src, 2, forbidOver20)
	for _, proposed := range []*ids.UUID{nil, &draft} {
		out := f.replay(t, r, proposed)
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", `"duplicate"`, f.s.Instance.String()} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("the outcome carries an input value %q", secret)
			}
		}
	}
}

// TestT074_ATamperingDenialReplaysWithoutThePipeline: the inputs of a
// tampering denial replay to the same denial, whatever policy is proposed.
func TestT074_ATamperingDenialReplaysWithoutThePipeline(t *testing.T) {
	f := newFixture(t)
	act := ids.NewV7()
	open := f.s.Authorize(f.s.Request(f.run, act, "create_refund", pipelinetest.Refund("ch_9", "10.00")))
	tampered := f.s.Authorize(f.s.Request(f.run, act, "create_refund", pipelinetest.Refund("ch_9", "11.00")))
	if open.Decision != adomain.CannotAuthorize || tampered.Evaluation != 2 {
		t.Fatalf("open %+v, tampered %+v", open, tampered)
	}
	draft := propose(f.src, 1, forbidOver20)
	for _, proposed := range []*ids.UUID{nil, &draft} {
		out := f.replay(t, tampered, proposed)
		if !out.Complete || out.Decision != adomain.Deny || out.Reason != adomain.ReasonActionTampered || !out.SameDecision ||
			out.Reproduced == (proposed != nil) {
			t.Fatalf("outcome = %+v", out)
		}
	}
}

// TestRecordedInputsAreTheValuesRead: the restricted accessor returns the
// recording itself, and a missing one is not found.
func TestRecordedInputsAreTheValuesRead(t *testing.T) {
	f := newFixture(t)
	r := f.refund("ch_1", "30.00")
	rec, err := f.engine.RecordedInputs(t.Context(), f.s.Org, r.TransactionID, 1)
	if err != nil || rec.Reads.Containment == nil || len(rec.Reads.Facts) != 1 {
		t.Fatalf("inputs = %+v, %v", rec, err)
	}
	if _, err := f.engine.RecordedInputs(t.Context(), f.s.Org, r.TransactionID, 2); !errors.Is(err, replay.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}
