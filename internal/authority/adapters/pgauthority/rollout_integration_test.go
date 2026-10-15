// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Policy rollouts against the real Authority (G0 M11.1, D12, D13): per-agent
// selection, target status, and shadow evaluation beside the decision path.

var pgCapOver1000 = pdomain.Rule{
	ID: "cap", Kind: pdomain.Forbid, Summary: "no refunds over 1000", Operations: []string{"payments.refund.create"},
	When: `action.params.amount > money("1000", "USD")`, Reason: "REFUND_OVER_CAP",
}

// fakeGate stands in for the publish gate (D6): it says whether a version
// loosens and publishes through the test-setup helper, then records the
// rollout as the gate's hook does (the real gate runs the hook in the
// publishing transaction: rollout_gate_integration_test.go).
type fakeGate struct {
	w       *world
	svc     **rollout.Service
	loosens bool
	asked   int
}

func (g *fakeGate) CheckPilot(context.Context, ids.UUID, ids.UUID, *ids.UUID, []rollout.RolloutCohort) (*rollout.ChangeRequest, error) {
	if !g.loosens {
		return nil, nil
	}
	g.asked++
	return &rollout.ChangeRequest{ID: ids.NewV7(), URL: "/policy-changes/x"}, nil
}

func (g *fakeGate) Publish(ctx context.Context, version ids.UUID, base *ids.UUID) (*rollout.ChangeRequest, error) {
	if g.loosens {
		g.asked++
		return &rollout.ChangeRequest{ID: ids.NewV7(), URL: "/policy-changes/y"}, nil
	}
	policytest.PublishVersion(ctx, g.w.t, g.w.pool, g.w.org, version)
	return nil, g.w.pool.InTenantTx(ctx, g.w.org, func(ctx context.Context, tx db.TenantTx) error {
		return (*g.svc).Published(ctx, tx, g.w.org, version, base)
	})
}

type sentNotes struct{ sent []napp.Message }

func (n *sentNotes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

type rolloutWorld struct {
	*world
	svc   *rollout.Service
	gate  *fakeGate
	notes *sentNotes
	// publisher is a person holding policy.publish at the org.
	publisher context.Context
}

func (w *world) rollouts(ed billing.Edition) *rolloutWorld {
	w.t.Helper()
	rw := &rolloutWorld{world: w, notes: &sentNotes{}}
	eng := w.replayEngine()
	rw.svc = &rollout.Service{Pool: w.pool, Editions: &edition{ed}, Replay: eng, Receipts: eng.Source, Notify: rw.notes, Lag: -1}
	rw.gate = &fakeGate{w: w, svc: &rw.svc}
	rw.svc.Gate = rw.gate
	rw.publisher = w.reader(tdomain.RolePolicyPublisher, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()})
	return rw
}

func (rw *rolloutWorld) sweep() rollout.Swept {
	rw.t.Helper()
	s, err := rw.svc.SweepOrg(context.Background(), rw.org)
	if err != nil {
		rw.t.Fatal(err)
	}
	return s
}

func (rw *rolloutWorld) target(rollout ids.UUID) dbq.PcPolicyRolloutTarget {
	rw.t.Helper()
	var out dbq.PcPolicyRolloutTarget
	if err := rw.pool.InTenantTx(context.Background(), rw.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetRolloutTarget(ctx, rw.org, rollout, rw.agent)
		return err
	}); err != nil {
		rw.t.Fatalf("target: %v", err)
	}
	return out
}

// pilot publishes base, stores next as a draft, and starts a pilot of next
// on the cohort "pilot" holding the world's agent.
func (rw *rolloutWorld) pilot(next ...pdomain.Rule) ids.UUID {
	rw.t.Helper()
	ctx := rw.publisher
	rw.publishPolicy(1, false, pgCapOver1000)
	draft := rw.publishPolicy(2, true, next...)
	rw.tested(draft)
	if _, err := rw.svc.CreateCohort(ctx, "pilot"); err != nil {
		rw.t.Fatal(err)
	}
	if _, err := rw.svc.ChangeCohort(ctx, "pilot", []ids.UUID{rw.agent}, false); err != nil {
		rw.t.Fatal(err)
	}
	r, err := rw.svc.StartRollout(ctx, draft, nil)
	if err != nil {
		rw.t.Fatal(err)
	}
	if _, cr, err := rw.svc.StartPilot(ctx, r.ID, []string{"pilot"}); err != nil || cr != nil {
		rw.t.Fatalf("pilot: %v %v", cr, err)
	}
	return r.ID
}

func (rw *rolloutWorld) selection(r finalize.Result) (ref, rolloutID, selected string) {
	rw.t.Helper()
	rec, err := rw.replayEngine().RecordedInputs(context.Background(), rw.org, r.TransactionID, r.Evaluation)
	if err != nil {
		rw.t.Fatal(err)
	}
	p := rec.Reads.Policy
	return p.Ref, p.Rollout, p.Selected
}

// TestHR234_PilotSelectsItsVersionForTheCohortsAgentsOnly: the Authority
// decides an agent of a pilot's ENFORCE cohort under the pilot's version
// and records the selection; once the agent is excluded (EXCEPTION), or the
// rollout cancelled, the published version decides it again. Nothing in
// the request takes part in the selection.
func TestHR234_PilotSelectsItsVersionForTheCohortsAgentsOnly(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2", "ch_3", "ch_4")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})

	w.publishPolicy(1, false, pgCapOver1000)
	before := w.authorize(w.request(run, ids.NewV7(), "ch_1", "70.00"))
	if ref, _, sel := rw.selection(before); before.Decision != adomain.Allow || ref != "org-policy@1" || sel != pipeline.SelectedDefault {
		t.Fatalf("before the pilot: %s under %s (%s)", before.Decision, ref, sel)
	}
	draft := w.publishPolicy(2, true, pgCapOver1000, pgHoldOver50)
	ctx := rw.publisher
	w.tested(draft)
	if _, err := rw.svc.CreateCohort(ctx, "pilot"); err != nil {
		t.Fatal(err)
	}
	r, err := rw.svc.StartRollout(ctx, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A pilot on a cohort the agent is not in changes nothing for it.
	if _, _, err := rw.svc.StartPilot(ctx, r.ID, []string{"pilot"}); err != nil {
		t.Fatal(err)
	}
	if res := w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00")); res.Decision != adomain.Allow {
		t.Fatalf("an agent outside the cohort: %s", res.Decision)
	}
	if _, err := rw.svc.ChangeCohort(ctx, "pilot", []ids.UUID{w.agent}, false); err != nil {
		t.Fatal(err)
	}
	if tg := rw.target(r.ID); tg.State != rollout.TargetConfigured || tg.OwnerID == nil || *tg.OwnerID != w.alice {
		t.Fatalf("target: %+v", tg)
	}
	held := w.authorize(w.request(run, ids.NewV7(), "ch_3", "70.00"))
	ref, rid, sel := rw.selection(held)
	if held.Decision != adomain.RequireApproval || decisive(held) != "REFUND_OVER_50" || ref != "org-policy@2" ||
		rid != r.ID.String() || sel != pipeline.SelectedPilot {
		t.Fatalf("in the pilot: %s %s under %s (%s %s)", held.Decision, decisive(held), ref, rid, sel)
	}
	if _, err := rw.svc.ExcludeTarget(ctx, r.ID, w.agent, "the refund desk needs the old rules this week"); err != nil {
		t.Fatal(err)
	}
	excluded := w.authorize(w.request(run, ids.NewV7(), "ch_4", "70.00"))
	if ref, _, sel := rw.selection(excluded); excluded.Decision != adomain.Allow || ref != "org-policy@1" || sel != pipeline.SelectedDefault {
		t.Fatalf("excluded: %s under %s (%s)", excluded.Decision, ref, sel)
	}
	// Adding it to the cohort again does not undo a person's exclusion (D37).
	if _, err := rw.svc.ChangeCohort(ctx, "pilot", []ids.UUID{w.agent}, false); err != nil {
		t.Fatal(err)
	}
	rw.sweep()
	if tg := rw.target(r.ID); tg.State != rollout.TargetException {
		t.Fatalf("an excluded target moved: %+v", tg)
	}
}

// TestHR234_AVersionThatDoesNotCompileFallsBackAndTheTargetFails: a pilot
// version that cannot be compiled for an evaluation is not used; the
// published version decides (FALLBACK, recorded), and the sweeper marks the
// target FAILED and notifies the agent's owner, once.
func TestHR234_AVersionThatDoesNotCompileFallsBackAndTheTargetFails(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})
	broken := pdomain.Rule{
		ID: "needs-unknown-fact", Kind: pdomain.Forbid, Summary: "reads a fact no provider declares", Operations: []string{"payments.refund.create"},
		When: `facts.payments_unknown_flag`, Reason: "UNKNOWN_FLAG", Facts: []pdomain.FactRef{{Name: "payments.unknown.flag", MaxAgeSeconds: 60}},
	}
	id := rw.pilot(broken)
	res := w.authorize(w.request(run, ids.NewV7(), "ch_1", "70.00"))
	ref, rid, sel := rw.selection(res)
	if res.Decision != adomain.Allow || ref != "org-policy@1" || rid != id.String() || sel != pipeline.SelectedFallback {
		t.Fatalf("fallback: %s under %s (%s %s)", res.Decision, ref, rid, sel)
	}
	if s := rw.sweep(); s.Failed != 1 {
		t.Fatalf("sweep: %+v", s)
	}
	tg := rw.target(id)
	if tg.State != rollout.TargetFailed || tg.Reason == nil || *tg.Reason != "FALLBACK" {
		t.Fatalf("target: %+v", tg)
	}
	if len(rw.notes.sent) != 1 || rw.notes.sent[0].Type != "policy.rollout_target_failed" ||
		!slices.Equal(rw.notes.sent[0].Personal, []ids.UUID{w.alice}) || rw.notes.sent[0].Params["agent"] != w.agent.String() {
		t.Fatalf("notifications: %+v", rw.notes.sent)
	}
	w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00"))
	if s := rw.sweep(); s.Failed != 0 || len(rw.notes.sent) != 1 {
		t.Fatalf("a second fallback notified again: %+v %d", s, len(rw.notes.sent))
	}
}

// TestHR234_TargetsAreAcknowledgedThenVerifiedByCoverage: a decision under
// the pilot's version acknowledges the agent's target, never the Authority.
// It is VERIFIED only once every route of the agent for the version's exact
// operations (a prefix rule expanded against the active definitions) has an
// unexpired PARTIAL or ENFORCED snapshot, a missing one counting as
// UNKNOWN; without a route it stays ACKNOWLEDGED (NO_ROUTES), and a lapse
// takes it back (COVERAGE_LAPSED). An agent removed from the pilot's cohort
// is its EXCEPTION (REMOVED_FROM_COHORT) and keeps the published version.
func TestHR234_TargetsAreAcknowledgedThenVerifiedByCoverage(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})
	everyPayment := pdomain.Rule{
		ID: "payments-freeze", Kind: pdomain.Forbid, Summary: "no payment operation while frozen (off)", Operations: []string{"payments.*"},
		When: `false`, Reason: "PAYMENTS_FROZEN",
	}
	id := rw.pilot(pgCapOver1000, pgHoldOver50, everyPayment)
	w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
	if tg := rw.target(id); tg.State != rollout.TargetConfigured {
		t.Fatalf("the Authority changed the target: %+v", tg)
	}
	if s := rw.sweep(); s.Acknowledged != 1 {
		t.Fatalf("sweep: %+v", s)
	}
	reason := func(want, coverage string) {
		t.Helper()
		tg := rw.target(id)
		got := ""
		if tg.Reason != nil {
			got = *tg.Reason
		}
		cov := ""
		if tg.Coverage != nil {
			cov = *tg.Coverage
		}
		if got != want || cov != coverage {
			t.Fatalf("target: %s %q coverage %q, want %q coverage %q", tg.State, got, cov, want, coverage)
		}
	}
	reason("NO_ROUTES", "")
	// A route of the connection for every operation: each of the version's
	// operations needs its own snapshot.
	exec(t, w.pool, w.org, `INSERT INTO pc.coverage_routes (org_id, id, agent_id, connection_id, operation, kind, channel, observation, source)
		VALUES ($1, $2, $3, $4, NULL, 'channel', 'http', 'observed', 'gateway')`, w.org, ids.NewV7(), w.agent, w.conn)
	snapshot := func(op, state string) {
		entry := ids.NewV7()
		exec(t, w.pool, w.org, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
			VALUES ($1, $2, 'coverage.test', 'test', 'test', '\x7b7d')`, w.org, entry)
		exec(t, w.pool, w.org, `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons,
			body, body_sha256, ledger_entry_id) VALUES ($1, $2, $3, $4, $5, $6, '{}', '{}', $7, $8)`,
			w.org, ids.NewV7(), w.agent, w.conn, op, state, make([]byte, 32), entry)
	}
	snapshot("payments.refund.create", "PARTIAL")
	rw.sweep()
	reason("COVERAGE_UNKNOWN", "UNKNOWN") // the other payments operations have no snapshot
	defs, err := (&defpg.Store{Pool: w.pool}).ActiveDefinitions(context.Background(), w.org)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range defs {
		if strings.HasPrefix(d.Operation, "payments.") && d.Operation != "payments.refund.create" {
			snapshot(d.Operation, "PARTIAL")
		}
	}
	if s := rw.sweep(); s.Verified != 1 {
		t.Fatalf("sweep: %+v", s)
	}
	if tg := rw.target(id); tg.State != rollout.TargetVerified {
		t.Fatalf("verified: %+v", tg)
	}
	reason("", "PARTIAL")
	snapshot("payments.refund.create", "OBSERVE_ONLY")
	if s := rw.sweep(); s.Lapsed != 1 {
		t.Fatalf("sweep: %+v", s)
	}
	reason("COVERAGE_LAPSED", "OBSERVE_ONLY")
	if _, err := rw.svc.ChangeCohort(rw.publisher, "pilot", []ids.UUID{w.agent}, true); err != nil {
		t.Fatal(err)
	}
	if tg := rw.target(id); tg.State != rollout.TargetException || tg.Reason == nil || *tg.Reason != "REMOVED_FROM_COHORT" {
		t.Fatalf("removed from the cohort: %+v", tg)
	}
	res := w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00"))
	if ref, _, sel := rw.selection(res); ref != "org-policy@1" || sel != pipeline.SelectedDefault {
		t.Fatalf("after the removal: %s (%s)", ref, sel)
	}
	// Added back, it is CONFIGURED again (D37).
	if _, err := rw.svc.ChangeCohort(rw.publisher, "pilot", []ids.UUID{w.agent}, false); err != nil {
		t.Fatal(err)
	}
	if tg := rw.target(id); tg.State != rollout.TargetConfigured || tg.Reason != nil {
		t.Fatalf("added back: %+v", tg)
	}
}

// TestHR233_ShadowAddsNothingToTheDecisionPath: the same request evaluates
// to the same decision, decision basis and checklist with and without an
// active shadow of a version that would deny it (and after the sweeper
// replayed decisions for it), and decisions made while it is active record
// the published version's selection; the prediction exists only in the
// shadow's own rows.
func TestHR233_ShadowAddsNothingToTheDecisionPath(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2", "ch_3")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})
	w.publishPolicy(1, false, pgCapOver1000)
	draft := w.publishPolicy(2, true, pgCapOver1000, pgForbidOver20)
	ctx := context.Background()
	same := w.request(run, ids.NewV7(), "ch_1", "70.00")
	same.Gateway = w.gw.ID
	evaluate := func() *pipeline.Evaluation {
		ev, err := w.auth.Pipeline.Evaluate(ctx, same)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	without := evaluate()
	r, err := rw.svc.StartRollout(rw.publisher, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	with := evaluate()
	decided := w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00"))
	rw.sweep()
	afterSweep := evaluate()
	for _, ev := range []*pipeline.Evaluation{with, afterSweep} {
		if ev.Decision != without.Decision || ev.Basis.Digest() != without.Basis.Digest() || !sameChecklist(ev.Checklist, without.Checklist) {
			t.Fatalf("with a shadow: %s %s %+v\nwithout: %s %s %+v", ev.Decision, ev.Basis.Digest(), ev.Checklist,
				without.Decision, without.Basis.Digest(), without.Checklist)
		}
	}
	if without.Decision != adomain.Allow || decided.Decision != adomain.Allow {
		t.Fatalf("decisions: %s %s %+v", without.Decision, decided.Decision, without.Checklist)
	}
	if ref, rid, sel := rw.selection(decided); ref != "org-policy@1" || rid != "" || sel != pipeline.SelectedDefault {
		t.Fatalf("recorded selection with a shadow: %s %q %s", ref, rid, sel)
	}
	s, err := rw.svc.GetShadowSummary(rw.publisher, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.ByCategory[replay.NewlyDenied] != 1 || s.Total != 1 {
		t.Fatalf("the shadow's prediction: %+v", s)
	}
}

func sameChecklist(a, b []pipeline.Item) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// TestHR232_ShadowSweepWritesOnlyItsOwnRows: a sweep that replays shadow
// decisions writes no transaction, receipt, reservation, permit, claim,
// ledger entry or audit event: only the rollout's results, counts and
// cursor change.
func TestHR232_ShadowSweepWritesOnlyItsOwnRows(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2", "ch_3")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})
	w.publishPolicy(1, false, pgCapOver1000)
	draft := w.publishPolicy(2, true, pgCapOver1000, pgForbidOver20)
	if _, err := rw.svc.StartRollout(rw.publisher, draft, nil); err != nil {
		t.Fatal(err)
	}
	w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00"))
	w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00"))
	w.authorize(w.request(run, ids.NewV7(), "ch_3", "125.00"))
	before := w.rowCounts()
	if s := rw.sweep(); s.Shadowed != 3 || s.Replays != 6 {
		t.Fatalf("sweep: %+v", s)
	}
	after := w.rowCounts()
	changed := []string{}
	for tb, n := range before {
		if after[tb] != n {
			changed = append(changed, tb)
		}
	}
	slices.Sort(changed)
	if want := []string{"policy_rollout_cursors", "policy_shadow_counts", "policy_shadow_results"}; !slices.Equal(changed, want) {
		t.Fatalf("tables changed by the sweep: %v, want %v", changed, want)
	}
}

// TestHR237_ShadowSummaryIsLabelledAndCarriesNoInputValues: the summary
// counts by category, operation, agent and day, and samples by id, decision
// and reason; the amounts and charges the decisions read appear nowhere in
// it, and it says it is a prediction.
func TestHR237_ShadowSummaryIsLabelledAndCarriesNoInputValues(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_9731", "ch_9732")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})
	w.publishPolicy(1, false, pgCapOver1000)
	draft := w.publishPolicy(2, true, pgCapOver1000, pgForbidOver20)
	r, err := rw.svc.StartRollout(rw.publisher, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.authorize(w.request(run, ids.NewV7(), "ch_9731", "73.21"))
	w.authorize(w.request(run, ids.NewV7(), "ch_9732", "19.87"))
	rw.sweep()
	s, err := rw.svc.GetShadowSummary(w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s.Label != "shadow prediction, not enforcement" || s.Total != 2 || s.ByCategory[replay.NewlyDenied] != 1 ||
		s.ByCategory[replay.Unchanged] != 1 || len(s.ByOperation) == 0 || len(s.ByAgent) == 0 || len(s.Samples) != 1 {
		t.Fatalf("summary: %+v", s)
	}
	if s.ExpandedExposure != 0 || !strings.HasPrefix(s.ExpandedExposureNote, "expanded exposure: 0 ") {
		t.Fatalf("expanded exposure: %d %q", s.ExpandedExposure, s.ExpandedExposureNote)
	}
	raw, _ := json.Marshal(s)
	for _, secret := range []string{"ch_973", "73.21", "19.87"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the summary carries the input value %q: %s", secret, raw)
		}
	}
}

// TestT103_RolloutsCannotBeConfused: selection and rollouts are per org and
// per person: another org's agents, cohorts and rollouts are not found; a
// rollout's stages only move forward, and only one is open per org; a pilot
// or completion whose base changed is refused; a loosening pilot waits for
// a change request; Community and service accounts cannot start one; and
// without the publish gate nothing is enforced.
func TestT103_RolloutsCannotBeConfused(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	rw := w.rollouts(billing.Team)
	ctx := rw.publisher
	w.publishPolicy(1, false, pgCapOver1000)
	draft := w.publishPolicy(2, true, pgCapOver1000, pgHoldOver50)
	if _, err := rw.svc.CreateCohort(ctx, "pilot"); err != nil {
		t.Fatal(err)
	}
	other, _ := w.m7OtherOrg("other")
	otherAgent := ids.NewV7()
	exec(t, w.pool, other, `INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'theirs', 'DISCOVERED', 'test')`,
		other, otherAgent)
	if _, err := rw.svc.ChangeCohort(ctx, "pilot", []ids.UUID{otherAgent}, false); !errors.Is(err, rollout.ErrAgentNotFound) {
		t.Fatalf("another org's agent: %v", err)
	}
	if _, err := rw.svc.StartRollout(ctx, draft, []string{"nope"}); !errors.Is(err, rollout.ErrCohortNotFound) {
		t.Fatalf("an unknown cohort: %v", err)
	}
	r, err := rw.svc.StartRollout(ctx, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.svc.StartRollout(ctx, w.publishPolicy(3, true, pgHoldOver50), nil); !errors.Is(err, rollout.ErrRolloutOpen) {
		t.Fatalf("a second open rollout: %v", err)
	}
	otherCtx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{
		Org: other, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: ids.NewV7()},
		Bindings: []tdomain.Binding{{Role: tdomain.RolePolicyPublisher, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: other.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	if _, err := rw.svc.GetRollout(otherCtx, r.ID); !errors.Is(err, rollout.ErrNotFound) {
		t.Fatalf("another org's rollout: %v", err)
	}
	if _, err := rw.svc.CancelRollout(otherCtx, r.ID); !errors.Is(err, rollout.ErrNotFound) {
		t.Fatalf("another org cancelled it: %v", err)
	}
	sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{
		Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing},
		Bindings: []tdomain.Binding{{Role: tdomain.RolePolicyPublisher, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}}},
	}, Credential: tapp.CredAPIKey})
	if _, err := rw.svc.CancelRollout(sa, r.ID); !errors.Is(err, rollout.ErrHumanOnly) {
		t.Fatalf("a service account: %v", err)
	}
	community := w.rollouts(billing.Community)
	if _, err := community.svc.CreateCohort(ctx, "more"); !errors.Is(err, rollout.ErrEdition) {
		t.Fatalf("community cohort: %v", err)
	}
	if _, _, err := (&rollout.Service{Pool: w.pool, Editions: &edition{billing.Team}}).StartPilot(ctx, r.ID, []string{"pilot"}); !errors.Is(err, rollout.ErrGateMissing) {
		t.Fatalf("without a gate: %v", err)
	}
	// A loosening pilot waits for its change request; the rollout stays in shadow.
	rw.gate.loosens = true
	if _, cr, err := rw.svc.StartPilot(ctx, r.ID, []string{"pilot"}); err != nil || cr == nil || rw.gate.asked != 1 {
		t.Fatalf("a loosening pilot: %v %v", cr, err)
	}
	if got, _ := rw.svc.GetRollout(ctx, r.ID); got.Stage != rollout.StageShadow {
		t.Fatalf("stage after a loosening request: %s", got.Stage)
	}
	rw.gate.loosens = false
	// A pilot checked against a version that is no longer published fails.
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		stale := ids.NewV7()
		return rw.svc.EnterPilot(ctx, tx, tapp.Caller{}.Actor(), r.ID, &stale, nil)
	}); !errors.Is(err, rollout.ErrBaseChanged) {
		t.Fatalf("a stale base: %v", err)
	}
	if _, _, err := rw.svc.StartPilot(ctx, r.ID, []string{"pilot"}); err != nil {
		t.Fatal(err)
	}
	// Stages never move back, at the database too.
	err = w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.policy_rollouts SET stage = 'SHADOW' WHERE org_id = $1 AND id = $2`, w.org, r.ID)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Fatalf("a stage moved back: %v", err)
	}
	// A rollout's version and base, its cohorts' modes and shadow results
	// never change (D22).
	for _, sql := range []string{
		`UPDATE pc.policy_rollouts SET base_version_id = NULL WHERE org_id = $1`,
		`UPDATE pc.policy_rollouts SET version_id = version_id WHERE org_id = $1`,
		`UPDATE pc.policy_rollout_cohorts SET mode = 'SHADOW' WHERE org_id = $1`,
		`UPDATE pc.policy_shadow_results SET category = 'UNCHANGED' WHERE org_id = $1`,
		`UPDATE pc.policy_cohorts SET name = 'renamed' WHERE org_id = $1`,
	} {
		err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, w.org)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Fatalf("%s: %v, want permission denied", sql, err)
		}
	}
	// Another version published meanwhile: the pilot cannot grow or complete.
	w.publishPolicy(4, false, pgCapOver1000)
	if _, err := rw.svc.ExpandPilot(ctx, r.ID, []string{"pilot"}); !errors.Is(err, rollout.ErrBaseChanged) {
		t.Fatalf("expand after the base changed: %v", err)
	}
	if _, _, err := rw.svc.CompleteRollout(ctx, r.ID); !errors.Is(err, rollout.ErrBaseChanged) {
		t.Fatalf("complete after the base changed: %v", err)
	}
	if got, err := rw.svc.CancelRollout(ctx, r.ID); err != nil || got.Stage != rollout.StageCancelled {
		t.Fatalf("cancel: %v %v", got.Stage, err)
	}
	// A cohort holds at most 1,000 agents.
	if _, err := rw.svc.CreateCohort(ctx, "big"); err != nil {
		t.Fatal(err)
	}
	exec(t, w.pool, w.org, `WITH a AS (INSERT INTO pc.agents (org_id, id, name, state, created_by)
		SELECT $1, gen_random_uuid(), 'bot-' || g, 'DISCOVERED', 'test' FROM generate_series(1, 1000) g RETURNING org_id, id)
		INSERT INTO pc.policy_cohort_members (org_id, cohort_id, agent_id, added_by)
		SELECT a.org_id, c.id, a.id, 'test' FROM a, pc.policy_cohorts c WHERE c.org_id = $1 AND c.name = 'big'`, w.org)
	if _, err := rw.svc.ChangeCohort(ctx, "big", []ids.UUID{w.agent}, false); !errors.Is(err, rollout.ErrCohortFull) {
		t.Fatalf("a 1,001st agent: %v", err)
	}
}

// TestHR234_CompletingPublishesForEveryoneAndRecordsTargets: completing a
// pilot publishes its version through the gate, the rollout becomes
// COMPLETE in the publishing transaction, and every agent is a target; a
// publish without a rollout records a COMPLETE one too (every edition).
// The lister lists the org while targets are not verified.
func TestHR234_CompletingPublishesForEveryoneAndRecordsTargets(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1")
	rw := w.rollouts(billing.Team)
	id := rw.pilot(pgCapOver1000, pgHoldOver50)
	got, cr, err := rw.svc.CompleteRollout(rw.publisher, id)
	if err != nil || cr != nil || got.Stage != rollout.StageComplete || got.CompletedAt == nil || got.Targets[rollout.TargetConfigured] != 1 {
		t.Fatalf("complete: %+v %v %v", got, cr, err)
	}
	refs, err := w.pool.CrossOrgList(context.Background(), rollout.ListDue, 10000)
	if err != nil || !slices.ContainsFunc(refs, func(r db.OrgRef) bool { return r.Org == w.org }) {
		t.Fatalf("lister: %v %v", refs, err)
	}
	run := w.run(w.grant("500").ID, ids.UUID{})
	res := w.authorize(w.request(run, ids.NewV7(), "ch_1", "70.00"))
	if ref, _, sel := rw.selection(res); ref != "org-policy@2" || sel != pipeline.SelectedDefault {
		t.Fatalf("after completion: %s (%s)", ref, sel)
	}
	if s := rw.sweep(); s.Acknowledged != 1 {
		t.Fatalf("sweep: %+v", s)
	}
	v3 := w.publishPolicy(3, true, pgCapOver1000)
	if _, err := rw.gate.Publish(context.Background(), v3, nil); err != nil {
		t.Fatal(err)
	}
	all, err := rw.svc.ListRollouts(rw.publisher, 10)
	if err != nil || len(all) != 2 || all[0].VersionID != v3 || all[0].Stage != rollout.StageComplete || all[0].CreatedBy != "system:publish" {
		t.Fatalf("rollouts: %+v %v", all, err)
	}
}

// tested records a passing validation and test run of a stored draft, as
// the publish gate does before a pilot (TESTED: the Authority selects only a
// version that passed the gate, D31).
func (w *world) tested(id ids.UUID) {
	w.t.Helper()
	s := &polpg.Store{Pool: w.pool}
	ctx := context.Background()
	v, err := s.Version(ctx, w.org, id)
	if err != nil {
		w.t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], v.ContentDigest)
	if _, err := s.RecordValidation(ctx, w.org, id, digest, pdomain.ValidationResult{Passed: true}, "test"); err != nil {
		w.t.Fatal(err)
	}
	if _, err := s.RecordTestRun(ctx, w.org, id, digest, pdomain.TestResult{Passed: true}, "test"); err != nil {
		w.t.Fatal(err)
	}
}

// TestHR233_APilotsShadowCohortsAddNothingToTheDecisionPath: an agent in a
// PILOT's SHADOW cohort is decided exactly as without the rollout (same
// decision, basis and checklist, the published version's selection), and
// only the shadow's rows hold the prediction.
func TestHR233_APilotsShadowCohortsAddNothingToTheDecisionPath(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})
	w.publishPolicy(1, false, pgCapOver1000)
	draft := w.publishPolicy(2, true, pgCapOver1000, pgForbidOver20)
	w.tested(draft)
	ctx := rw.publisher
	for _, name := range []string{"watch", "pilot"} {
		if _, err := rw.svc.CreateCohort(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rw.svc.ChangeCohort(ctx, "watch", []ids.UUID{w.agent}, false); err != nil {
		t.Fatal(err)
	}
	same := w.request(run, ids.NewV7(), "ch_1", "70.00")
	same.Gateway = w.gw.ID
	evaluate := func() *pipeline.Evaluation {
		ev, err := w.auth.Pipeline.Evaluate(context.Background(), same)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	without := evaluate()
	r, err := rw.svc.StartRollout(ctx, draft, []string{"watch"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := rw.svc.StartPilot(ctx, r.ID, []string{"pilot"}); err != nil || got.Stage != rollout.StagePilot {
		t.Fatalf("pilot: %+v %v", got.Stage, err)
	}
	with := evaluate()
	decided := w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00"))
	rw.sweep()
	afterSweep := evaluate()
	for _, ev := range []*pipeline.Evaluation{with, afterSweep} {
		if ev.Decision != without.Decision || ev.Basis.Digest() != without.Basis.Digest() || !sameChecklist(ev.Checklist, without.Checklist) {
			t.Fatalf("in a pilot's shadow cohort: %s %s\nwithout: %s %s", ev.Decision, ev.Basis.Digest(), without.Decision, without.Basis.Digest())
		}
	}
	if ref, rid, sel := rw.selection(decided); decided.Decision != adomain.Allow || ref != "org-policy@1" || rid != "" || sel != pipeline.SelectedDefault {
		t.Fatalf("recorded selection: %s %s %q %s", decided.Decision, ref, rid, sel)
	}
	s, err := rw.svc.GetShadowSummary(ctx, r.ID)
	if err != nil || s.ByCategory[replay.NewlyDenied] != 1 || s.Total != 1 {
		t.Fatalf("the shadow's prediction: %+v %v", s, err)
	}
}

// TestHR232_ShadowStopsWithoutTheTeamEdition (D31): once the licence is no
// longer Team, the sweeper replays nothing for a shadow; it still follows
// the rollout's decisions.
func TestHR232_ShadowStopsWithoutTheTeamEdition(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1")
	rw := w.rollouts(billing.Team)
	run := w.run(w.grant("500").ID, ids.UUID{})
	w.publishPolicy(1, false, pgCapOver1000)
	draft := w.publishPolicy(2, true, pgCapOver1000, pgForbidOver20)
	r, err := rw.svc.StartRollout(rw.publisher, draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.authorize(w.request(run, ids.NewV7(), "ch_1", "70.00"))
	lapsed := w.rollouts(billing.Community)
	if s := lapsed.sweep(); s.Evaluations != 1 || s.Replays != 0 || s.Shadowed != 0 {
		t.Fatalf("sweep without Team: %+v", s)
	}
	if s, err := rw.svc.GetShadowSummary(rw.publisher, r.ID); err != nil || s.Total != 0 {
		t.Fatalf("summary: %+v %v", s, err)
	}
}
