// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// replayable is one scenario: a world and the request it decides.
type replayable struct {
	name     string
	setup    func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request
	decision adomain.Decision
	code     string
}

var holdOver50 = pdomain.Rule{
	ID: "hold", Kind: pdomain.RequireApproval, Summary: "over 50 needs approval", Operations: []string{"payments.refund.create"},
	When: `action.params.amount > money("50", "USD")`, Reason: "REFUND_OVER_50", Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
}

func refund(s *pipelinetest.Scenario, run ids.UUID, charge, amount string) pipeline.Request {
	return s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund(charge, amount))
}

func policy(t *testing.T, s *pipelinetest.Scenario, rules ...pdomain.Rule) {
	t.Helper()
	if err := s.W.SetPolicy(rules, map[string]fdomain.Type{"payments.charge.refundable": fdomain.TypeBoolean}); err != nil {
		t.Fatal(err)
	}
}

func limits(t *testing.T, s *pipelinetest.Scenario, doc string) ids.UUID {
	t.Helper()
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	lim, err := gdomain.DecodeLimits([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	g.Revision, g.Limits = 2, lim
	s.W.Grants.Put(g)
	return s.Run(g.ID, s.Alice)
}

var scenarios = []replayable{
	{"allowed", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		return refund(s, run, "ch_1", "30.00")
	}, adomain.Allow, pipeline.ReasonGrantCovers},
	{"over the grant's bound", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		return refund(s, run, "ch_1", "500.00")
	}, adomain.Deny, ""},
	{"a fact missing", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		return refund(s, run, "ch_9", "30.00")
	}, adomain.CannotAuthorize, fdomain.ReasonFactMissing},
	{"a policy that forbids", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		policy(t, s, pdomain.Rule{
			ID: "small", Kind: pdomain.Forbid, Summary: "no refunds over 20", Operations: []string{"payments.refund.create"},
			When: `action.params.amount > money("20", "USD") && facts.payments_charge_refundable`, Reason: "TOO_LARGE",
		})
		return refund(s, run, "ch_1", "30.00")
	}, adomain.Deny, "TOO_LARGE"},
	{"a policy that holds", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		policy(t, s, holdOver50)
		return refund(s, run, "ch_1", "70.00")
	}, adomain.RequireApproval, "REFUND_OVER_50"},
	{"an approved hold", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		policy(t, s, holdOver50)
		req := refund(s, run, "ch_1", "70.00")
		ev, err := s.Authority.Pipeline.Evaluate(t.Context(), req)
		if err != nil || ev.Hold == nil {
			t.Fatalf("hold: %v %+v", err, ev)
		}
		s.W.SetHold(ev.RunID, ev.ActionID, &pipeline.HoldRequest{
			ID: ids.NewV7(), State: "APPROVED", Binding: ev.Hold.Binding.Hash, Deadline: ev.Hold.Deadline, ConsumeBy: &ev.Hold.Deadline,
		})
		return req
	}, adomain.Allow, ""},
	{"a repeat parked", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		if res := s.Authorize(refund(s, run, "ch_2", "30.00")); res.Decision != adomain.Allow {
			t.Fatalf("first: %+v", res)
		}
		return refund(s, run, "ch_2", "30.00")
	}, adomain.CannotAuthorize, pipeline.ReasonReconciliation},
	{"a task budget", func(t *testing.T, s *pipelinetest.Scenario, _ ids.UUID) pipeline.Request {
		run := limits(t, s, `{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.*"], "currency": "USD", "limit": "100", "period": "none"}]}`)
		if res := s.Authorize(refund(s, run, "ch_1", "80.00")); res.Decision != adomain.Allow {
			t.Fatalf("first: %+v", res)
		}
		return refund(s, run, "ch_2", "30.00")
	}, adomain.Deny, gdomain.ReasonBudgetExhausted},
	{"a counter", func(t *testing.T, s *pipelinetest.Scenario, _ ids.UUID) pipeline.Request {
		run := limits(t, s, `{"counters": [{"id": "per_charge", "operations": ["payments.refund.create"], "key": "target", "window": "day", "max": "2"}]}`)
		return refund(s, run, "ch_3", "10.00")
	}, adomain.Allow, ""},
	{"a guardrail", func(t *testing.T, s *pipelinetest.Scenario, _ ids.UUID) pipeline.Request {
		env := gdomain.Envelope{ID: gdomain.NewEnvelopeID(), Org: s.Org, Revision: 1, Scope: gdomain.Scope{Kind: gdomain.ScopeTeam, ID: s.Team}, Name: "payments"}
		env.Bounds, _ = gdomain.DecodeBounds([]byte(`{"operations": ["payments.refund.get"]}`))
		if err := s.W.Grants.PutEnvelope(t.Context(), s.Org, env, false, audit.Event{Name: "test.event", Outcome: audit.Success}); err != nil {
			t.Fatal(err)
		}
		g := s.Grant(pipelinetest.RootBounds, s.Alice)
		return refund(s, s.Run(g.ID, s.Alice), "ch_1", "10.00")
	}, adomain.Deny, gdomain.ReasonOutsideGuardrail},
	{"an unknown run", func(_ *testing.T, s *pipelinetest.Scenario, _ ids.UUID) pipeline.Request {
		return refund(s, ids.NewV7(), "ch_1", "10.00")
	}, adomain.Deny, pipeline.ReasonRunMismatch},
	{"the kill switch", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		s.W.Cont.KillSwitch = true
		return refund(s, run, "ch_1", "10.00")
	}, adomain.Deny, adomain.ReasonKillSwitch},
	{"a quarantined connection", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		c, _ := s.W.Connection(context.Background(), s.Org, s.Connection)
		c.State = "QUARANTINED"
		s.W.PutConnection(c)
		return refund(s, run, "ch_1", "10.00")
	}, adomain.Deny, pipeline.ReasonConnectionContained},
	{"a monitor-mode route", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		c, _ := s.W.Connection(context.Background(), s.Org, s.Connection)
		c.DefaultMode = pipeline.ModeMonitor
		s.W.PutConnection(c)
		return refund(s, run, "ch_1", "500.00")
	}, adomain.Deny, ""},
	{"a definition not active", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		s.W.SetState("payments.refund.create", defs.StateReviewed)
		return refund(s, run, "ch_1", "10.00")
	}, adomain.CannotAuthorize, pipeline.ReasonDefinitionNotActive},
	{"a read that failed", func(_ *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		s.W.Fail["Facts"] = true
		return refund(s, run, "ch_1", "10.00")
	}, adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable},
	{"a policy read that failed", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		policy(t, s, holdOver50)
		s.W.Fail["Policy"] = true
		return refund(s, run, "ch_1", "70.00")
	}, adomain.CannotAuthorize, pipeline.ReasonEvidenceUnavailable},
	// Step 8's verification checks (G0 M7, F497): the connection's reads
	// are recorded with it.
	{"a verify obligation", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		policy(t, s, verifyAt(defs.LevelFollowUp))
		return refund(s, run, "ch_1", "30.00")
	}, adomain.AllowWithObligations, "VERIFY_REFUNDS"},
	{"a level no verifier reaches", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		policy(t, s, verifyAt(defs.LevelDomainEffect))
		return refund(s, run, "ch_1", "30.00")
	}, adomain.CannotAuthorize, pipeline.ReasonVerifierUnsupported},
	{"a connection that cannot make the read", func(t *testing.T, s *pipelinetest.Scenario, run ids.UUID) pipeline.Request {
		policy(t, s, verifyAt(defs.LevelFollowUp))
		c, _ := s.W.Connection(context.Background(), s.Org, s.Connection)
		c.Reads = []string{"payments.refund.recent"}
		s.W.PutConnection(c)
		return refund(s, run, "ch_1", "30.00")
	}, adomain.CannotAuthorize, pipeline.ReasonVerifierUnsupported},
}

func verifyAt(level defs.Level) pdomain.Rule {
	return pdomain.Rule{
		ID: "verify", Kind: pdomain.Constrain, Summary: "refunds are verified", Operations: []string{"payments.refund.create"},
		When: "true", Reason: "VERIFY_REFUNDS", Constraint: &pdomain.Constraint{Kind: pdomain.Verify, Level: level},
	}
}

// TestRecordingReplaysEveryScenarioExactly records each scenario's
// evaluation, encodes and decodes the recording, and evaluates it again
// from the recording alone (with the definition and the policy loaded by
// reference): the evaluation is the same, and nothing was missing.
func TestRecordingReplaysEveryScenarioExactly(t *testing.T) {
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			s := pipelinetest.NewScenario(t, nil)
			g := s.Grant(pipelinetest.RootBounds, s.Alice)
			req := sc.setup(t, s, s.Run(g.ID, s.Alice))
			orig, replayed, gaps := roundTrip(t, s, req)
			if orig.Decision != sc.decision || (sc.code != "" && orig.Decisive().Code != sc.code) {
				t.Fatalf("original = %s %s, want %s %s", orig.Decision, orig.Decisive().Code, sc.decision, sc.code)
			}
			if len(gaps) > 0 {
				t.Fatalf("gaps: %v", gaps)
			}
			if a, b := view(orig), view(replayed); a != b {
				t.Fatalf("the replay differs:\noriginal %s\nreplayed %s", a, b)
			}
		})
	}
}

// roundTrip evaluates req through a Recorder, round-trips the recording
// through its JSON, and evaluates it again from a Reader.
func roundTrip(t *testing.T, s *pipelinetest.Scenario, req pipeline.Request) (*pipeline.Evaluation, *pipeline.Evaluation, []recording.Gap) {
	t.Helper()
	ctx := t.Context()
	rec := recording.NewRecorder(s.W, req)
	orig, err := (&pipeline.Pipeline{}).EvaluateWith(ctx, rec, req)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rec.Recording()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := recording.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := recording.Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	if again, _ := recording.Encode(decoded); !bytes.Equal(raw, again) {
		t.Fatalf("the encoding is not stable:\n%s\n%s", raw, again)
	}
	rd := recording.NewReader(s.Org, decoded, served(t, s, decoded))
	req2, err := rd.Request()
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := (&pipeline.Pipeline{}).EvaluateWith(ctx, rd, req2)
	if err != nil {
		t.Fatal(err)
	}
	return orig, replayed, rd.Gaps()
}

// served loads what the recording names by reference, as a replay does:
// each definition by its pin, and the policy's bundle compiled again from
// the recorded reference.
func served(t *testing.T, s *pipelinetest.Scenario, r *recording.Recording) recording.Served {
	t.Helper()
	out := recording.Served{Definitions: map[string]*defs.Definition{}}
	for _, d := range r.Reads.Definitions {
		if d.Err != "" {
			continue
		}
		p, err := s.W.Definition(t.Context(), s.Org, d.Pin)
		if err != nil {
			t.Fatal(err)
		}
		out.Definitions[d.Digest] = p.Definition
	}
	if p := r.Reads.Policy; p != nil && p.Err == "" && !p.None {
		s.W.Fail["Policy"] = false
		cur, err := s.W.Policy(t.Context(), s.Org)
		if err != nil {
			t.Fatal(err)
		}
		if out.Policy, err = p.Compile(cur.Compiled.Bundle); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// view is everything an evaluation decides and binds, as text.
func view(ev *pipeline.Evaluation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "decision=%s checklist=%+v basis=%s %+v act=%s eff=%s dedupe=%s window=%s epoch=%d now=%s mode=%s op=%s\n",
		ev.Decision, ev.Checklist, ev.Basis.Digest(), ev.Basis, ev.ActionHash, ev.EffectiveHash, ev.DedupeKey, ev.RepeatWindow,
		ev.Epoch, ev.Now.UTC().Format(time.RFC3339Nano), ev.Mode, ev.Operation)
	fmt.Fprintf(&b, "obligations=%+v approvals=%+v stepups=%+v requirements=%+v labels=%v identity=%+v\n",
		ev.Obligations, ev.Approvals, ev.StepUps, ev.Requirements, ev.Labels, ev.Identity)
	fmt.Fprintf(&b, "chain=%+v plan=%d/%d rows=%d/%d\n", ev.Chain.Versions(), len(ev.Plan.Budgets), len(ev.Plan.Counters),
		len(ev.Rows.Accounts), len(ev.Rows.Counters))
	for _, d := range ev.Plan.Budgets {
		fmt.Fprintf(&b, "budget %s %s %s row=%s\n", d.Ref.Rule, d.Amount, d.Ref.Start.UTC().Format(time.RFC3339), ev.Rows.Accounts[d.Ref])
	}
	for _, d := range ev.Plan.Counters {
		fmt.Fprintf(&b, "counter %s %x row=%s\n", d.Ref.Rule, d.Ref.Key, ev.Rows.Counters[d.Ref])
	}
	if ev.Amount != nil {
		fmt.Fprintf(&b, "amount=%s\n", ev.Amount)
	}
	if c := ev.Connection; c != nil {
		fmt.Fprintf(&b, "connection=%+v\n", *c)
	}
	if h := ev.Hold; h != nil {
		fmt.Fprintf(&b, "hold binding=%x display=%x deadline=%s state=%s code=%s keep=%v satisfied=%v expire=%v reqs=%+v\n",
			h.Binding.Hash, h.DisplayHash, h.Deadline.UTC().Format(time.RFC3339), h.State, h.Code, h.Keep, h.Satisfied, h.Expire,
			h.Requirements)
	}
	return b.String()
}

// TestRecordingKeepsEveryReadOfAnEvaluation: what a held refund read is
// all in its recording.
func TestRecordingKeepsEveryReadOfAnEvaluation(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	policy(t, s, holdOver50)
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "70.00")
	rec := recording.NewRecorder(s.W, req)
	if _, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req); err != nil {
		t.Fatal(err)
	}
	r, err := rec.Recording()
	if err != nil {
		t.Fatal(err)
	}
	x := r.Reads
	if x.Containment == nil || len(x.Definitions) != 1 || x.Policy == nil || len(x.Runs) != 1 || len(x.Agents) != 1 ||
		len(x.Chains) != 1 || len(x.Envelopes) != 1 || len(x.Facts) != 1 || len(x.Claims) != 1 || len(x.Connections) != 1 ||
		len(x.Holds) != 1 || len(x.Variants) != 1 || x.HoldSettings == nil {
		t.Fatalf("reads = %+v", x)
	}
	if r.Format != recording.FormatVersion || r.Pipeline != pipeline.Version {
		t.Fatalf("versions = %d, %d", r.Format, r.Pipeline)
	}
	// By reference: the definition by its digest, the policy by version.
	if x.Definitions[0].Digest != req.Action.Action.Definition.Digest || x.Policy.Ref != "org-policy@1" ||
		x.Policy.Catalog["payments.charge.refundable"] != "boolean" {
		t.Fatalf("references = %+v %+v", x.Definitions[0], x.Policy)
	}
	if !bytes.Equal(r.Request.Action, req.Action.Canonical) {
		t.Fatal("the canonical action is not recorded as it was decided")
	}
}

// TestRecordingReaderListsReadsItDoesNotHold: a replay that needs a read
// the evaluation never made gets ErrNotRecorded and a gap, never a guess
// (HR-197, F507).
func TestRecordingReaderListsReadsItDoesNotHold(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "70.00") // no policy: no hold reads
	rec := recording.NewRecorder(s.W, req)
	if _, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req); err != nil {
		t.Fatal(err)
	}
	r, _ := rec.Recording()
	// A proposed policy that holds and needs another fact.
	proposed, err := r.Reads.Policy.Proposed(&pdomain.Bundle{ID: "org-policy", Version: 2, Rules: []pdomain.Rule{
		holdOver50,
		{
			ID: "fraud", Kind: pdomain.Forbid, Summary: "no refunds on disputed charges", Operations: []string{"payments.refund.create"},
			When: `facts.payments_charge_disputed`, Reason: "DISPUTED", Facts: []pdomain.FactRef{{Name: "payments.charge.disputed", MaxAgeSeconds: 300}},
		},
	}}, map[string]fdomain.Type{"payments.charge.disputed": fdomain.TypeBoolean})
	if err != nil {
		t.Fatal(err)
	}
	sv := served(t, s, r)
	sv.Policy, sv.Proposed = proposed, true
	rd := recording.NewReader(s.Org, r, sv)
	req2, _ := rd.Request()
	ev, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rd, req2)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Decision != adomain.CannotAuthorize || ev.Decisive().Code != pipeline.ReasonEvidenceUnavailable {
		t.Fatalf("decision = %s %s, want CANNOT_AUTHORIZE for the facts never read: %+v", ev.Decision, ev.Decisive().Code, ev.Checklist)
	}
	gaps := rd.Gaps()
	if !slices.ContainsFunc(gaps, func(g recording.Gap) bool {
		return g.Read == "facts" && g.Step == pipeline.StepFacts && strings.Contains(g.Detail, "payments.charge.disputed")
	}) {
		t.Fatalf("gaps = %v", gaps)
	}
	if _, err := rd.HoldSettings(t.Context(), s.Org); !errors.Is(err, recording.ErrNotRecorded) {
		t.Fatalf("hold settings: %v", err)
	}
	if _, err := rd.Containment(t.Context(), ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000b2")); !errors.Is(err, recording.ErrNotRecorded) {
		t.Fatalf("another org's containment: %v", err)
	}
}
