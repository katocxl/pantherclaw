// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// verifyOver50 is a policy rule that requires refunds over 50 USD to be
// verified at level (G0 M7 design decision 2).
func verifyOver50(level defs.Level) pdomain.Rule {
	return pdomain.Rule{
		ID: "verify-large", Kind: pdomain.Constrain, Summary: "refunds over 50 USD are verified", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("50.00", "USD")`, Reason: "VERIFY_LARGE_REFUNDS",
		Constraint: &pdomain.Constraint{Kind: pdomain.Verify, Level: level},
	}
}

// unsupported returns the VERIFIER_UNSUPPORTED item of ev, if any.
func unsupported(ev *pipeline.Evaluation) (pipeline.Item, bool) {
	for _, it := range ev.Checklist {
		if it.Code == pipeline.ReasonVerifierUnsupported {
			return it, true
		}
	}
	return pipeline.Item{}, false
}

// TestHR191_APolicyRaisesTheRequiredLevel: a verify obligation the
// definition's verifier reaches raises the level the verify plan requires,
// and the decision lists it as an obligation the Authority applies after
// dispatch; an action the rule does not match keeps the definition's level.
func TestHR191_APolicyRaisesTheRequiredLevel(t *testing.T) {
	f := newFx(t)
	if err := f.w.SetPolicy([]pdomain.Rule{verifyOver50(defs.LevelFollowUp)}, nil); err != nil {
		t.Fatal(err)
	}
	ev := f.call(f.run, "create_refund", refund("ch_1", "80.00"))
	expect(t, ev, adomain.AllowWithObligations, "VERIFY_LARGE_REFUNDS")
	if ev.Verify == nil || ev.Verify.Required != defs.LevelFollowUp || len(ev.Verify.Expected) != 3 {
		t.Fatalf("verify plan %+v", ev.Verify)
	}
	if len(ev.Obligations) != 1 || ev.Obligations[0].Kind != pdomain.Verify || ev.Obligations[0].Level != defs.LevelFollowUp ||
		ev.Obligations[0].Timing != pdomain.TimingAfterDispatch {
		t.Fatalf("obligations %+v", ev.Obligations)
	}
	if ev.EffectiveHash != ev.ActionHash {
		t.Fatal("a verify obligation changed the action")
	}
	if it := ev.Decisive(); it.Status != pipeline.StatusConstrained || it.Step != pipeline.StepRequirements ||
		it.Detail != "the effect must be verified at follow_up level" {
		t.Fatalf("the checklist explains the obligation: %+v", it)
	}

	small := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, small, adomain.Allow, pipeline.ReasonGrantCovers)
	if small.Verify == nil || small.Verify.Required != defs.LevelAcceptance || len(small.Obligations) != 0 {
		t.Fatalf("an unmatched rule: plan %+v obligations %+v", small.Verify, small.Obligations)
	}
}

// TestHR191_AnUnreachableLevelCannotBeAuthorized: a required level above
// what the definition's verifier reaches (it reaches follow_up) is
// CANNOT_AUTHORIZE with VERIFIER_UNSUPPORTED, naming the rule that asked
// for it; no verify plan is fixed (F497).
func TestHR191_AnUnreachableLevelCannotBeAuthorized(t *testing.T) {
	for _, level := range []defs.Level{defs.LevelDomainEffect, defs.LevelDownstream} {
		t.Run(string(level), func(t *testing.T) {
			f := newFx(t)
			if err := f.w.SetPolicy([]pdomain.Rule{verifyOver50(level)}, nil); err != nil {
				t.Fatal(err)
			}
			ev := f.call(f.run, "create_refund", refund("ch_1", "80.00"))
			expect(t, ev, adomain.CannotAuthorize, pipeline.ReasonVerifierUnsupported)
			it := ev.Decisive()
			if it.Step != pipeline.StepRequirements || it.Status != pipeline.StatusMissing || it.Level != "policy org-policy@1 rule verify-large" ||
				!strings.Contains(it.Detail, "reaches follow_up") {
				t.Fatalf("item %+v", it)
			}
			if ev.Verify != nil || ev.Permits() {
				t.Fatalf("an unsupported level fixed a plan %+v", ev.Verify)
			}
		})
	}
}

// TestHR191_AConnectionThatCannotServeTheReadCannotBeAuthorized: a
// required level above acceptance needs a connection whose pinned package
// serves every read the verifier names (its read and its lookup); one that
// does not is CANNOT_AUTHORIZE with VERIFIER_UNSUPPORTED. Without such a
// requirement the connection's reads do not matter.
func TestHR191_AConnectionThatCannotServeTheReadCannotBeAuthorized(t *testing.T) {
	f := newFx(t)
	put := func(reads []string) {
		c, err := f.w.Connection(context.Background(), org, f.conn)
		if err != nil {
			t.Fatal(err)
		}
		c.Reads = reads
		f.w.PutConnection(c)
	}
	put([]string{})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "80.00")), adomain.Allow, pipeline.ReasonGrantCovers)

	if err := f.w.SetPolicy([]pdomain.Rule{verifyOver50(defs.LevelFollowUp)}, nil); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		reads []string
		read  string
	}{
		"no reads":      {[]string{}, "payments.refund.get"},
		"no lookup":     {[]string{"payments.refund.get"}, "payments.refund.list"},
		"another reads": {[]string{"payments.refund.list", "payments.refund.recent"}, "payments.refund.get"},
	} {
		put(c.reads)
		ev := f.call(f.run, "create_refund", refund("ch_1", "80.00"))
		expect(t, ev, adomain.CannotAuthorize, pipeline.ReasonVerifierUnsupported)
		if it := ev.Decisive(); !strings.HasSuffix(it.Detail, "does not serve the verifier's read "+c.read) {
			t.Errorf("%s: %+v", name, it)
		}
	}
	put([]string{"payments.refund.get", "payments.refund.list"})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "80.00")), adomain.AllowWithObligations, "VERIFY_LARGE_REFUNDS")
}

// TestHR191_TheDefinitionsOwnRequirementIsCheckedToo: verifier.required in
// the package is checked like a policy's obligation: met through a
// connection that serves the reads, VERIFIER_UNSUPPORTED through one that
// does not, with the definition (no policy level) as its source.
func TestHR191_TheDefinitionsOwnRequirementIsCheckedToo(t *testing.T) {
	f := newFxWith(t, func(raw []byte) []byte {
		at := []byte("      level: follow_up\n")
		if !bytes.Contains(raw, at) {
			t.Fatal("the refund verifier's level moved; update the fixture")
		}
		return bytes.Replace(raw, at, []byte("      level: follow_up\n      required: follow_up\n"), 1)
	}, "")
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
	if ev.Verify == nil || ev.Verify.Required != defs.LevelFollowUp {
		t.Fatalf("verify plan %+v", ev.Verify)
	}
	c, err := f.w.Connection(context.Background(), org, f.conn)
	if err != nil {
		t.Fatal(err)
	}
	c.Reads = []string{}
	f.w.PutConnection(c)
	ev = f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.CannotAuthorize, pipeline.ReasonVerifierUnsupported)
	if it, _ := unsupported(ev); it.Level != "" {
		t.Fatalf("the definition's requirement names a level: %+v", it)
	}
}
