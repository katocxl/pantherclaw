// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// boundRefunds binds a refund's reason to the charge's state object, as a
// merge is bound to its pull request's head (pc.github's
// github.pull.head.sha == params.sha), and names that fact as the one
// whose change supersedes its approval requests.
func boundRefunds(raw []byte) []byte {
	raw = bytes.Replace(raw, []byte("      - fact: payments.charge.refundable\n        max_age_seconds: 300\n"),
		[]byte("      - fact: payments.charge.refundable\n        max_age_seconds: 300\n      - fact: payments.charge.state\n"+
			"        max_age_seconds: 300\n        binds: {member: reason, param: reason, reason: STATE_MOVED}\n"), 1)
	return bytes.Replace(raw, []byte("      fields: [params.amount, params.reason, target.id]\n"),
		[]byte("      fields: [params.amount, params.reason, target.id]\n      invalidate_on: payments.charge.state\n"), 1)
}

func (f *fx) state(charge string, members map[string]any) {
	f.w.PutFact(fdomain.Fact{
		Name: "payments.charge.state", SubjectType: "payments.charge", SubjectID: charge,
		Value: fdomain.Value{Type: fdomain.TypeObject, Object: members}, ObservedAt: now.Add(-time.Second), RecordedAt: now, ProviderID: f.provider,
	})
}

// TestHR205_ABoundParamMustMatchItsFact: an action whose definition binds
// a param to a fact member (a merge to its pull request's head) is decided
// only while the current fact says the same: otherwise it is
// CANNOT_AUTHORIZE with the binding's reason, naming both values, and a new
// decision at the current value can follow. A hold of such an action
// carries the key whose fact change supersedes it.
func TestHR205_ABoundParamMustMatchItsFact(t *testing.T) {
	f := newFxWith(t, boundRefunds, "")
	f.state("ch_1", map[string]any{"reason": "duplicate"})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.Allow, pipeline.ReasonGrantCovers)

	f.state("ch_1", map[string]any{"reason": "fraudulent"})
	ev := f.call(f.run, "create_refund", refund("ch_1", "30.00"))
	expect(t, ev, adomain.CannotAuthorize, "STATE_MOVED")
	if d := ev.Decisive().Detail; !strings.Contains(d, "params.reason is duplicate") || !strings.Contains(d, "payments.charge.state.reason is fraudulent") {
		t.Fatalf("detail %q", d)
	}
	f.state("ch_1", map[string]any{"other": "x"})
	expect(t, f.call(f.run, "create_refund", refund("ch_1", "30.00")), adomain.CannotAuthorize, "STATE_MOVED")

	f.state("ch_1", map[string]any{"reason": "duplicate"})
	if err := f.w.SetPolicy([]pdomain.Rule{approvalOver50()}, nil); err != nil {
		t.Fatal(err)
	}
	ev = f.call(f.run, "create_refund", refund("ch_1", "70.00"))
	if ev.Decision != adomain.RequireApproval || ev.Hold == nil || ev.Hold.InvalidationKey != "payments.charge.state[reason]@payments.charge:ch_1" {
		t.Fatalf("hold %s %+v", ev.Decision, ev.Hold)
	}
}
