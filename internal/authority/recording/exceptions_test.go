// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestRecordingKeepsTheExceptionsItApplied (G0 M11.1 D14): an evaluation
// that used a policy exception records it with the policy read, and its
// replay applies it as recorded: the same WAIVED item, the same decision.
func TestRecordingKeepsTheExceptionsItApplied(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	rule := pdomain.Rule{
		ID: "no-over-20", Kind: pdomain.Forbid, Summary: "no refunds over 20 USD", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("20.00", "USD")`, Reason: "REFUND_OVER_20", Exceptable: true,
	}
	policy(t, s, rule)
	d := pdomain.RuleDigest(rule)
	x := pdomain.Exception{
		ID: "01920000-0000-7000-8000-0000000000e1", Rule: rule.ID, RuleDigest: hex.EncodeToString(d[:]),
		Operations: []string{"payments.refund.create"}, ExpiresAt: s.W.Cont.Now.Add(time.Hour).UTC(),
	}
	s.W.SetExceptions([]pdomain.Exception{x})
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "30.00")
	orig, replayed, gaps := roundTrip(t, s, req)
	if orig.Decision != adomain.Allow || len(gaps) > 0 {
		t.Fatalf("original %s, gaps %v", orig.Decision, gaps)
	}
	if a, b := view(orig), view(replayed); a != b || !strings.Contains(a, string(pipeline.StatusWaived)) {
		t.Fatalf("the replay differs or waived nothing:\noriginal %s\nreplayed %s", a, b)
	}
	rec := recording.NewRecorder(s.W, req)
	if _, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req); err != nil {
		t.Fatal(err)
	}
	r, err := rec.Recording()
	if err != nil {
		t.Fatal(err)
	}
	got := r.Reads.Policy.Exceptions
	if len(got) != 1 || got[0].ID != x.ID || got[0].RuleDigest != x.RuleDigest || !got[0].ExpiresAt.Equal(x.ExpiresAt) {
		t.Fatalf("recorded exceptions %+v", got)
	}
}
