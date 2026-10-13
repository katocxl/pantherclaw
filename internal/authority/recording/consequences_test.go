// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestRecordingReplaysConsequences (HR-206, HR-197): an evaluation whose
// action has consequence rules records their ids with the definition, and
// its replay decides each consequence again from the recorded facts:
// predicted, unknown or not triggered alike. Rules that are not the ones
// recorded are a gap, never a different decision.
func TestRecordingReplaysConsequences(t *testing.T) {
	for name, tc := range map[string]struct {
		members  map[string]any
		decision adomain.Decision
		state    consequences.State
	}{
		"predicted":     {map[string]any{"state": "scheduled", "environments": []any{"payroll"}}, adomain.Allow, consequences.Predicted},
		"not triggered": {map[string]any{"state": "none", "environments": []any{}}, adomain.Allow, consequences.NotTriggered},
		"unknown":       {nil, adomain.CannotAuthorize, consequences.Unknown},
	} {
		t.Run(name, func(t *testing.T) {
			s := pipelinetest.NewScenario(t, pipelinetest.PayoutConsequence)
			if tc.members != nil {
				s.W.PutFact(fdomain.Fact{
					Name: "payments.charge.payouts", SubjectType: "payments.charge", SubjectID: "ch_1",
					Value: fdomain.Value{Type: fdomain.TypeObject, Object: tc.members}, ObservedAt: s.W.Cont.Now.Add(-time.Second), ProviderID: ids.NewV7(),
				})
			}
			g := s.Grant(pipelinetest.PayoutBounds, s.Alice)
			orig, replayed, gaps := roundTrip(t, s, refund(s, s.Run(g.ID, s.Alice), "ch_1", "30.00"))
			if orig.Decision != tc.decision || len(orig.Consequences) != 1 || orig.Consequences[0].State != tc.state {
				t.Fatalf("original = %s %+v", orig.Decision, orig.Consequences)
			}
			if len(gaps) > 0 {
				t.Fatalf("gaps: %v", gaps)
			}
			if a, b := view(orig), view(replayed); a != b {
				t.Fatalf("the replay differs:\noriginal %s\nreplayed %s", a, b)
			}
		})
	}

	s := pipelinetest.NewScenario(t, pipelinetest.PayoutConsequence)
	g := s.Grant(pipelinetest.PayoutBounds, s.Alice)
	req := refund(s, s.Run(g.ID, s.Alice), "ch_1", "30.00")
	rec := recording.NewRecorder(s.W, req)
	if _, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rec, req); err != nil {
		t.Fatal(err)
	}
	r, err := rec.Recording()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(r.Reads.Definitions, func(d recording.Definition) bool { return len(d.Consequences) > 0 })
	if i < 0 || !slices.Equal(r.Reads.Definitions[i].Consequences, []string{"refund-triggers-payout"}) {
		t.Fatalf("recorded definitions %+v", r.Reads.Definitions)
	}
	served := served(t, s, r)
	for digest := range served.Consequences {
		served.Consequences[digest] = nil // as if the version's rules had changed
	}
	rd := recording.NewReader(s.Org, r, served)
	if _, err := (&pipeline.Pipeline{}).EvaluateWith(t.Context(), rd, req); err != nil {
		t.Fatal(err)
	}
	if gaps := rd.Gaps(); !slices.ContainsFunc(gaps, func(g recording.Gap) bool { return strings.Contains(g.Detail, "consequence rules") }) {
		t.Fatalf("other rules than the recorded ones: gaps %v", gaps)
	}
}
