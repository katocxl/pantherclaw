// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strings"
	"testing"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

var allKinds = []bdomain.Kind{
	bdomain.KindNewTool, bdomain.KindNewDestination, bdomain.KindUnusualHour,
	bdomain.KindNewSequence, bdomain.KindVolumeSpike, bdomain.KindSpendSpike,
}

// TestHR644_EverySignalIsLabeledInferenceAtMostAnAlert: whatever the kind,
// a behavior signal is valid, rests on INFERRED, says UNVALIDATED and the
// label, extends pc.drift.behavior, never asks for more than ALERT, and is
// never a CONFIRMED alert, so it can't start a contain step (HR-640). A
// simulated one is a test signal (HR-222, HR-642). Covers: F932, F933
func TestHR644_EverySignalIsLabeledInferenceAtMostAnAlert(t *testing.T) {
	org := ids.New[ids.Org]()
	for _, origin := range []bdomain.Origin{bdomain.OriginReal, bdomain.OriginSimulated} {
		for _, k := range allKinds {
			a := bdomain.Action{
				ID: ids.NewV7(), Agent: ids.NewV7(), Run: ids.NewV7(), Operation: "secrets.dump", Connection: ids.NewV7(),
				At: time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC),
			}
			s := signal(org, origin, found{
				Deviation: bdomain.Deviation{Kind: k, Value: strings.Repeat("v", 5000), Action: a, Text: "Never done secrets.dump"},
				profile:   bdomain.BehaviorProfile{Actions: 120, ActiveDays: 14},
			})
			if err := s.Validate(); err != nil {
				t.Fatalf("%s %s: %v", origin, k, err)
			}
			if s.Basis != reflexdomain.BasisInferred || s.Basis.Confirmed() || s.Source != reflexdomain.SourceBehavior {
				t.Errorf("%s %s: basis %s source %s", origin, k, s.Basis, s.Source)
			}
			if s.Attention.AtLeast(reflexdomain.AttentionIncident) || !s.Attention.Valid() {
				t.Errorf("%s %s: attention %s", origin, k, s.Attention)
			}
			if !strings.HasPrefix(s.RuleID, ruleRoot) || s.Facts["basis"] != bdomain.Basis ||
				s.Facts["definition_status"] != bdomain.DefinitionStatus || !strings.Contains(s.Summary, bdomain.Label) {
				t.Errorf("%s %s: unlabeled %+v", origin, k, s)
			}
			if len(s.Facts["value"]) > reflexdomain.MaxFactValue {
				t.Errorf("%s %s: value of %d bytes", origin, k, len(s.Facts["value"]))
			}
			simulated := origin == bdomain.OriginSimulated
			if s.Test != simulated || strings.HasPrefix(s.Title, "SIMULATED: ") != simulated {
				t.Errorf("%s %s: test %v title %q", origin, k, s.Test, s.Title)
			}
		}
	}
}

// TestHR644_ABehaviorSignalAboveAlertOrNotInferredIsRefused: Reflex itself
// refuses a behavior signal that claims more. Covers: F932
func TestHR644_ABehaviorSignalAboveAlertOrNotInferredIsRefused(t *testing.T) {
	a := bdomain.Action{ID: ids.NewV7(), Agent: ids.NewV7(), Run: ids.NewV7(), Operation: "x", At: time.Now()}
	ok := signal(ids.New[ids.Org](), bdomain.OriginReal, found{Deviation: bdomain.Deviation{Kind: bdomain.KindNewTool, Value: "x", Action: a, Text: "x"}})
	for name, change := range map[string]func(*reflexdomain.Signal){
		"incident": func(s *reflexdomain.Signal) { s.Attention = reflexdomain.AttentionIncident },
		"observed": func(s *reflexdomain.Signal) { s.Basis = reflexdomain.BasisObserved },
		"matched":  func(s *reflexdomain.Signal) { s.Basis = reflexdomain.BasisRuleMatch },
	} {
		s := ok
		change(&s)
		if s.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
