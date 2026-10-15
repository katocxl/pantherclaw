// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package replay_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
)

func TestClassifyDecisionChanges(t *testing.T) {
	const (
		allow = adomain.Allow
		awo   = adomain.AllowWithObligations
		step  = adomain.RequireStepUp
		appr  = adomain.RequireApproval
		deny  = adomain.Deny
		cant  = adomain.CannotAuthorize
	)
	for _, c := range []struct {
		before, after adomain.Decision
		br, ar        string
		want          replay.Category
	}{
		{allow, allow, "GRANTED", "GRANTED", replay.Unchanged},
		{deny, deny, "POLICY_FORBID", "POLICY_FORBID", replay.Unchanged},
		{allow, deny, "GRANTED", "POLICY_FORBID", replay.NewlyDenied},
		{appr, cant, "HOLD", "FACT_MISSING", replay.NewlyDenied},
		{awo, deny, "X", "Y", replay.NewlyDenied},
		{allow, appr, "GRANTED", "HOLD", replay.NewlyHeld},
		{allow, step, "GRANTED", "STEP_UP", replay.NewlyHeld},
		{step, appr, "STEP_UP", "HOLD", replay.NewlyHeld},
		{awo, step, "X", "Y", replay.NewlyHeld},
		{allow, awo, "GRANTED", "CONSTRAINED", replay.NewlyConstrained},
		{deny, allow, "POLICY_FORBID", "GRANTED", replay.NewlyAllowed},
		{appr, step, "HOLD", "STEP_UP", replay.NewlyAllowed},
		{cant, awo, "X", "Y", replay.NewlyAllowed},
		{awo, allow, "X", "X", replay.NewlyAllowed},
		{deny, cant, "POLICY_FORBID", "FACT_MISSING", replay.ReasonChanged},
		{cant, deny, "X", "X", replay.ReasonChanged},
		{deny, deny, "POLICY_FORBID", "OTHER_FORBID", replay.ReasonChanged},
		{allow, allow, "A", "B", replay.ReasonChanged},
		// An unknown decision ranks with DENY: never read as an allow.
		{adomain.Decision("BOGUS"), allow, "X", "X", replay.NewlyAllowed},
		{allow, adomain.Decision("BOGUS"), "X", "X", replay.NewlyDenied},
	} {
		if got := replay.Classify(c.before, c.after, c.br, c.ar); got != c.want {
			t.Errorf("%s/%s → %s/%s: %s, want %s", c.before, c.br, c.after, c.ar, got, c.want)
		}
	}
	for _, d := range []adomain.Decision{allow, awo, step, appr, deny, cant} {
		if got := replay.Classify(d, d, "R", "R"); got == replay.Unevaluable {
			t.Fatal("Classify never answers UNEVALUABLE")
		}
	}
}
