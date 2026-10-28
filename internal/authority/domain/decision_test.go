// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "testing"

func TestDecisionPermits(t *testing.T) {
	if !Allow.Permits() || !AllowWithObligations.Permits() || Deny.Permits() || CannotAuthorize.Permits() || RequireApproval.Permits() ||
		RequireStepUp.Permits() {
		t.Fatal("Permits is wrong")
	}
}

func TestOutcomeDecisive(t *testing.T) {
	o := Outcome{Decision: Deny, Reasons: []Reason{{Code: "A"}, {Code: "B", Decisive: true}}}
	if o.Decisive() != "B" {
		t.Fatalf("Decisive = %q, want the decisive reason", o.Decisive())
	}
	if (Outcome{Reasons: []Reason{{Code: "A"}}}).Decisive() != "A" || (Outcome{}).Decisive() != "" {
		t.Fatal("Decisive without a decisive reason is the first one, or empty")
	}
}

// Covers: F069
func TestDecisionPresentation(t *testing.T) {
	for d, want := range map[Decision]struct {
		p     Presentation
		label string
	}{
		Allow:                {PresentAllow, "Allow"},
		AllowWithObligations: {PresentConstrain, "Constrain"},
		RequireApproval:      {PresentHold, "Hold"},
		RequireStepUp:        {PresentHold, "Hold"},
		Deny:                 {PresentDeny, "Deny"},
		CannotAuthorize:      {PresentCannotAuthorize, "Cannot authorize"},
		Decision("BOGUS"):    {PresentCannotAuthorize, "Cannot authorize"},
	} {
		if got := d.Presentation(); got != want.p || got.Label() != want.label {
			t.Errorf("%s: presentation %s %q, want %s %q", d, got, got.Label(), want.p, want.label)
		}
	}
	if PresentAllow.Explains() || PresentConstrain.Explains() || !PresentHold.Explains() || !PresentDeny.Explains() ||
		!PresentCannotAuthorize.Explains() {
		t.Fatal("only Hold, Deny and Cannot authorize name a failing category")
	}
}
