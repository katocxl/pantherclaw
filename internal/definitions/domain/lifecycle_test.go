// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
)

func TestLifecycleTransitions(t *testing.T) {
	allowed := map[[2]State]bool{
		{StateUnclassified, StateDraft}: true, {StateDraft, StateReviewed}: true, {StateReviewed, StateActive}: true,
		{StateActive, StateStale}: true, {StateActive, StateQuarantined}: true, {StateStale, StateReviewed}: true,
		{StateStale, StateQuarantined}: true, {StateQuarantined, StateReviewed}: true, {StateReviewed, StateQuarantined}: true,
	}
	for _, s := range Lifecycle.States() {
		if s != StateRetired {
			allowed[[2]State{s, StateRetired}] = true
		}
	}
	for _, from := range Lifecycle.States() {
		for _, to := range Lifecycle.States() {
			err := Lifecycle.Check(from, to)
			if want := allowed[[2]State{from, to}]; want != (err == nil) {
				t.Errorf("%s → %s: err = %v, want allowed=%v", from, to, err, want)
			}
			if err != nil && !errors.Is(err, statemachine.ErrIllegalTransition) {
				t.Errorf("%s → %s: %v", from, to, err)
			}
		}
	}
	if !Lifecycle.Terminal(StateRetired) {
		t.Error("RETIRED is terminal (F398)")
	}
	for _, s := range Lifecycle.States() {
		if s.Usable() != (s == StateActive) {
			t.Errorf("%s.Usable() = %v: only ACTIVE meaning maps actions", s, s.Usable())
		}
	}
}

// F404: nothing reaches ACTIVE without passing REVIEWED.
func TestActivationRequiresReview(t *testing.T) {
	for _, s := range Lifecycle.States() {
		if s != StateReviewed && Lifecycle.Can(s, StateActive) {
			t.Errorf("%s → ACTIVE skips review", s)
		}
	}
}

func TestHR123_PinsOnlyMoveForward(t *testing.T) {
	cur := &Pin{Package: "pc.mock-payments", Version: "1.2.0", Digest: "sha256:aa"}
	for _, c := range []struct {
		next Pin
		want error
	}{
		{Pin{"pc.mock-payments", "1.2.1", "sha256:bb"}, nil},
		{Pin{"pc.mock-payments", "1.10.0", "sha256:bb"}, nil},
		{Pin{"pc.mock-payments", "1.2.0", "sha256:aa"}, nil},
		{Pin{"pc.mock-payments", "1.1.9", "sha256:bb"}, ErrPinRollback},
		{Pin{"pc.mock-payments", "0.9.0", "sha256:aa"}, ErrPinRollback},
		{Pin{"pc.mock-payments", "1.2.0", "sha256:bb"}, ErrPinConflict},
		{Pin{"pc.other", "2.0.0", "sha256:bb"}, ErrInvalid},
		{Pin{"pc.mock-payments", "1.2", "sha256:bb"}, ErrInvalid},
	} {
		if err := CheckPinAdvance(cur, c.next); !errors.Is(err, c.want) && (err != nil || c.want != nil) {
			t.Errorf("%s → %+v: err = %v, want %v", cur.Version, c.next, err, c.want)
		}
	}
	if err := CheckPinAdvance(nil, Pin{"pc.mock-payments", "0.0.1", "sha256:aa"}); err != nil {
		t.Fatalf("first pin: %v", err)
	}
}

func consequencePackage() *Package {
	p := refundPackage()
	// The consequence operation is defined in the package: a virtual
	// write, never dispatched (G0 M8).
	p.Definitions = append(p.Definitions, Definition{
		Operation: "finance.notification.send", Summary: "Finance is notified of a large refund", Access: AccessWrite,
		Target:        TargetSpec{Type: "payments.charge", IDPattern: `^ch_[A-Za-z0-9]{1,64}$`, Account: PresenceNone},
		Effects:       []Effect{{Kind: "notify", Description: "Notifies finance"}},
		Reversibility: Compensatable, Retry: RetrySpec{OnUnknown: OnUnknownReconcile},
		Approval:  &ApprovalTemplate{Title: "Notify finance of {target.id}", Fields: []string{"target.id"}},
		Assurance: Assurance{Basis: BasisDocumented, ReviewedBy: []string{"Joshua Kato"}, ValidUntil: "2027-10-08"},
	})
	p.Consequences = []ConsequenceRule{{
		ID: "large-refund-notifies-finance", Operation: "payments.refund.create",
		When:          `action.params.amount > money("1000.00", "USD")`,
		RequiresFacts: []string{"payments.finance_notification.enabled"},
		Consequence:   Consequence{Operation: "finance.notification.send", Effect: "notify", Description: "Finance is notified"},
		ValidUntil:    "2027-10-08",
	}}
	return p
}

func TestConsequenceRules(t *testing.T) {
	if err := consequencePackage().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(c *ConsequenceRule){
		"id":              func(c *ConsequenceRule) { c.ID = "Large Refund" },
		"operation":       func(c *ConsequenceRule) { c.Operation = "payments.charge.create" },
		"no condition":    func(c *ConsequenceRule) { c.When = "" },
		"no facts":        func(c *ConsequenceRule) { c.RequiresFacts = nil },
		"fact name":       func(c *ConsequenceRule) { c.RequiresFacts = []string{"Finance!"} },
		"consequence op":  func(c *ConsequenceRule) { c.Consequence.Operation = "notify" },
		"undefined op":    func(c *ConsequenceRule) { c.Consequence.Operation = "finance.notification.page" },
		"effect":          func(c *ConsequenceRule) { c.Consequence.Effect = "" },
		"description":     func(c *ConsequenceRule) { c.Consequence.Description = "" },
		"validity":        func(c *ConsequenceRule) { c.ValidUntil = "forever" },
		"duplicate id":    func(c *ConsequenceRule) {},
		"long expression": func(c *ConsequenceRule) { c.When = longText(5000) },
	} {
		p := consequencePackage()
		mutate(&p.Consequences[0])
		if name == "duplicate id" {
			p.Consequences = append(p.Consequences, p.Consequences[0])
		}
		if err := p.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}
