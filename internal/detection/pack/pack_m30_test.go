// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pack

import (
	"fmt"
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// enumeration is n allowed reads of distinct targets by run r1 within the
// window.
func enumeration(n int) []rules.TestEvent {
	out := make([]rules.TestEvent, 0, n)
	for i := range n {
		out = append(out, rules.TestEvent{
			Kind: "receipt.decision", Decision: "ALLOW", Operation: "crm.customer.read",
			Subjects: map[string]string{"run": "r1"}, Attrs: map[string]string{"target_digest": fmt.Sprintf("t%02d", i)},
			At: fmt.Sprintf("%ds", 5*(i+1)),
		})
	}
	return out
}

// sends are executions toward a public destination by agent a1 through c1
// from n distinct runs, an hour apart.
func sends(n int, class string) []rules.TestEvent {
	out := make([]rules.TestEvent, 0, n)
	for i := range n {
		out = append(out, rules.TestEvent{
			Kind: "receipt.execution", DestinationClass: class,
			Subjects: map[string]string{"agent": "a1", "connection": "c1", "run": fmt.Sprintf("r%d", i)},
			At:       fmt.Sprintf("%dh", i),
		})
	}
	return out
}

// TestHR709_EnumerationAndScheduledSendsRaiseInferredAlerts: 60 distinct
// targets read by one run in 10 minutes, and 12 runs of one agent sending
// to one public connection in 24 hours, fire; both rules are INFERRED
// alerts in Business (G0 M30 D931, D931b, D932, D947b).
//
// Covers: HR-709
func TestHR709_EnumerationAndScheduledSendsRaiseInferredAlerts(t *testing.T) {
	if !fires(t, "pc.reads.enumeration", enumeration(60)...) {
		t.Error("60 distinct reads did not fire")
	}
	if !fires(t, "pc.exfil.scheduled_sends", sends(12, "public")...) {
		t.Error("12 runs sending out did not fire")
	}
	p, err := Load(env(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range p.Rules {
		if c.Rule.ID != "pc.reads.enumeration" && c.Rule.ID != "pc.exfil.scheduled_sends" {
			continue
		}
		seen++
		if c.Rule.Basis != reflexdomain.BasisInferred || c.Rule.Attention != reflexdomain.AttentionAlert || c.Rule.Edition != "business" {
			t.Errorf("%s: basis %s attention %s edition %s", c.Rule.ID, c.Rule.Basis, c.Rule.Attention, c.Rule.Edition)
		}
	}
	if seen != 2 {
		t.Fatalf("%d of the two rules loaded", seen)
	}
}

// TestHR709_BelowTheThresholdsNothingFires: 59 targets, one target read
// many times, sends from fewer runs or to an internal destination stay
// quiet.
//
// Covers: HR-709
func TestHR709_BelowTheThresholdsNothingFires(t *testing.T) {
	same := enumeration(70)
	for i := range same {
		same[i].Attrs = map[string]string{"target_digest": "t00"}
	}
	for name, events := range map[string][]rules.TestEvent{
		"59 targets": enumeration(59),
		"one target": same,
	} {
		if fires(t, "pc.reads.enumeration", events...) {
			t.Errorf("%s fired", name)
		}
	}
	if fires(t, "pc.exfil.scheduled_sends", sends(11, "public")...) {
		t.Error("11 runs fired")
	}
	if fires(t, "pc.exfil.scheduled_sends", sends(12, "internal")...) {
		t.Error("internal sends fired")
	}
}

// TestT323_BulkReadsAndDripSendsAreAlertedNotHeld: the enumeration and
// scheduled-send rules only raise signals; the volume itself is limited by
// a grant's read rule (HR-706), which nothing applies by default (T-323).
//
// Covers: T-323
func TestT323_BulkReadsAndDripSendsAreAlertedNotHeld(t *testing.T) {
	if !fires(t, "pc.reads.enumeration", enumeration(60)...) || !fires(t, "pc.exfil.scheduled_sends", sends(12, "public")...) {
		t.Fatal("bulk reads and drip sends did not raise both alerts")
	}
	p, err := Load(env(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Rules {
		if (c.Rule.ID == "pc.reads.enumeration" || c.Rule.ID == "pc.exfil.scheduled_sends") &&
			(c.Rule.Attention == reflexdomain.AttentionIncident || c.Rule.Attention == reflexdomain.AttentionPage) {
			t.Errorf("%s escalates beyond an alert", c.Rule.ID)
		}
	}
}
