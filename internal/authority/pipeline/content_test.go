// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	active   = "ACTIVE"
	watching = "WATCHING"
)

var injected = []pipeline.PayloadFinding{{Kind: "injection_phrase", Location: "arg/note"}}

func (f *fx) contentEval(findings ...pipeline.PayloadFinding) *pipeline.Evaluation {
	f.t.Helper()
	req := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "10.00"))
	req.ContentFindings = findings
	return f.eval(req)
}

// rank orders decisions from the most open to the strictest.
func rank(d adomain.Decision) int {
	switch d {
	case adomain.Allow:
		return 0
	case adomain.AllowWithObligations:
		return 1
	case adomain.RequireApproval, adomain.RequireStepUp:
		return 2
	case adomain.CannotAuthorize:
		return 3
	case adomain.Deny:
		return 4
	default:
		return 4
	}
}

// TestHR648_FlagHoldsALaterWriteNotARead: a flag on the run tree holds a
// write in ACTIVE, and the item is decisive.
//
// Covers: F939
func TestHR648_FlagHoldsALaterWriteNotARead(t *testing.T) {
	f := newFx(t)
	f.w.SetContentSignals(active, "injection_phrase")
	ev := f.contentEval()
	if ev.Decision != adomain.RequireApproval {
		t.Fatalf("decision %s", ev.Decision)
	}
	it, ok := itemOf(ev, pipeline.ReasonContentFlagHold)
	if !ok || !strings.Contains(it.Detail, "inference") {
		t.Fatalf("%+v %v", it, ok)
	}
}

// TestHR648_OutboundFlagHoldsNow: an outbound flag holds its own action.
//
// Covers: F939
func TestHR648_OutboundFlagHoldsNow(t *testing.T) {
	f := newFx(t)
	f.w.SetContentSignals(active)
	if ev := f.contentEval(injected...); ev.Decision != adomain.RequireApproval {
		t.Fatalf("decision %s", ev.Decision)
	}
}

// TestHR650_ScanIncompleteHolds: a scan that could not finish holds like any
// flag, on the action and on the run.
//
// Covers: F939
func TestHR650_ScanIncompleteHolds(t *testing.T) {
	f := newFx(t)
	f.w.SetContentSignals(active)
	if ev := f.contentEval(pipeline.PayloadFinding{Kind: "scan_incomplete", Location: "classifier_unavailable"}); ev.Decision != adomain.RequireApproval {
		t.Fatalf("outbound: %s", ev.Decision)
	}
	f.w.SetContentSignals(active, "scan_incomplete")
	if ev := f.contentEval(); ev.Decision != adomain.RequireApproval {
		t.Fatalf("run: %s", ev.Decision)
	}
}

// TestHR647_WatchingChangesNoDecision: WATCHING and OFF decide as if no flag
// existed, and WATCHING notes what ACTIVE would have held.
//
// Covers: F939
func TestHR647_WatchingChangesNoDecision(t *testing.T) {
	f := newFx(t)
	base := f.contentEval().Decision
	f.w.SetContentSignals(watching, "injection_phrase")
	ev := f.contentEval(injected...)
	if ev.Decision != base {
		t.Fatalf("watching decided %s, without flags %s", ev.Decision, base)
	}
	if _, ok := itemOf(ev, pipeline.ReasonContentFlagWatching); !ok {
		t.Fatal("no note")
	}
	f.w.SetContentSignals("OFF", "injection_phrase")
	ev = f.contentEval(injected...)
	if _, ok := itemOf(ev, pipeline.ReasonContentFlagWatching); ev.Decision != base || ok {
		t.Fatalf("off decided %s, noted %v", ev.Decision, ok)
	}
}

// TestHR648_NoFlagEverAllowsOrLifts: across every mode and every mix of run
// and outbound flags, a decision is at least as strict as the same action
// with no flag, an already-held or denied action stays so, and each
// requirement it had stays.
//
// Covers: F939
func TestHR648_NoFlagEverAllowsOrLifts(t *testing.T) {
	kinds := [][]string{nil, {"injection_phrase"}, {"scan_incomplete"}, {"secret_format", "pii_card", "classifier_flag"}}
	outbound := [][]pipeline.PayloadFinding{nil, injected, {{Kind: "scan_incomplete", Location: "over_bound"}}}
	worlds := map[string]func(f *fx){
		"open":    func(*fx) {},
		"payload": func(*fx) {},
	}
	for name, set := range worlds {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			set(f)
			req := func(fs ...pipeline.PayloadFinding) *pipeline.Evaluation {
				r := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "10.00"))
				r.ContentFindings = fs
				if name == "payload" {
					r.PayloadFindings = []pipeline.PayloadFinding{{Kind: "private_key", Location: "arg/k"}}
				}
				return f.eval(r)
			}
			f.w.SetContentSignals("OFF")
			base := req()
			for _, mode := range []string{"OFF", watching, active} {
				for _, k := range kinds {
					for _, o := range outbound {
						f.w.SetContentSignals(mode, k...)
						got := req(o...)
						if rank(got.Decision) < rank(base.Decision) {
							t.Fatalf("%s %v %v: %s is looser than %s", mode, k, o, got.Decision, base.Decision)
						}
						if len(got.Requirements) < len(base.Requirements) {
							t.Fatalf("%s %v %v: a requirement was lifted", mode, k, o)
						}
					}
				}
			}
		})
	}
}

// TestHR648_AReadPassesAFlagOnTheRun: a flag on the tree leaves a read alone,
// and a read's own outbound flag still holds it (D512).
//
// Covers: F939
func TestHR648_AReadPassesAFlagOnTheRun(t *testing.T) {
	f := newFx(t)
	f.w.SetContentSignals("OFF")
	read := func(fs ...pipeline.PayloadFinding) *pipeline.Evaluation {
		r := f.parse(f.run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
		r.ContentFindings = fs
		return f.eval(r)
	}
	base := read().Decision
	f.w.SetContentSignals(active, "injection_phrase")
	if ev := read(); ev.Decision != base {
		t.Fatalf("a read was held: %s, without flags %s", ev.Decision, base)
	}
	// The fixture's read cannot file an approval request, so its hold fails
	// closed as CANNOT_AUTHORIZE: never looser than a hold.
	if ev := read(injected...); rank(ev.Decision) < rank(adomain.RequireApproval) {
		t.Fatalf("a read's own flag: %s %+v", ev.Decision, ev.Checklist)
	}
	write := f.parse(f.run, ids.NewV7(), "create_refund", refund("ch_1", "10.00"))
	if ev := f.eval(write); ev.Decision != adomain.RequireApproval {
		t.Fatalf("a write on the flagged run: %s", ev.Decision)
	}
}

// TestHR648_ContentReadFailureNeverOpens: a mode that cannot be read is
// CANNOT_AUTHORIZE.
//
// Covers: F939
func TestHR648_ContentReadFailureNeverOpens(t *testing.T) {
	f := newFx(t)
	f.w.Fail["ContentSignals"] = true
	if ev := f.contentEval(); ev.Decision != adomain.CannotAuthorize {
		t.Fatalf("decision %s", ev.Decision)
	}
}
