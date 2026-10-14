// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// probeRange builds a range pack whose one server-observed step cites a
// sandbox report: the step expects BLOCKED and says it observed observed.
// withBundle leaves the closure's bundle out when false; agent is the range
// agent.
func probeRange(k *packKit, c *bundletest.Closure, observed, agent string, withBundle bool) []byte {
	return k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Scope = pack.Scope{Kind: pack.ScopeRange, Range: rangeID}
		m.Statement = pack.RangeStatement
		m.Include = pack.Include{Receipts: true}
		matched := observed == domain.OutcomeBlocked
		verdict := "PASS"
		counts := pack.AssuranceCounts{Pass: 1}
		if !matched {
			verdict, counts = "FAIL", pack.AssuranceCounts{Fail: 1}
		}
		sc := pack.AssuranceScenario{
			ID: "RT-020", Digest: digestA, Category: "boundary", Tier: "community", Suite: "coding-agent", StepCount: 1, Verdict: verdict,
			Steps: []pack.AssuranceStep{{
				ID: "ssh_push", Expect: pack.AssuranceExpect{Outcome: domain.OutcomeBlocked}, Observed: pack.AssuranceExpect{Outcome: observed},
				ObservedBy: "SERVER", Matched: matched, Probe: c.Runs[report.KindSandbox], ProbeKind: "ssh_push", Kind: "probe",
			}},
		}
		cats := map[string]pack.AssuranceCounts{"functional": {}, "boundary": counts, "recovery": {}, "explanation": {}}
		a := pack.Assurance{
			Format: pack.AssuranceFormat, Range: rangeID, Org: m.Org, Agent: agent, Started: "2026-10-14T10:00:00Z", Finished: "2026-10-14T10:05:00Z",
			RunnerVersion: "test", ScenarioSetDigest: domain.SetDigest([]domain.Scenario{{ID: "RT-020", Digest: digestA}}),
			PolicyVersions: []pack.AssuranceVersion{}, PackageVersions: []pack.AssuranceVersion{},
			Scenarios: []pack.AssuranceScenario{sc}, Totals: counts, Categories: cats, Mismatches: []pack.AssuranceMismatch{},
			Statement: pack.RangeStatement,
		}
		data, err := pack.Canonical(a)
		if err != nil {
			k.t.Fatal(err)
		}
		out := []pack.File{{Path: pack.AssurancePath, Kind: pack.KindAssurance, Data: data}, files[0]}
		if withBundle {
			out = append(out, files[1])
		}
		return out
	})
}

// TestHR224_RangeProbeStepsReDeriveOffline: a server-observed step that
// cites a probe report is re-derived from the signed report in the pack,
// through the sandbox.closure entry that records it; a lying step, a forged
// or missing report, or another agent's report fails it.
func TestHR224_RangeProbeStepsReDeriveOffline(t *testing.T) {
	newKit := func(o bundletest.ClosureOpts) (*packKit, *bundletest.Closure) {
		k := newPackKit(t)
		c := k.iss.AppendClosure(o)
		k.iss.Checkpoint()
		return k, c
	}
	verify := func(k *packKit, raw []byte) *bundle.Report {
		return bundle.VerifyPack(raw, bundle.Options{Trust: k.trust})
	}
	k, c := newKit(bundletest.ClosureOpts{})
	r := verify(k, probeRange(k, c, domain.OutcomeBlocked, c.Agent, true))
	if got := statusOf(r, "range.step"); got != bundle.Passed {
		t.Fatalf("a probe step against its signed report = %q, want passed:\n%s", got, r.Text())
	}
	if r.Failed() {
		t.Fatalf("a good probe range failed:\n%s", r.Text())
	}
	for _, tc := range []struct {
		name string
		run  func() *bundle.Report
	}{
		{"a step that lies about the report", func() *bundle.Report {
			k, c := newKit(bundletest.ClosureOpts{})
			return verify(k, probeRange(k, c, domain.OutcomeAllow, c.Agent, true))
		}},
		{"a forged report", func() *bundle.Report {
			k, c := newKit(bundletest.ClosureOpts{Forge: report.KindSandbox})
			return verify(k, probeRange(k, c, domain.OutcomeBlocked, c.Agent, true))
		}},
		{"a pack without the closure's bundle", func() *bundle.Report {
			k, c := newKit(bundletest.ClosureOpts{})
			return verify(k, probeRange(k, c, domain.OutcomeBlocked, c.Agent, false))
		}},
		{"another agent's report", func() *bundle.Report {
			k, c := newKit(bundletest.ClosureOpts{})
			return verify(k, probeRange(k, c, domain.OutcomeBlocked, rangeAgent, true))
		}},
	} {
		if got := statusOf(tc.run(), "range.step"); got != bundle.Failed {
			t.Errorf("%s: range.step = %q, want failed", tc.name, got)
		}
	}
}
