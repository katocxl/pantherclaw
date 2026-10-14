// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

func closureIssuer(t *testing.T, o bundletest.ClosureOpts) (*bundletest.Issuer, *bundletest.Closure) {
	t.Helper()
	iss := bundletest.NewIssuer(t)
	iss.Append(2)
	c := iss.AppendClosure(o)
	iss.Checkpoint()
	return iss, c
}

func verifyClosure(t *testing.T, iss *bundletest.Issuer, b *bundle.Bundle) *bundle.Report {
	t.Helper()
	trust, err := bundle.ParseTrust(iss.Trust())
	if err != nil {
		t.Fatal(err)
	}
	return bundle.Verify(b, bundle.Options{Trust: trust})
}

func checksNamed(r *bundle.Report, name string) []bundle.Check {
	var out []bundle.Check
	for _, c := range r.Checks {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// TestHR227_ProbeReportsVerifyOffline: a bundle with a sandbox.closure
// entry and the probe reports it names verifies offline: the entry is in a
// signed checkpoint, each report verifies under the key the entry names and
// matches its digest and session, and every probe is listed as passed.
func TestHR227_ProbeReportsVerifyOffline(t *testing.T) {
	iss, c := closureIssuer(t, bundletest.ClosureOpts{})
	r := verifyClosure(t, iss, iss.Bundle())
	if r.Failed() {
		t.Fatalf("a good closure failed:\n%s", r.Text())
	}
	probes := checksNamed(r, "closure.probe")
	var lines []string
	for _, p := range probes {
		if p.Status != bundle.Passed {
			t.Errorf("%s %s is %s", p.Name, p.Subject, p.Status)
		}
		lines = append(lines, strings.TrimPrefix(p.Subject, "closure "+c.ID+" ")+" "+p.Detail)
	}
	for _, want := range []string{"ssh_push blocked", "planted_pat_push blocked"} {
		if !slices.Contains(lines, want) {
			t.Errorf("no passed line %q in %v", want, lines)
		}
	}
	if got := checksNamed(r, "closure.reports"); len(got) != 1 || got[0].Status != bundle.Passed {
		t.Errorf("closure.reports = %v", got)
	}
	if got := checksNamed(r, "closure.result"); len(got) != 1 || got[0].Status != bundle.Passed {
		t.Errorf("closure.result = %v", got)
	}
	// The entry itself is in the signed checkpoint.
	for _, ic := range checksNamed(r, "entry.inclusion") {
		if ic.Status != bundle.Passed {
			t.Errorf("entry.inclusion %s is %s: %s", ic.Subject, ic.Status, ic.Detail)
		}
	}
}

// TestT095_ASwappedOrForgedProbeReportFailsVerify: a closure whose report
// is swapped, re-signed with another key, whose recorded outcome was edited
// or whose report is dropped fails verification; it is never not
// available.
func TestT095_ASwappedOrForgedProbeReportFailsVerify(t *testing.T) {
	cases := []struct {
		name   string
		opts   bundletest.ClosureOpts
		tamper func(c *bundletest.Closure, b *bundle.Bundle)
	}{
		{"a swapped report", bundletest.ClosureOpts{}, func(c *bundletest.Closure, b *bundle.Bundle) {
			other := bundletest.NewIssuer(t)
			oc := other.AppendClosure(bundletest.ClosureOpts{})
			for k := range b.ProbeReports {
				if b.ProbeReports[k].Run == c.Runs[report.KindSandbox] {
					b.ProbeReports[k].Report = oc.Report(report.KindSandbox)
				}
			}
		}},
		{"a report re-signed with another key", bundletest.ClosureOpts{Forge: report.KindSandbox}, nil},
		{"a control report re-signed with another key", bundletest.ClosureOpts{Forge: report.KindControl}, nil},
		{"an edited outcome", bundletest.ClosureOpts{EditOutcome: "ssh_push"}, nil},
		{"a dropped report", bundletest.ClosureOpts{}, func(c *bundletest.Closure, b *bundle.Bundle) {
			b.ProbeReports = slices.DeleteFunc(b.ProbeReports, func(p bundle.ProbeReport) bool { return p.Run == c.Runs[report.KindCanary] })
		}},
		{"all reports dropped", bundletest.ClosureOpts{}, func(_ *bundletest.Closure, b *bundle.Bundle) { b.ProbeReports = nil }},
		{"a report altered by one byte", bundletest.ClosureOpts{}, func(c *bundletest.Closure, b *bundle.Bundle) {
			for k := range b.ProbeReports {
				if b.ProbeReports[k].Run == c.Runs[report.KindControl] {
					rep := []byte(b.ProbeReports[k].Report)
					rep[len(rep)-3] ^= 1
					b.ProbeReports[k].Report = string(rep)
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iss, c := closureIssuer(t, tc.opts)
			b := iss.Bundle()
			if tc.tamper != nil {
				tc.tamper(c, b)
			}
			r := verifyClosure(t, iss, b)
			if !r.Failed() {
				t.Fatalf("%s passed:\n%s", tc.name, r.Text())
			}
			for _, ck := range checksNamed(r, "closure.reports") {
				if ck.Status == bundle.NotAvailable {
					t.Errorf("%s is not available, want failed", ck.Detail)
				}
			}
			if slices.ContainsFunc(checksNamed(r, "closure.probe"), func(p bundle.Check) bool { return p.Status == bundle.Passed }) {
				t.Errorf("a probe line passed on a tampered closure:\n%s", r.Text())
			}
		})
	}
	// A closure entry rewritten after the fact (the history is rebuilt
	// without a signed checkpoint) never passes.
	iss, _ := closureIssuer(t, bundletest.ClosureOpts{})
	if r := verifyClosure(t, iss, iss.Rewrite(3).Bundle()); !r.Failed() {
		t.Errorf("a rewritten closure entry passed:\n%s", r.Text())
	}
}
