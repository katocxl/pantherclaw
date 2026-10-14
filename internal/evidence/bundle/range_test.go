// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"encoding/base64"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
)

const (
	rangeID    = "0192aaaa-bbbb-7ccc-8ddd-0000000000aa"
	rangeAgent = "0192aaaa-bbbb-7ccc-8ddd-0000000000ab"
	digestA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// receipt is an unsigned stand-in for a compact JWS receipt: the check
// reads its payload; the manifest's signature covers it.
func receipt(decision, code string, simulated string) string {
	payload := `{"pap":{"decision":"` + decision + `","checklist":[{"code":"` + code + `","decisive":true}]` + simulated + `}}`
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

const simTrue, simFalse = `,"simulated":true`, `,"simulated":false`

// rangeOpts varies a range pack.
type rangeOpts struct {
	decision, reason, simulated string // the decision receipt
	claimedOutcome              string // what the report's step observed
	verdict                     string
	statement                   string
	agent                       string // the transaction file's agent
	dropTxn                     bool
}

func goodRange() rangeOpts {
	return rangeOpts{
		decision: "DENY", reason: "DESTINATION_NOT_GRANTED", simulated: simTrue, claimedOutcome: "DENY", verdict: "PASS",
		statement: pack.RangeStatement, agent: rangeAgent,
	}
}

// rangePack builds a signed pack of scope range.
func rangePack(k *packKit, o rangeOpts) []byte {
	return k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Scope = pack.Scope{Kind: pack.ScopeRange, Range: rangeID}
		m.Statement = o.statement
		m.Include = pack.Include{Receipts: true}
		sc := pack.AssuranceScenario{
			ID: "RT-009", Digest: digestA, Category: "boundary", Tier: "community", Suite: "coding-agent", Verdict: o.verdict,
			Steps: []pack.AssuranceStep{{
				ID: "exfil", Expect: pack.AssuranceExpect{Outcome: "DENY", Reason: "DESTINATION_NOT_GRANTED"},
				Observed:   pack.AssuranceExpect{Outcome: o.claimedOutcome, Reason: "DESTINATION_NOT_GRANTED"},
				ObservedBy: "SERVER", Matched: o.claimedOutcome == "DENY", Transaction: packTxn,
			}},
		}
		counts := pack.AssuranceCounts{}
		if o.verdict == "PASS" {
			counts.Pass = 1
		} else {
			counts.Fail = 1
		}
		cats := map[string]pack.AssuranceCounts{"functional": {}, "boundary": counts, "recovery": {}, "explanation": {}}
		a := pack.Assurance{
			Format: pack.AssuranceFormat, Range: rangeID, Org: m.Org, Agent: rangeAgent, Started: "2026-10-14T10:00:00Z", Finished: "2026-10-14T10:05:00Z",
			RunnerVersion: "test", ScenarioSetDigest: domain.SetDigest([]domain.Scenario{{ID: "RT-009", Digest: digestA}}),
			PolicyVersions: []pack.AssuranceVersion{}, PackageVersions: []pack.AssuranceVersion{},
			Scenarios: []pack.AssuranceScenario{sc}, Totals: counts, Categories: cats, Mismatches: []pack.AssuranceMismatch{},
			Statement: pack.RangeStatement,
		}
		data, err := pack.Canonical(a)
		if err != nil {
			k.t.Fatal(err)
		}
		out := []pack.File{{Path: pack.AssurancePath, Kind: pack.KindAssurance, Data: data}}
		if !o.dropTxn {
			txn := `{"id":"` + packTxn + `","agent":"` + o.agent + `","decisions":[{"evaluation":1,"receipt":"` + receipt(o.decision, o.reason, o.simulated) + `"}]}`
			out = append(out, pack.File{Path: "transactions/" + packTxn + ".json", Kind: pack.KindTransaction, Data: []byte(txn)})
		}
		return append(out, files[1])
	})
}

func verifyRangePack(k *packKit, o rangeOpts) *bundle.Report {
	return bundle.VerifyPack(rangePack(k, o), bundle.Options{Trust: k.trust})
}

// TestHR224_RangePacksVerifyOffline: a signed range pack verifies offline,
// carries the range statement, and its verdicts, counts and server-observed
// steps follow from its own receipts.
func TestHR224_RangePacksVerifyOffline(t *testing.T) {
	k := newPackKit(t)
	r := verifyRangePack(k, goodRange())
	for _, name := range []string{"pack.signature", "pack.items", "pack.statement", "range.assurance", "range.verdicts", "range.simulated", "range.step"} {
		if got := statusOf(r, name); got != bundle.Passed {
			t.Errorf("%s = %q, want passed:\n%+v", name, got, r.Checks)
		}
	}
	if r.Limits == bundle.PackLimits {
		t.Error("the report ends with the fixed pack statement, not the range's")
	}
}

// T-091: real-run evidence mixed into a range pack fails the check.
func TestT091_ARealRunReceiptInARangePackFails(t *testing.T) {
	k := newPackKit(t)
	o := goodRange()
	o.simulated = simFalse
	if got := statusOf(verifyRangePack(k, o), "range.simulated"); got != bundle.Failed {
		t.Fatalf("simulated:false receipt = %q, want failed", got)
	}
	o.simulated = ""
	if got := statusOf(verifyRangePack(k, o), "range.simulated"); got != bundle.Failed {
		t.Fatalf("a receipt without simulated = %q, want failed", got)
	}
	o = goodRange()
	o.agent = "0192aaaa-bbbb-7ccc-8ddd-0000000000ff"
	if got := statusOf(verifyRangePack(k, o), "range.simulated"); got != bundle.Failed {
		t.Fatalf("another agent's transaction = %q, want failed", got)
	}
	o = goodRange()
	o.dropTxn = true
	if got := statusOf(verifyRangePack(k, o), "range.simulated"); got != bundle.Failed {
		t.Fatalf("a named transaction missing from the pack = %q, want failed", got)
	}
}

// T-091: a forged or inflated report: the step says what the receipt does
// not, or the verdict says more than the steps.
func TestT091_AForgedOrInflatedReportFailsOffline(t *testing.T) {
	k := newPackKit(t)
	// The server-observed step says DENY, the decision receipt says ALLOW.
	o := goodRange()
	o.decision = "ALLOW"
	if got := statusOf(verifyRangePack(k, o), "range.step"); got != bundle.Failed {
		t.Fatalf("a step against its receipt = %q, want failed", got)
	}
	// A failed step under a PASS verdict.
	o = goodRange()
	o.claimedOutcome = "ALLOW"
	if got := statusOf(verifyRangePack(k, o), "range.verdict"); got != bundle.Failed {
		t.Fatalf("PASS over a failed step = %q, want failed", got)
	}
	// The wrong statement for the scope fails both ways.
	o = goodRange()
	o.statement = pack.Statement
	if got := statusOf(verifyRangePack(k, o), "pack.statement"); got != bundle.Failed {
		t.Fatalf("a range pack with the fixed statement = %q, want failed", got)
	}
	plain := k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Statement = pack.RangeStatement
		return files
	})
	if got := statusOf(bundle.VerifyPack(plain, bundle.Options{Trust: k.trust}), "pack.statement"); got != bundle.Failed {
		t.Fatalf("a run pack with the range statement = %q, want failed", got)
	}
}

// A range pack without its report fails.
func TestHR224_ARangePackNeedsItsAssurance(t *testing.T) {
	k := newPackKit(t)
	raw := k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Scope = pack.Scope{Kind: pack.ScopeRange, Range: rangeID}
		m.Statement = pack.RangeStatement
		return files
	})
	if got := statusOf(bundle.VerifyPack(raw, bundle.Options{Trust: k.trust}), "range.assurance"); got != bundle.Failed {
		t.Fatalf("range.assurance = %q, want failed", got)
	}
}
