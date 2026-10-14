// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"encoding/json/v2"
	"slices"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
)

// verifyRange checks a pack of scope range offline (G0 M12, D13, HR-224):
// the assurance report is the one of the manifest's range and org; its
// verdicts, counts and scenario-set digest follow from its own steps;
// every receipt of every transaction it names says simulated: true; and
// each step the server observed matches that transaction's decision
// receipt (or its effect state), so a report cannot say more than the
// receipts do. Steps the runner observed are listed as such: the pack
// cannot confirm them.
func verifyRange(r *Report, m *pack.Manifest, files map[string][]byte, runs map[string]verifiedRun) {
	subject := "range " + m.Scope.Range
	var item *pack.Item
	for i := range m.Items {
		if m.Items[i].Kind != pack.KindAssurance {
			continue
		}
		if item != nil {
			r.add("range.assurance", subject, Failed, "the manifest lists more than one assurance report")
			return
		}
		item = &m.Items[i]
	}
	if item == nil || item.Path != pack.AssurancePath {
		r.add("range.assurance", subject, Failed, "the pack has no %s", pack.AssurancePath)
		return
	}
	a, err := pack.DecodeAssurance(files[item.Path])
	if err != nil {
		r.add("range.assurance", subject, Failed, "%v", err)
		return
	}
	switch {
	case a.Range != m.Scope.Range || a.Org != m.Org:
		r.add("range.assurance", subject, Failed, "the report is of range %s of org %s, not the manifest's", truncate(a.Range), truncate(a.Org))
		return
	case a.Statement != pack.RangeStatement:
		r.add("range.assurance", subject, Failed, "the report does not carry the range statement")
		return
	case !m.Include.Receipts:
		r.add("range.assurance", subject, Failed, "a range pack must include receipts")
		return
	}
	r.add("range.assurance", subject, Passed, "report of range %s, agent %s, runner %s", a.Range, a.Agent, truncate(a.RunnerVersion))
	rederive(r, subject, a)
	txns := referenced(a)
	receipts := map[string]*txnReceipts{}
	for _, id := range txns {
		receipts[id] = verifyReceipts(r, m, files, a, id)
	}
	clientSteps := 0
	for _, sc := range a.Scenarios {
		for _, st := range sc.Steps {
			switch {
			case st.ObservedBy == "CLIENT":
				clientSteps++
			case st.Transaction != "":
				verifyStep(r, sc.ID, st, receipts[st.Transaction])
			case st.Probe != "":
				verifyProbeStep(r, m, a, sc.ID, st, runs)
			default:
				r.add("range.step", sc.ID+" "+st.ID, NotAvailable, "observed by the server, but it cites no transaction or probe report to re-derive it from")
			}
		}
	}
	if clientSteps > 0 {
		r.add("range.client_observed", subject, NotAvailable, "%d steps were observed by the runner and cannot be confirmed from the pack", clientSteps)
	}
	if r.notFull {
		r.add("range.complete", subject, NotAvailable, "range pack not fully verifiable: receipts of some of its transactions are not in the pack")
	}
	if n := len(a.Mismatches); n > 0 {
		r.add("range.mismatches", subject, NotAvailable, "the server overwrote the runner's claim in %d steps (listed in the report)", n)
	}
}

// rederive recomputes every verdict, the totals and the digest of the
// scenario set from the report's own scenarios and steps.
func rederive(r *Report, subject string, a *pack.Assurance) {
	var totals pack.AssuranceCounts
	cats := map[string]pack.AssuranceCounts{}
	bad := 0
	var set []domain.Scenario
	mismatches := 0
	for _, sc := range a.Scenarios {
		set = append(set, domain.Scenario{ID: sc.ID, Digest: sc.Digest})
		want := sc.Verdict
		switch sc.Verdict {
		case string(domain.Pass), string(domain.Fail):
			want = string(domain.Pass)
			if len(sc.Steps) == 0 || len(sc.Steps) != sc.StepCount {
				want = string(domain.Fail)
			}
			for _, st := range sc.Steps {
				exp, obs := domain.Expect(st.Expect), domain.Expect(st.Observed)
				matched := exp.Matches(obs)
				if st.ObservedBy == "SERVER" {
					// The server derives no code (D34).
					matched = exp.MatchesIgnoringCode(obs)
				}
				if st.Matched != matched {
					r.add("range.step", sc.ID+" "+st.ID, Failed, "its matched flag disagrees with its expected and observed values")
					bad++
				}
				if !matched {
					want = string(domain.Fail)
				}
				if st.Mismatch {
					mismatches++
				}
			}
		case string(domain.Errored), string(domain.Skipped):
		case string(domain.Missing):
			if len(sc.Steps) != 0 {
				want = ""
			}
		default:
			want = ""
		}
		if want != sc.Verdict {
			r.add("range.verdict", sc.ID, Failed, "the report says %s, its steps say %q", sc.Verdict, want)
			bad++
		}
		bump := func(c *pack.AssuranceCounts) {
			switch sc.Verdict {
			case "PASS":
				c.Pass++
			case "FAIL":
				c.Fail++
			case "ERROR":
				c.Error++
			case "SKIPPED":
				c.Skipped++
			case "MISSING":
				c.Missing++
			}
		}
		bump(&totals)
		c := cats[sc.Category]
		bump(&c)
		cats[sc.Category] = c
	}
	for _, c := range domain.Categories {
		if _, ok := cats[c]; !ok {
			cats[c] = pack.AssuranceCounts{}
		}
	}
	switch {
	case totals != a.Totals || !mapsEqual(cats, a.Categories):
		r.add("range.counts", subject, Failed, "the report's totals or per-category counts differ from its scenarios")
		bad++
	case domain.SetDigest(set) != a.ScenarioSetDigest:
		r.add("range.counts", subject, Failed, "the scenario-set digest differs from the scenarios' digests")
		bad++
	case len(a.Mismatches) != mismatches:
		r.add("range.counts", subject, Failed, "the report lists %d mismatches but its steps hold %d", len(a.Mismatches), mismatches)
		bad++
	}
	if bad == 0 {
		r.add("range.verdicts", subject, Passed, "%d scenarios: every verdict, the counts and the scenario-set digest follow from the steps", len(a.Scenarios))
	}
}

func mapsEqual(a, b map[string]pack.AssuranceCounts) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// referenced lists the transactions the steps name, once each.
func referenced(a *pack.Assurance) []string {
	var out []string
	for _, sc := range a.Scenarios {
		for _, st := range sc.Steps {
			if st.Transaction != "" {
				out = append(out, st.Transaction)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// txnFile is the part of transactions/<id>.json the check reads.
type txnFile struct {
	ID        string `json:"id"`
	Agent     string `json:"agent"`
	Effect    string `json:"effect_state"`
	Decisions []struct {
		Evaluation int    `json:"evaluation"`
		Receipt    string `json:"receipt"`
	} `json:"decisions"`
	Execution *struct {
		Receipt string `json:"receipt"`
	} `json:"execution"`
	Effects []struct {
		Receipt string `json:"receipt"`
	} `json:"effects"`
}

// txnReceipts is what a transaction's latest decision receipt said.
type txnReceipts struct {
	ok  bool
	rec domain.TransactionRecord
}

// verifyReceipts checks that every receipt of a transaction the report
// names says simulated: true, that the transaction is the range agent's,
// and returns what its latest decision receipt said.
func verifyReceipts(r *Report, m *pack.Manifest, files map[string][]byte, a *pack.Assurance, id string) *txnReceipts {
	subject := "transaction " + id
	raw, ok := files["transactions/"+id+".json"]
	if !ok {
		reason := "the report names it, but the pack does not hold it"
		for _, g := range m.Gaps {
			if g.Subject == subject {
				r.add("range.simulated", subject, NotAvailable, "%s: %s", g.Reason, truncate(g.Detail))
				r.notFull = true
				return nil
			}
		}
		r.add("range.simulated", subject, Failed, "%s", reason)
		return nil
	}
	var t txnFile
	if err := json.Unmarshal(raw, &t); err != nil || t.ID != id {
		r.add("range.simulated", subject, Failed, "the transaction file is malformed")
		return nil
	}
	if t.Agent != a.Agent {
		r.add("range.simulated", subject, Failed, "the transaction is of agent %s, not the range agent", truncate(t.Agent))
		return nil
	}
	var all []string
	latest, latestEval := "", -1
	for _, d := range t.Decisions {
		if d.Receipt != "" {
			all = append(all, d.Receipt)
			if d.Evaluation > latestEval {
				latest, latestEval = d.Receipt, d.Evaluation
			}
		}
	}
	if t.Execution != nil && t.Execution.Receipt != "" {
		all = append(all, t.Execution.Receipt)
	}
	for _, e := range t.Effects {
		if e.Receipt != "" {
			all = append(all, e.Receipt)
		}
	}
	if len(all) == 0 {
		r.add("range.simulated", subject, NotAvailable, "no receipt body is in the pack (removed by retention)")
		r.notFull = true
		return nil
	}
	nonSim := 0
	for _, c := range all {
		if body, ok := domain.ParseReceipt(c); !ok || body.Simulated == nil || !*body.Simulated {
			nonSim++
		}
	}
	if nonSim > 0 {
		// The step check still runs: it says what the receipts support.
		r.add("range.simulated", subject, Failed, "%d of %d receipts of this transaction do not say simulated: true: real-run evidence in a range pack", nonSim, len(all))
	} else {
		r.add("range.simulated", subject, Passed, "all %d receipts say simulated: true", len(all))
	}
	out := &txnReceipts{ok: latest != "", rec: domain.TransactionRecord{EffectState: t.Effect}}
	if latest != "" {
		body, _ := domain.ParseReceipt(latest)
		out.rec.Decision, out.rec.Reason, out.rec.Reasons = body.Decision, body.Decisive, body.Reasons
	}
	return out
}

// verifyStep checks a server-observed step against the receipts of its
// transaction: the outcome and reason the server recorded must be the ones
// the decision receipt (or the effect state) supports.
func verifyStep(r *Report, scenario string, st pack.AssuranceStep, t *txnReceipts) {
	subject := scenario + " " + st.ID
	if t == nil || !t.ok {
		r.add("range.step", subject, NotAvailable, "its transaction's decision receipt is not in the pack")
		r.notFull = true
		return
	}
	got := t.rec.Observe(domain.Expect(st.Expect))
	rec := domain.Expect(st.Observed)
	if got.Observed.Outcome != rec.Outcome || (rec.Reason != "" && rec.Reason != got.Observed.Reason && !slices.Contains(got.Reasons, rec.Reason)) {
		r.add("range.step", subject, Failed, "the report says %s %s, the decision receipt says %s %s", rec.Outcome, truncate(rec.Reason), got.Observed.Outcome, truncate(got.Observed.Reason))
		return
	}
	r.add("range.step", subject, Passed, "matches the decision receipt: %s", got.Observed.Outcome)
}

// verifyProbeStep re-derives a server-observed step from the probe report
// it cites (HR-224, HR-227): the report must have verified against a
// sandbox.closure entry of the pack's bundles (its signature, digest and
// session), be of the range's agent, and hold the result the step names;
// BLOCKED when that was blocked, ALLOW when it got through. The report
// missing from the pack is a failure, unless the manifest lists it as a gap.
func verifyProbeStep(r *Report, m *pack.Manifest, a *pack.Assurance, scenario string, st pack.AssuranceStep, runs map[string]verifiedRun) {
	subject := scenario + " " + st.ID
	run, ok := runs[st.Probe]
	if !ok {
		for _, g := range m.Gaps {
			if g.Subject == "probe report "+st.Probe {
				r.add("range.step", subject, NotAvailable, "%s: %s", g.Reason, truncate(g.Detail))
				r.notFull = true
				return
			}
		}
		r.add("range.step", subject, Failed, "it cites probe report %s, which no verified sandbox closure in the pack records", truncate(st.Probe))
		return
	}
	if run.agent != a.Agent {
		r.add("range.step", subject, Failed, "the probe report is of agent %s, not the range agent", truncate(run.agent))
		return
	}
	results := map[string]string{}
	for _, res := range run.report.Results {
		results[res.Name] = res.Observed
	}
	got, ok := domain.ProbeRecord{Results: results}.Observe(st.ProbeKind)
	rec := domain.Expect(st.Observed)
	switch {
	case !ok:
		r.add("range.step", subject, Failed, "the signed probe report has no usable result %q", truncate(st.ProbeKind))
	case got.Observed.Outcome != rec.Outcome:
		r.add("range.step", subject, Failed, "the report says %s, the signed probe report says %s", rec.Outcome, got.Observed.Outcome)
	default:
		r.add("range.step", subject, Passed, "matches the signed probe report: %s %s", st.ProbeKind, got.Observed.Outcome)
	}
}
