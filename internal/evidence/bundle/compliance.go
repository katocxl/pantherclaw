// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"bytes"
	"encoding/json/v2"
	"slices"

	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	rangedomain "github.com/katocxl/pantherclaw/internal/ranges/domain"
)

// verifyCompliance checks a pack of scope compliance offline (G0 M25 D301,
// HR-604): the report is the one of the manifest's org and period and carries
// the fixed statement; its header follows from its inputs; every control
// state follows from those inputs under the same table the server used, so a
// report cannot say more than its counts do; and every transaction it cites
// is in the pack, simulated exactly as the report says. Records a pack does
// not hold, such as a grant, are listed as such: the pack cannot confirm them.
func verifyCompliance(r *Report, m *pack.Manifest, files map[string][]byte) {
	subject := "compliance " + m.Pack
	var item *pack.Item
	for i := range m.Items {
		if m.Items[i].Kind != pack.KindCompliance {
			continue
		}
		if item != nil {
			r.add("compliance.report", subject, Failed, "the manifest lists more than one compliance report")
			return
		}
		item = &m.Items[i]
	}
	if item == nil || item.Path != pack.CompliancePath {
		r.add("compliance.report", subject, Failed, "the pack has no %s", pack.CompliancePath)
		return
	}
	rep, err := domain.Decode(files[item.Path])
	if err != nil {
		r.add("compliance.report", subject, Failed, "%v", err)
		return
	}
	switch {
	case rep.Org != m.Org || rep.PeriodStart != m.Scope.From || rep.PeriodEnd != m.Scope.To:
		r.add("compliance.report", subject, Failed, "the report is of org %s for %s to %s, not the manifest's", truncate(rep.Org),
			truncate(rep.PeriodStart), truncate(rep.PeriodEnd))
		return
	case rep.Statement != pack.ComplianceStatement:
		r.add("compliance.report", subject, Failed, "the report does not carry the fixed statement")
		return
	case !m.Include.Receipts:
		r.add("compliance.report", subject, Failed, "a compliance pack must include receipts")
		return
	}
	r.add("compliance.report", subject, Passed, "report of %s for %s to %s: %d real and %d simulated records", truncate(string(rep.Framework)),
		rep.PeriodStart, rep.PeriodEnd, rep.Split.Real, rep.Split.Simulated)
	verifyComplianceInputs(r, subject, rep)
	verifyComplianceControls(r, subject, rep)
	verifyComplianceRefs(r, subject, m, files, rep)
}

// verifyComplianceInputs holds the counts to what they can honestly be.
func verifyComplianceInputs(r *Report, subject string, rep *domain.Report) {
	bad := 0
	fail := func(source, detail string) {
		bad++
		r.add("compliance.inputs", source, Failed, "%s", detail)
	}
	if rep.Split != domain.SplitOf(rep.Inputs) {
		fail(subject, "the header's real and simulated split differs from the sources")
	}
	seen := map[domain.Source]bool{}
	for _, s := range rep.Inputs.Sources {
		name := string(s.Source)
		if seen[s.Source] {
			fail(truncate(name), "the source is listed twice")
		}
		seen[s.Source] = true
		switch {
		case !s.Readable && (s.Real != 0 || s.Simulated != 0 || len(s.Refs) != 0):
			fail(truncate(name), "it says it was not readable, yet it holds records")
		case slices.Contains(domain.TestSources(), s.Source) && s.Real != 0:
			fail(truncate(name), "a test result is simulated by construction, yet it counts real records")
		}
		if s.Source == domain.SourceReceipts || s.Source == domain.SourceApprovals {
			if (s.Real > 0 && !cites(s, false)) || (s.Simulated > 0 && !cites(s, true)) {
				fail(truncate(name), "it counts records and cites none of them")
			}
		}
	}
	type key struct {
		tag    string
		source domain.Source
	}
	tested := map[key]bool{}
	for _, t := range rep.Inputs.Tests {
		name := truncate(t.Tag + "/" + string(t.Source))
		if tested[key{t.Tag, t.Source}] {
			fail(name, "the test result is listed twice")
		}
		tested[key{t.Tag, t.Source}] = true
		if !knownTag(t.Tag) {
			fail(name, "the tag is no risk of any control table")
		}
		i := slices.IndexFunc(rep.Inputs.Sources, func(s domain.SourceCount) bool { return s.Source == t.Source })
		switch {
		case !slices.Contains(domain.TestSources(), t.Source):
			fail(name, "a test result from a source that runs no tests")
		case i < 0 || !rep.Inputs.Sources[i].Readable:
			fail(name, "a test result from a source the report could not read")
		}
	}
	if bad == 0 {
		r.add("compliance.inputs", subject, Passed, "the header, the source counts and the test results agree")
	}
}

// knownTag reports whether a control of any table reads the tag.
func knownTag(tag string) bool {
	for _, f := range domain.Frameworks() {
		for _, c := range domain.Controls(f) {
			if slices.Contains(c.Tests, tag) {
				return true
			}
		}
	}
	return false
}

func cites(s domain.SourceCount, simulated bool) bool {
	return slices.ContainsFunc(s.Refs, func(x domain.Ref) bool { return x.Simulated == simulated })
}

// verifyComplianceControls runs the server's own rule on the report's inputs.
func verifyComplianceControls(r *Report, subject string, rep *domain.Report) {
	if !rep.Framework.Known() || domain.CatalogDigest(rep.Framework) != rep.CatalogDigest {
		r.add("compliance.controls", subject, NotAvailable, "written under another control table: update pclaw to re-derive its %d controls", len(rep.Controls))
		r.notFull = true
		return
	}
	want, err := domain.Evaluate(rep.Framework, rep.Inputs)
	if err != nil {
		r.add("compliance.controls", subject, Failed, "%v", err)
		return
	}
	a, errA := pack.Canonical(want)
	b, errB := pack.Canonical(rep.Controls)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		r.add("compliance.controls", subject, Failed, "a control's state or gaps differ from what the report's own inputs give")
		return
	}
	r.add("compliance.controls", subject, Passed, "all %d control states follow from the report's inputs", len(want))
}

// verifyComplianceRefs checks every cited transaction against its receipts.
func verifyComplianceRefs(r *Report, subject string, m *pack.Manifest, files map[string][]byte, rep *domain.Report) {
	simulated := map[string]bool{}
	other := 0
	for _, s := range rep.Inputs.Sources {
		for _, ref := range s.Refs {
			if ref.Type == domain.RefTransaction {
				simulated[ref.ID] = ref.Simulated
			} else {
				other++
			}
		}
	}
	ok := 0
	ids := make([]string, 0, len(simulated))
	for id := range simulated {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if verifyCited(r, m, files, id, simulated[id]) {
			ok++
		}
	}
	if ok > 0 {
		r.add("compliance.refs", subject, Passed, "%d cited transactions are in the pack, simulated as the report says", ok)
	}
	if other > 0 {
		r.add("compliance.server_records", subject, NotAvailable, "%d cited grants, coverage records, ranges or campaigns are the server's records: the pack does not hold them", other)
	}
}

// verifyCited checks one cited transaction. Its absence is a failure unless
// the manifest lists it as a gap: a report must not cite what it cannot show.
func verifyCited(r *Report, m *pack.Manifest, files map[string][]byte, id string, simulated bool) bool {
	subject := "transaction " + truncate(id)
	raw, ok := files["transactions/"+id+".json"]
	if !ok {
		for _, g := range m.Gaps {
			if g.Subject == "transaction "+id {
				r.add("compliance.ref", subject, NotAvailable, "%s: %s", g.Reason, truncate(g.Detail))
				return false
			}
		}
		r.add("compliance.ref", subject, Failed, "the report cites it, but the pack does not hold it")
		return false
	}
	var t txnFile
	if err := json.Unmarshal(raw, &t); err != nil || t.ID != id {
		r.add("compliance.ref", subject, Failed, "the transaction file is malformed")
		return false
	}
	var all []string
	for _, d := range t.Decisions {
		if d.Receipt != "" {
			all = append(all, d.Receipt)
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
		r.add("compliance.ref", subject, NotAvailable, "no receipt body is in the pack (removed by retention)")
		return false
	}
	for _, c := range all {
		body, ok := rangedomain.ParseReceipt(c)
		if !ok {
			r.add("compliance.ref", subject, Failed, "a receipt cannot be read")
			return false
		}
		if got := body.Simulated != nil && *body.Simulated; got != simulated {
			r.add("compliance.ref", subject, Failed, "the report calls it simulated=%v, its receipt says simulated=%v", simulated, got)
			return false
		}
	}
	return true
}
