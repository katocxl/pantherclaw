// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle

import (
	"bytes"
	"errors"

	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
)

// verifyThreatMap checks a pack of scope threat_map offline (G0 M28 D720,
// HR-688): the report is of the manifest's org and carries the fixed
// statement; its mapping is this verifier's PantherClaw mapping (D720e),
// else it is not re-derived; it was built with the MITRE catalog this verifier embeds,
// else it cannot be re-derived here; and re-running the evaluator on the
// report's own inputs and mapping gives every technique, lane, reason, gap
// and tactic count it shows. Any difference fails.
func verifyThreatMap(r *Report, m *pack.Manifest, files map[string][]byte) {
	subject := "threat map " + m.Pack
	var item *pack.Item
	for i := range m.Items {
		if m.Items[i].Kind != pack.KindThreatMap {
			continue
		}
		if item != nil {
			r.add("threatmap.report", subject, Failed, "the manifest lists more than one threat map report")
			return
		}
		item = &m.Items[i]
	}
	if item == nil || item.Path != pack.ThreatMapPath {
		r.add("threatmap.report", subject, Failed, "the pack has no %s", pack.ThreatMapPath)
		return
	}
	rep, err := domain.DecodeReport(files[item.Path])
	if err != nil {
		r.add("threatmap.report", subject, Failed, "%v", err)
		return
	}
	switch {
	case rep.Org != m.Org:
		r.add("threatmap.report", subject, Failed, "the report is of org %s, not the manifest's", truncate(rep.Org))
		return
	case rep.Statement != domain.Statement:
		r.add("threatmap.report", subject, Failed, "the report does not carry the fixed statement")
		return
	case rep.Inputs.Framework != rep.Framework || rep.Inputs.Scope != rep.Scope || !rep.Inputs.EvaluatedAt.Equal(rep.EvaluatedAt) ||
		rep.Mapping.Digest != rep.MappingDigest:
		r.add("threatmap.report", subject, Failed, "the report's header differs from its own inputs and mapping")
		return
	}
	r.add("threatmap.report", subject, Passed, "threat map of %s (MITRE %s), evaluated %s", truncate(string(rep.Framework)),
		truncate(rep.Catalog.Version), rep.EvaluatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	// The mapping is this build's (G0 M28 D720e): its digest names the whole
	// mapping document, so a pack with this build's digest must carry this
	// build's evaluator view byte for byte; another digest is another
	// PantherClaw's mapping and is not re-derived here.
	shipped := mapset.Evaluator(rep.Framework)
	if shipped.Digest == "" || rep.MappingDigest != shipped.Digest {
		r.add("threatmap.mapping", subject, NotAvailable, "built with another PantherClaw mapping (%s): check this part with the pclaw version that built the pack",
			truncate(rep.MappingDigest))
		r.notFull = true
		return
	}
	got, errGot := pack.Canonical(rep.Mapping)
	own, errOwn := pack.Canonical(shipped)
	if errGot != nil || errOwn != nil || !bytes.Equal(got, own) {
		r.add("threatmap.mapping", subject, Failed, "the report's mapping differs from the PantherClaw mapping its digest names")
		return
	}
	r.add("threatmap.mapping", subject, Passed, "the report's mapping is PantherClaw mapping %s", truncate(rep.MappingDigest))
	want, err := rep.Rederive()
	switch {
	case errors.Is(err, domain.ErrOtherCatalog):
		r.add("threatmap.lanes", subject, NotAvailable, "built with another MITRE catalog (%s %s): check this part with the pclaw version that built the pack",
			truncate(string(rep.Framework)), truncate(rep.Catalog.Version))
		r.notFull = true
		return
	case err != nil:
		r.add("threatmap.lanes", subject, Failed, "%v", err)
		return
	}
	if id, ok := firstDifference(want, *rep); !ok {
		r.add("threatmap.lanes", subject, Failed, "%s differs from what the report's own inputs and mapping give", truncate(id))
		return
	}
	r.add("threatmap.lanes", subject, Passed, "all %d techniques and %d tactic counts follow from the report's inputs and mapping",
		len(want.Techniques), len(want.Tactics))
}

// firstDifference compares a re-derived report with the one in the pack and
// names the first technique or tactic that differs, or "the report" when
// they differ elsewhere.
func firstDifference(want, got domain.Report) (string, bool) {
	same := func(a, b any) bool {
		x, errX := pack.Canonical(a)
		y, errY := pack.Canonical(b)
		return errX == nil && errY == nil && bytes.Equal(x, y)
	}
	if len(want.Techniques) != len(got.Techniques) {
		return "the technique list", false
	}
	for i := range want.Techniques {
		if !same(want.Techniques[i], got.Techniques[i]) {
			return "technique " + got.Techniques[i].ID, false
		}
	}
	if len(want.Tactics) != len(got.Tactics) {
		return "the tactic list", false
	}
	for i := range want.Tactics {
		if !same(want.Tactics[i], got.Tactics[i]) {
			return "tactic " + got.Tactics[i].ID, false
		}
	}
	if !same(want, got) {
		return "the report", false
	}
	return "", true
}
