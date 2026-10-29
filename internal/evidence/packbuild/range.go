// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	rangeapp "github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// CodeRangeUnavailable marks a range pack whose range the creator cannot
// read (redteam.read where the range agent lives), or that has not
// finished.
const CodeRangeUnavailable = "RANGE_UNAVAILABLE"

// CodeRangeCustomer marks a range pack asked for a range of customer-authored
// scenarios: those never go in an assurance pack (G0 M17 D126, HR-466).
const CodeRangeCustomer = "RANGE_CUSTOMER_NOT_ATTESTED"

var errRange = errors.New("packbuild: the range is not a finished range the creator may read")

var errCustomer = errors.New("packbuild: a customer range has no assurance pack")

// rangeData is the range a pack of scope range reports.
type rangeData struct {
	rng     domain.Range
	results []domain.Result
}

// loadRange reads the range and its results as the creator: it must be
// finished and the creator must hold redteam.read where its agent lives.
func (b *builder) loadRange() (*rangeData, error) {
	id, err := ids.ParseUUID(b.r.scope.Range)
	if err != nil {
		return nil, errRange
	}
	var out rangeData
	err = pgranges.Store{Pool: b.s.Pool}.InTx(b.ctx, b.org, true, func(ctx context.Context, tx rangeapp.Tx) error {
		rng, err := tx.Range(ctx, id, false)
		if err != nil {
			return err
		}
		a, err := tx.Agent(ctx, rng.Agent)
		if err != nil {
			return err
		}
		if rng.State != domain.Finished || b.c.Require(td.PermRedteamRead, a.Path) != nil {
			return errRange
		}
		if rng.Origin != domain.OriginLibrary {
			return errCustomer
		}
		out.rng = rng
		out.results, err = tx.Results(ctx, id)
		return err
	})
	if errors.Is(err, rangeapp.ErrNotFound) || errors.Is(err, rangeapp.ErrAgentMissing) {
		return nil, errRange
	}
	return &out, err
}

// rangeTransactions lists the transactions the range's steps name.
func (d *rangeData) transactions() []ids.UUID {
	var out []ids.UUID
	for _, r := range d.results {
		for _, st := range r.Steps {
			if st.Transaction != nil {
				out = append(out, *st.Transaction)
			}
		}
	}
	slices.SortFunc(out, func(x, y ids.UUID) int { return strings.Compare(x.String(), y.String()) })
	return slices.Compact(out)
}

func versionsOf(vs []domain.VersionRef) []pack.AssuranceVersion {
	out := make([]pack.AssuranceVersion, 0, len(vs))
	for _, v := range vs {
		out = append(out, pack.AssuranceVersion(v))
	}
	return out
}

func rangeTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// assurance adds assurance.json: the range, its scenarios and steps as the
// server recorded them, and the counts per category (D13).
func (b *builder) assurance() error {
	d := b.rangeData
	a := pack.Assurance{
		Format: pack.AssuranceFormat, Range: d.rng.ID.String(), Org: b.org.String(), Agent: d.rng.Agent.String(),
		Started: rangeTime(d.rng.Started), RunnerVersion: d.rng.RunnerVersion, ScenarioSetDigest: d.rng.SetDigest,
		PolicyVersions: versionsOf(d.rng.Versions.Policies), PackageVersions: versionsOf(d.rng.Versions.Packages),
		Scenarios: []pack.AssuranceScenario{}, Categories: map[string]pack.AssuranceCounts{}, Mismatches: []pack.AssuranceMismatch{},
		Statement: pack.RangeStatement,
	}
	if d.rng.Finished != nil {
		a.Finished = rangeTime(*d.rng.Finished)
	}
	if d.rng.Baseline != nil {
		a.BaselineRange = d.rng.Baseline.String()
	}
	for _, c := range domain.Categories {
		a.Categories[c] = pack.AssuranceCounts{}
	}
	// The scenarios in the order the range declared them.
	byID := map[string]domain.Result{}
	for _, r := range d.results {
		byID[r.Scenario.ID] = r
	}
	for _, decl := range d.rng.Scenarios {
		r, ok := byID[decl.ID]
		if !ok {
			continue
		}
		sc := pack.AssuranceScenario{
			ID: decl.ID, Title: decl.Title, Digest: decl.Digest, Category: decl.Category, Tier: decl.Tier, Suite: decl.Suite, StepCount: decl.StepCount,
			Verdict: string(r.Verdict), ClaimedVerdict: string(r.Claimed), Steps: []pack.AssuranceStep{},
		}
		for _, st := range r.Steps {
			s := pack.AssuranceStep{
				ID: st.ID, Expect: pack.AssuranceExpect(st.Expect), Observed: pack.AssuranceExpect(st.Observed),
				ObservedBy: string(st.ObservedBy), Mismatch: st.Mismatch, Matched: st.Matched, Decisive: st.Decisive, Kind: st.Kind, ProbeKind: st.ProbeKind,
			}
			if st.Mismatch {
				c := pack.AssuranceExpect(st.Claimed)
				s.Claimed = &c
				a.Mismatches = append(a.Mismatches, pack.AssuranceMismatch{Scenario: decl.ID, Step: st.ID})
			}
			if st.Transaction != nil {
				s.Transaction = st.Transaction.String()
			}
			if st.Probe != nil {
				s.Probe = st.Probe.String()
			}
			sc.Steps = append(sc.Steps, s)
		}
		bump := func(c *pack.AssuranceCounts) {
			switch r.Verdict {
			case domain.Pass:
				c.Pass++
			case domain.Fail:
				c.Fail++
			case domain.Errored:
				c.Error++
			case domain.Skipped:
				c.Skipped++
			case domain.Missing:
				c.Missing++
			}
		}
		bump(&a.Totals)
		c := a.Categories[decl.Category]
		bump(&c)
		a.Categories[decl.Category] = c
		a.Scenarios = append(a.Scenarios, sc)
	}
	data, err := pack.Canonical(a)
	if err != nil {
		return err
	}
	b.files = append(b.files, pack.File{Path: pack.AssurancePath, Kind: pack.KindAssurance, Data: data})
	return nil
}

// probeRuns lists the probe reports the range's steps cite, once each.
func (d *rangeData) probeRuns() []ids.UUID {
	var out []ids.UUID
	for _, r := range d.results {
		for _, st := range r.Steps {
			if st.Probe != nil {
				out = append(out, *st.Probe)
			}
		}
	}
	slices.SortFunc(out, func(x, y ids.UUID) int { return strings.Compare(x.String(), y.String()) })
	return slices.Compact(out)
}

// probeProofs adds a verify bundle of the probe reports the range's steps
// cite: the sandbox.closure entries that record them, with their inclusion
// proofs, and the signed reports, so `pclaw verify` re-derives those steps
// offline (HR-224, HR-227). A report no closure entry records is a gap.
func (b *builder) probeProofs() error {
	runs := b.rangeData.probeRuns()
	if len(runs) == 0 {
		return nil
	}
	gap := func(id ids.UUID, reason, detail string) {
		b.gap("probe report "+id.String(), reason, "%s", detail)
	}
	x, err := b.s.Bundles.ExportBundle(b.ctx, evapp.Selection{ProbeRuns: runs}, 0)
	switch {
	case errors.Is(err, evapp.ErrNothingToExport), errors.Is(err, evapp.ErrBundleTooLarge):
		for _, id := range runs {
			gap(id, pack.GapNotFound, "no chained sandbox closure records this probe report, or its bundle is too large")
		}
		return nil
	case err != nil:
		return err
	}
	bd, err := bundle.Decode(x.Bundle)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, p := range bd.ProbeReports {
		have[p.Run] = true
	}
	for _, id := range runs {
		if !have[id.String()] {
			gap(id, pack.GapNotFound, "no chained sandbox closure records this probe report")
		}
	}
	b.files = append(b.files, pack.File{Path: "proofs/probes-0001.json", Kind: pack.KindBundle, Data: x.Bundle})
	return nil
}
