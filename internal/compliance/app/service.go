// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app reads a framework's coverage (G0 M25 D300-D304, D311, D312;
// F892-F896; HR-600..606). Coverage derives only from PantherClaw's own
// records, each read under its own permission at org scope: what the caller
// may not read is a gap that says so, never a count of nothing. Nothing here
// writes anything.
package app

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	"github.com/katocxl/pantherclaw/internal/compliance/ports"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	rangeapp "github.com/katocxl/pantherclaw/internal/ranges/app"
	rangedomain "github.com/katocxl/pantherclaw/internal/ranges/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Limits of one report.
const (
	// MaxPeriod bounds a period, like a pack's time range.
	MaxPeriod = 366 * 24 * time.Hour
	// MaxRefs bounds the records cited for one source or tag.
	MaxRefs = 10
	// MaxRanges bounds the ranges one report reads, newest first.
	MaxRanges = 100
)

// Errors.
var (
	ErrEdition     = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "this framework needs a higher edition")
	ErrUnknown     = pcerr.New(pcerr.InvalidArgument, "UNKNOWN_FRAMEWORK", "name a listed framework")
	ErrBadPeriod   = pcerr.New(pcerr.InvalidArgument, "INVALID_PERIOD", "end must be after start, at most 366 days later")
	ErrUnavailable = pcerr.New(pcerr.Unavailable, "COMPLIANCE_UNAVAILABLE", "compliance coverage is not available on this server")
)

// Entitlements reports the licence's entitlements.
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service reads coverage.
type Service struct {
	Pool *db.Pool
	Ents Entitlements
	// Campaigns reads campaign results; nil holds none.
	Campaigns ports.CampaignResults
}

// FrameworkInfo is one framework as this edition sees it.
type FrameworkInfo struct {
	Framework domain.Framework
	Title     string
	Controls  int
	Available bool
}

func caller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	if !c.CanAnywhere(td.PermComplianceRead) {
		return tenancy.Caller{}, td.ErrPermissionDenied(td.PermComplianceRead)
	}
	return c, nil
}

func (s *Service) ents(ctx context.Context) (billing.Entitlements, error) {
	if s.Ents == nil {
		return billing.Entitlements{}, ErrEdition
	}
	return s.Ents.Current(ctx)
}

// ListFrameworks lists every framework. A framework this edition does not
// read is listed all the same, so nobody takes its absence for a clean slate.
func (s *Service) ListFrameworks(ctx context.Context) ([]FrameworkInfo, error) {
	if _, err := caller(ctx); err != nil {
		return nil, err
	}
	ents, err := s.ents(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]FrameworkInfo, 0, len(domain.Frameworks()))
	for _, f := range domain.Frameworks() {
		out = append(out, FrameworkInfo{
			Framework: f, Title: f.Title(), Controls: len(domain.Controls(f)), Available: ents.ComplianceFramework(string(f)),
		})
	}
	return out, nil
}

// GetFrameworkCoverage derives a framework's controls for a period from what
// the caller may read. It needs compliance.read and the framework's edition.
func (s *Service) GetFrameworkCoverage(ctx context.Context, f domain.Framework, start, end time.Time) (domain.Report, error) {
	if _, err := caller(ctx); err != nil {
		return domain.Report{}, err
	}
	ents, err := s.ents(ctx)
	if err != nil {
		return domain.Report{}, err
	}
	if !f.Known() {
		return domain.Report{}, ErrUnknown
	}
	if !ents.ComplianceFramework(string(f)) {
		return domain.Report{}, ErrEdition
	}
	return s.Report(ctx, f, start, end)
}

// Report derives the same coverage for the caller in ctx with no check of its
// own beyond each source's permission: a pack's job calls it as the pack's
// creator, whose evidence.export and edition were checked when they asked.
func (s *Service) Report(ctx context.Context, f domain.Framework, start, end time.Time) (domain.Report, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return domain.Report{}, err
	}
	if !f.Known() {
		return domain.Report{}, ErrUnknown
	}
	if !end.After(start) || end.Sub(start) > MaxPeriod {
		return domain.Report{}, ErrBadPeriod
	}
	if s.Pool == nil {
		return domain.Report{}, ErrUnavailable
	}
	in, err := s.inputs(ctx, c, start, end)
	if err != nil {
		return domain.Report{}, err
	}
	controls, err := domain.Evaluate(f, in)
	if err != nil {
		return domain.Report{}, err
	}
	return domain.Report{
		Format: domain.Format, Org: c.Org.String(), Framework: f, CatalogDigest: domain.CatalogDigest(f),
		PeriodStart: start.UTC().Format(time.RFC3339Nano), PeriodEnd: end.UTC().Format(time.RFC3339Nano),
		Split: domain.SplitOf(in), Inputs: in, Controls: controls, Statement: pack.ComplianceStatement,
	}, nil
}

// inputs reads every source. Records of one report come from one snapshot.
func (s *Service) inputs(ctx context.Context, c tenancy.Caller, start, end time.Time) (domain.Inputs, error) {
	org := td.OrgPath(c.Org)
	can := func(p td.Permission) bool { return c.Can(p, org) }
	in := domain.Inputs{Sources: []domain.SourceCount{}, Tests: []domain.TestCount{}, Stated: []domain.StatedCount{}}
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for _, r := range []struct {
			perm td.Permission
			read func(context.Context, *dbq.Queries, ids.OrgID, time.Time, time.Time) (domain.SourceCount, error)
			src  domain.Source
		}{
			{td.PermEvidenceRead, receipts, domain.SourceReceipts},
			{td.PermApprovalRead, approvals, domain.SourceApprovals},
			{td.PermGrantRead, grants, domain.SourceGrants},
			{td.PermCoverageRead, coverage, domain.SourceCoverage},
		} {
			n := domain.SourceCount{Source: r.src, Refs: []domain.Ref{}}
			if can(r.perm) {
				var err error
				if n, err = r.read(ctx, q, c.Org, start, end); err != nil {
					return err
				}
				n.Source, n.Readable = r.src, true
			}
			in.Sources = append(in.Sources, n)
		}
		role, risk := domain.StatedCount{Field: domain.FieldAIActRole}, domain.StatedCount{Field: domain.FieldAIActRisk}
		if can(td.PermAgentRead) {
			st, err := q.ComplianceStatedCounts(ctx, c.Org)
			if err != nil {
				return err
			}
			role.Readable, role.Stated, role.Unset = true, st.RoleStated, st.RoleUnset
			risk.Readable, risk.Stated, risk.Unset = true, st.RiskStated, st.RiskUnset
		}
		in.Stated = append(in.Stated, role, risk)
		return nil
	}, db.ReadOnly(), db.RepeatableRead())
	if err != nil {
		return domain.Inputs{}, err
	}
	tally := newTally()
	rangeSource := domain.SourceCount{Source: domain.SourceRange, Refs: []domain.Ref{}}
	if can(td.PermRedteamRead) {
		rangeSource.Readable = true
		if err := s.ranges(ctx, c.Org, start, end, &rangeSource, tally); err != nil {
			return domain.Inputs{}, err
		}
	}
	campaignSource := domain.SourceCount{Source: domain.SourceCampaign, Refs: []domain.Ref{}}
	if can(td.PermRedteamRead) {
		campaignSource.Readable = true
		if err := s.campaigns(ctx, c.Org, start, end, &campaignSource, tally); err != nil {
			return domain.Inputs{}, err
		}
	}
	in.Sources = append(in.Sources, rangeSource, campaignSource)
	in.Tests = tally.counts()
	return in, nil
}

func refs(kind string, simulated bool, list []ids.UUID) []domain.Ref {
	out := make([]domain.Ref, 0, len(list))
	for _, id := range list {
		out = append(out, domain.Ref{Type: kind, ID: id.String(), Simulated: simulated})
	}
	return out
}

func receipts(ctx context.Context, q *dbq.Queries, org ids.OrgID, start, end time.Time) (domain.SourceCount, error) {
	n, err := q.ComplianceReceiptCounts(ctx, org, start, end)
	if err != nil {
		return domain.SourceCount{}, err
	}
	out := domain.SourceCount{Real: n.RealCount, Simulated: n.SimulatedCount, Refs: []domain.Ref{}}
	for _, sim := range []bool{false, true} {
		list, err := q.ComplianceReceiptRefs(ctx, dbq.ComplianceReceiptRefsParams{
			OrgID: org, Simulated: sim, PeriodStart: start, PeriodEnd: end, PageLimit: MaxRefs,
		})
		if err != nil {
			return domain.SourceCount{}, err
		}
		out.Refs = append(out.Refs, refs(domain.RefTransaction, sim, list)...)
	}
	return out, nil
}

// approvals cites the transactions that were held: their receipts are what a
// pack can show offline.
func approvals(ctx context.Context, q *dbq.Queries, org ids.OrgID, start, end time.Time) (domain.SourceCount, error) {
	n, err := q.ComplianceApprovalCounts(ctx, org, &start, &end)
	if err != nil {
		return domain.SourceCount{}, err
	}
	out := domain.SourceCount{Real: n.RealCount, Simulated: n.SimulatedCount, Refs: []domain.Ref{}}
	for _, sim := range []bool{false, true} {
		list, err := q.ComplianceApprovalRefs(ctx, dbq.ComplianceApprovalRefsParams{
			OrgID: org, Simulated: sim, PeriodStart: &start, PeriodEnd: &end, PageLimit: MaxRefs,
		})
		if err != nil {
			return domain.SourceCount{}, err
		}
		out.Refs = append(out.Refs, refs(domain.RefTransaction, sim, list)...)
	}
	return out, nil
}

func grants(ctx context.Context, q *dbq.Queries, org ids.OrgID, start, end time.Time) (domain.SourceCount, error) {
	n, err := q.ComplianceGrantCounts(ctx, org, end, &start)
	if err != nil {
		return domain.SourceCount{}, err
	}
	out := domain.SourceCount{Real: n.RealCount, Simulated: n.SimulatedCount, Refs: []domain.Ref{}}
	for _, sim := range []bool{false, true} {
		list, err := q.ComplianceGrantRefs(ctx, dbq.ComplianceGrantRefsParams{
			OrgID: org, Simulated: sim, PeriodStart: &start, PeriodEnd: end, PageLimit: MaxRefs,
		})
		if err != nil {
			return domain.SourceCount{}, err
		}
		out.Refs = append(out.Refs, refs(domain.RefGrant, sim, list)...)
	}
	return out, nil
}

func coverage(ctx context.Context, q *dbq.Queries, org ids.OrgID, start, end time.Time) (domain.SourceCount, error) {
	n, err := q.ComplianceCoverageCount(ctx, org, end, &start)
	if err != nil {
		return domain.SourceCount{}, err
	}
	list, err := q.ComplianceCoverageRefs(ctx, dbq.ComplianceCoverageRefsParams{
		OrgID: org, PeriodStart: &start, PeriodEnd: end, PageLimit: MaxRefs,
	})
	if err != nil {
		return domain.SourceCount{}, err
	}
	return domain.SourceCount{Real: n, Refs: refs(domain.RefCoverage, false, list)}, nil
}

// tally adds up test results by tag and source.
type tally struct {
	byKey map[string]*domain.TestCount
}

func newTally() *tally { return &tally{byKey: map[string]*domain.TestCount{}} }

func (t *tally) at(tag string, src domain.Source) *domain.TestCount {
	key := tag + "/" + string(src)
	c, ok := t.byKey[key]
	if !ok {
		c = &domain.TestCount{Tag: tag, Source: src, Refs: []domain.Ref{}}
		t.byKey[key] = c
	}
	return c
}

func (t *tally) cite(c *domain.TestCount, r domain.Ref) {
	if len(c.Refs) < MaxRefs && !slices.Contains(c.Refs, r) {
		c.Refs = append(c.Refs, r)
	}
}

func (t *tally) counts() []domain.TestCount {
	out := make([]domain.TestCount, 0, len(t.byKey))
	for _, c := range t.byKey {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b domain.TestCount) int {
		return strings.Compare(a.Tag+"/"+string(a.Source), b.Tag+"/"+string(b.Source))
	})
	return out
}

// libraryTags returns a scenario's tags: the server's library says them, and
// only for the digest it shipped, never the runner.
func libraryTags(id, digest string) []string {
	e, ok := library.Lookup(id)
	if !ok || e.Digest != digest {
		return nil
	}
	return e.ASI
}

// ranges reads finished library ranges. A customer-authored range is left
// out by the query (HR-466).
func (s *Service) ranges(ctx context.Context, org ids.OrgID, start, end time.Time, src *domain.SourceCount, t *tally) error {
	var list []ids.UUID
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		list, err = dbq.New(tx).ComplianceRanges(ctx, dbq.ComplianceRangesParams{
			OrgID: org, PeriodStart: &start, PeriodEnd: &end, PageLimit: MaxRanges + 1,
		})
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	if len(list) > MaxRanges {
		list, src.Truncated = list[:MaxRanges], true
	}
	return pgranges.Store{Pool: s.Pool}.InTx(ctx, org, true, func(ctx context.Context, tx rangeapp.Tx) error {
		for _, id := range list {
			results, err := tx.Results(ctx, id)
			if err != nil {
				return err
			}
			ref := domain.Ref{Type: domain.RefRange, ID: id.String(), Simulated: true}
			if len(src.Refs) < MaxRefs {
				src.Refs = append(src.Refs, ref)
			}
			for _, r := range results {
				tags := libraryTags(r.Scenario.ID, r.Scenario.Digest)
				if len(tags) == 0 {
					continue
				}
				src.Simulated++
				for _, tag := range tags {
					c := t.at(tag, domain.SourceRange)
					count(c, r)
					t.cite(c, ref)
				}
			}
		}
		return nil
	})
}

// count files one scenario's result. PASS needs every step seen by the
// server: a runner's word alone is a report, not a test that held (HR-224).
func count(c *domain.TestCount, r rangedomain.Result) {
	switch r.Verdict {
	case rangedomain.Pass:
		for _, st := range r.Steps {
			if st.ObservedBy != rangedomain.Server {
				c.Reported++
				return
			}
		}
		c.Held++
	case rangedomain.Fail:
		c.Failed++
	case rangedomain.Errored, rangedomain.Skipped, rangedomain.Missing:
		c.NotExercised++
	default:
		c.NotExercised++ // a verdict this build does not know never held
	}
}

func (s *Service) campaigns(ctx context.Context, org ids.OrgID, start, end time.Time, src *domain.SourceCount, t *tally) error {
	if s.Campaigns == nil {
		return nil
	}
	steps, truncated, err := s.Campaigns.CampaignSteps(ctx, org, start, end)
	if err != nil {
		return err
	}
	src.Truncated = truncated
	for _, st := range steps {
		ref := domain.Ref{Type: domain.RefCampaign, ID: st.Campaign.String(), Simulated: true}
		if len(st.Tags) > 0 {
			src.Simulated++
			if len(src.Refs) < MaxRefs && !slices.Contains(src.Refs, ref) {
				src.Refs = append(src.Refs, ref)
			}
		}
		for _, tag := range st.Tags {
			c := t.at(tag, domain.SourceCampaign)
			switch st.Outcome {
			case ports.OutcomeHeld, ports.OutcomeDenied:
				c.Held++
			case ports.OutcomeAllowed:
				c.Failed++
			case ports.OutcomeNotRoutedReported:
				c.Reported++ // labeled reported, never proven (D309)
			default:
				c.NotExercised++ // D306
			}
			t.cite(c, ref)
		}
	}
	return nil
}

// ReportInfo is one signed report's parameters and digest.
type ReportInfo struct {
	ID, Pack, CreatedBy ids.UUID
	Framework           domain.Framework
	Start, End, Created time.Time
	// SHA256 is the hex digest of compliance.json, empty until built.
	SHA256 string
}

// ReportPage is one page of reports.
type ReportPage struct {
	Items []ReportInfo
	Next  string
}

// ListReports lists the signed reports, newest first (D303).
func (s *Service) ListReports(ctx context.Context, pr page.Request) (ReportPage, error) {
	c, err := caller(ctx)
	if err != nil {
		return ReportPage{}, err
	}
	var out ReportPage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListComplianceReports(ctx, c.Org, pr.After, pr.Limit())
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcComplianceReport) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, ReportInfo{
				ID: r.ID, Pack: r.PackID, CreatedBy: r.CreatedBy, Framework: domain.Framework(r.Framework),
				Start: r.PeriodStart, End: r.PeriodEnd, Created: r.CreatedAt, SHA256: hex.EncodeToString(r.ReportSha256),
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
