// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves the adversarial range on the server (G0 M12, PN-009;
// HR-224; T-091): starting a range for a range agent, recording each
// scenario's result with the server's own records winning over the runner's
// claims, finishing the range and exporting its assurance report as an
// evidence pack. Storage, the transaction and probe records and the pack
// builder are ports, so the rules run without a database.
package app

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var (
	idPattern     = regexp.MustCompile(`^RT-[0-9]{3}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Limits.
const (
	MaxScenarios    = 200
	MaxSteps        = 40
	MaxRunnerLength = 64
)

// Errors of the range use cases.
var (
	ErrEdition      = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "this needs a higher licence: business-tier scenarios need Business, assurance reports Team")
	ErrNotFound     = pcerr.New(pcerr.NotFound, "RANGE_NOT_FOUND", "range not found")
	ErrAgentMissing = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrNotRange     = pcerr.New(pcerr.FailedPrecondition, "NOT_A_RANGE_AGENT", "ranges run only for range agents")
	ErrNotRunning   = pcerr.New(pcerr.FailedPrecondition, "RANGE_NOT_RUNNING", "the range has finished or was abandoned")
	ErrNotFinished  = pcerr.New(pcerr.FailedPrecondition, "RANGE_NOT_FINISHED", "the range has not finished")
	ErrBaseline     = pcerr.New(pcerr.FailedPrecondition, "BASELINE_INVALID", "the baseline must be a finished range")
	ErrScenarios    = pcerr.New(pcerr.InvalidArgument, "INVALID_SCENARIOS", "declare 1 to 200 distinct scenarios")
	ErrUndeclared   = pcerr.New(pcerr.InvalidArgument, "SCENARIO_NOT_DECLARED", "the scenario, with this digest, was not declared when the range started")
	ErrRecorded     = pcerr.New(pcerr.AlreadyExists, "RESULT_RECORDED", "the scenario already has a result in this range")
	ErrSteps        = pcerr.New(pcerr.InvalidArgument, "INVALID_STEPS", "steps need distinct ids, a PASS or FAIL needs at least one, and at most 40")
	// ErrRecord is every rejected transaction or probe reference; it never
	// says which rule failed, so it cannot be used to probe other objects.
	ErrRecord  = pcerr.New(pcerr.InvalidArgument, "RANGE_RECORD_INVALID", "a transaction or probe report named by a step is not a simulated record of this range's agent made after the range started")
	ErrUnwired = pcerr.New(pcerr.Unavailable, "RANGE_EXPORT_UNAVAILABLE", "assurance reports are not available on this server")
)

// AgentRef is an agent as ranges need it.
type AgentRef struct {
	ID         ids.UUID
	RangeAgent bool
	// Path is where permissions over the agent are checked.
	Path td.Path
}

// Tx is the range store inside one tenant transaction.
type Tx interface {
	// Agent returns the agent, or ErrAgentMissing.
	Agent(ctx context.Context, id ids.UUID) (AgentRef, error)
	// Versions returns the policy and package versions the agent runs
	// under now.
	Versions(ctx context.Context, agent ids.UUID) (domain.Versions, error)
	// Range returns the range (locked for update when lock), or ErrNotFound.
	Range(ctx context.Context, id ids.UUID, lock bool) (domain.Range, error)
	// InsertRange stores the range and returns it with the database's start time.
	InsertRange(ctx context.Context, r domain.Range) (domain.Range, error)
	// Transition moves a range from Running to state and returns the
	// database's finish time; it reports
	// false when the range was no longer Running (a conditional update).
	Transition(ctx context.Context, id ids.UUID, to domain.State) (time.Time, bool, error)
	ListRanges(ctx context.Context, agent *ids.UUID, after ids.UUID, limit int32) ([]domain.Range, error)
	// Results returns the recorded results of a range, in recording order.
	Results(ctx context.Context, rng ids.UUID) ([]domain.Result, error)
	// InsertResult appends a result; false when the scenario already has one.
	InsertResult(ctx context.Context, rng ids.UUID, r domain.Result) (time.Time, bool, error)
	// Transaction returns the server's record of a transaction, if any.
	Transaction(ctx context.Context, id ids.UUID) (domain.TransactionRecord, bool, error)
	// Probe returns the signed probe record of a report, if any.
	Probe(ctx context.Context, id ids.UUID) (domain.ProbeRecord, bool, error)
	// Audit records an event in the same transaction.
	Audit(ctx context.Context, ev audit.Event) error
}

// Store runs fn in a tenant transaction for org.
type Store interface {
	InTx(ctx context.Context, org ids.OrgID, readOnly bool, fn func(ctx context.Context, tx Tx) error) error
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// PackExporter builds a finished range's assurance report as an evidence
// pack and returns the pack's id.
type PackExporter interface {
	ExportRange(ctx context.Context, rng ids.UUID) (ids.UUID, error)
}

// Service serves ranges.
type Service struct {
	Store    Store
	Editions Editions
	Exporter PackExporter
}

// StartInput starts a range.
type StartInput struct {
	Agent         ids.UUID
	Scenarios     []domain.Scenario
	RunnerVersion string
	Baseline      *ids.UUID
}

func (s *Service) entitlements(ctx context.Context) (billing.Entitlements, error) {
	if s.Editions == nil {
		return billing.CommunityEntitlements(), nil
	}
	return s.Editions.Current(ctx)
}

// StartRange records a range for a range agent (redteam.run over the
// agent). The declarations are checked up front (INVALID_SCENARIOS);
// business-tier scenarios need a Business licence; a baseline must be a
// finished range of the org, so a running or abandoned one cannot stand in
// for a real one.
func (s *Service) StartRange(ctx context.Context, in StartInput) (domain.Range, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return domain.Range{}, err
	}
	if err := checkDecls(in.Scenarios); err != nil {
		return domain.Range{}, err
	}
	if in.RunnerVersion == "" || len(in.RunnerVersion) > MaxRunnerLength {
		return domain.Range{}, ErrScenarios
	}
	ents, err := s.entitlements(ctx)
	if err != nil {
		return domain.Range{}, err
	}
	for _, sc := range in.Scenarios {
		if sc.Tier == domain.TierBusiness && !ents.RangeFullLibrary() {
			return domain.Range{}, ErrEdition
		}
	}
	var out domain.Range
	err = s.Store.InTx(ctx, c.Org, false, func(ctx context.Context, tx Tx) error {
		a, err := agentFor(ctx, c, tx, in.Agent)
		if err != nil {
			return err
		}
		if !a.RangeAgent {
			return ErrNotRange
		}
		if in.Baseline != nil {
			b, err := tx.Range(ctx, *in.Baseline, false)
			if err != nil || b.State != domain.Finished {
				if err != nil && !errors.Is(err, ErrNotFound) {
					return err
				}
				return ErrBaseline
			}
		}
		versions, err := tx.Versions(ctx, a.ID)
		if err != nil {
			return err
		}
		set := slices.Clone(in.Scenarios)
		slices.SortFunc(set, func(x, y domain.Scenario) int { return strings.Compare(x.ID, y.ID) })
		out = domain.Range{
			ID: ids.NewV7(), Agent: a.ID, StartedBy: c.Principal.String(), RunnerVersion: in.RunnerVersion,
			SetDigest: domain.SetDigest(set), Scenarios: set, Versions: versions, Baseline: in.Baseline,
			State: domain.Running,
		}
		if out, err = tx.InsertRange(ctx, out); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{
			Name: "redteam.range_started", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "redteam_range", ID: out.ID.String()},
			Details: map[string]string{"agent_id": a.ID.String(), "scenarios": strconv.Itoa(len(set)), "set_digest": out.SetDigest},
		})
	})
	return out, err
}

func checkDecls(set []domain.Scenario) error {
	if len(set) == 0 || len(set) > MaxScenarios {
		return ErrScenarios
	}
	seen := map[string]bool{}
	for _, sc := range set {
		if seen[sc.ID] || !idPattern.MatchString(sc.ID) || !digestPattern.MatchString(sc.Digest) || len(sc.Title) > 200 ||
			!slices.Contains(domain.Categories, sc.Category) || (sc.Suite != "coding-agent" && sc.Suite != "platform") ||
			(sc.Tier != domain.TierCommunity && sc.Tier != domain.TierBusiness) || sc.StepCount < 1 || sc.StepCount > MaxSteps {
			return ErrScenarios
		}
		seen[sc.ID] = true
	}
	return nil
}

// agentFor loads a range agent the caller may run ranges for. An agent the
// caller cannot read is not found; a readable one they may not run is
// permission denied.
func agentFor(ctx context.Context, c tenancy.Caller, tx Tx, id ids.UUID) (AgentRef, error) {
	a, err := tx.Agent(ctx, id)
	if err != nil {
		return a, err
	}
	if err := c.Require(td.PermRedteamRun, a.Path); err != nil {
		if c.Require(td.PermAgentRead, a.Path) != nil {
			return a, ErrAgentMissing
		}
		return a, err
	}
	return a, nil
}

// StepIn is a step the runner recorded.
type StepIn = domain.StepInput

// RecordInput records a scenario's result.
type RecordInput struct {
	Range    ids.UUID
	Scenario string
	Digest   string
	Verdict  domain.Verdict
	Steps    []domain.StepInput
}

// RecordResult records one scenario's result in a running range
// (redteam.run). A step that names a transaction or a probe report is
// observed by the server from its own records, which win over the runner's
// claim (a differing claim marks the step MISMATCH); a transaction or probe
// that is not a simulated record of the range's agent made after the range
// started rejects the call. The scenario verdict is recomputed from the
// steps (HR-224, T-091).
func (s *Service) RecordResult(ctx context.Context, in RecordInput) (domain.Result, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return domain.Result{}, err
	}
	if len(in.Steps) > MaxSteps {
		return domain.Result{}, ErrSteps
	}
	var out domain.Result
	err = s.Store.InTx(ctx, c.Org, false, func(ctx context.Context, tx Tx) error {
		rng, err := tx.Range(ctx, in.Range, true)
		if err != nil {
			return err
		}
		if err := rangeAgentFor(ctx, c, tx, rng); err != nil {
			return err
		}
		if rng.State != domain.Running {
			return ErrNotRunning
		}
		var decl *domain.Scenario
		for i := range rng.Scenarios {
			if rng.Scenarios[i].ID == in.Scenario && rng.Scenarios[i].Digest == in.Digest {
				decl = &rng.Scenarios[i]
			}
		}
		if decl == nil {
			return ErrUndeclared
		}
		if in.Verdict == domain.Pass && len(in.Steps) != decl.StepCount {
			// A PASS records every step; FAIL and ERROR may stop early.
			return ErrSteps
		}
		recorded, err := tx.Results(ctx, rng.ID)
		if err != nil {
			return err
		}
		steps, err := s.resolve(ctx, tx, rng, recorded, decl.ID, in.Steps)
		if err != nil {
			return err
		}
		verdict, ok := domain.Derive(in.Verdict, steps)
		if !ok {
			return ErrSteps
		}
		if verdict == domain.Pass && len(steps) != decl.StepCount {
			verdict = domain.Fail
		}
		out = domain.Result{Scenario: *decl, Verdict: verdict, Steps: steps}
		if verdict != in.Verdict {
			out.Claimed = in.Verdict
		}
		at, added, err := tx.InsertResult(ctx, rng.ID, out)
		if err != nil {
			return err
		} else if !added {
			return ErrRecorded
		}
		out.Recorded = at
		mismatches := 0
		for _, st := range steps {
			if st.Mismatch {
				mismatches++
			}
		}
		return tx.Audit(ctx, audit.Event{
			Name: "redteam.result_recorded", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "redteam_range", ID: rng.ID.String()},
			Details: map[string]string{
				"scenario_id": decl.ID, "verdict": string(verdict), "mismatched_steps": strconv.Itoa(mismatches),
			},
		})
	})
	return out, err
}

func (s *Service) resolve(ctx context.Context, tx Tx, rng domain.Range, recorded []domain.Result, scenario string, in []domain.StepInput) ([]domain.Step, error) {
	// A transaction backs the steps of one scenario per range: several
	// steps of that scenario may cite it, another scenario may not.
	usedBy := map[ids.UUID]string{}
	for _, r := range recorded {
		for _, st := range r.Steps {
			if st.Transaction != nil {
				usedBy[*st.Transaction] = r.Scenario.ID
			}
		}
	}
	seen := map[string]bool{}
	steps := make([]domain.Step, 0, len(in))
	for _, st := range in {
		if st.ID == "" || st.Kind == "" || seen[st.ID] {
			return nil, ErrSteps
		}
		seen[st.ID] = true
		if st.Transaction != nil && st.Probe != nil {
			// One step is backed by one record.
			return nil, ErrRecord
		}
		var derived *domain.Derived
		if st.Transaction != nil {
			rec, found, err := tx.Transaction(ctx, *st.Transaction)
			if err != nil {
				return nil, err
			}
			if !found || !rec.Belongs(rng.Agent, rng.Started) {
				return nil, ErrRecord
			}
			if other, taken := usedBy[*st.Transaction]; taken && other != scenario {
				return nil, ErrRecord
			}
			usedBy[*st.Transaction] = scenario
			if domain.DerivesFromTransaction(st.Kind, st.Expect) {
				d := rec.Observe(st.Expect)
				derived = &d
			}
		}
		if st.Probe != nil {
			rec, found, err := tx.Probe(ctx, *st.Probe)
			if err != nil {
				return nil, err
			}
			if !found || !rec.Belongs(rng.Agent, rng.Started) || st.ProbeKind == "" {
				return nil, ErrRecord
			}
			d, ok := rec.Observe(st.ProbeKind)
			if !ok {
				// The report has no such result.
				return nil, ErrRecord
			}
			derived = &d
		}
		steps = append(steps, domain.Resolve(st, derived))
	}
	return steps, nil
}

// rangeAgentFor checks the caller may run the range's agent: another org's
// range, or one over an agent the caller cannot read, is not found.
func rangeAgentFor(ctx context.Context, c tenancy.Caller, tx Tx, rng domain.Range) error {
	a, err := tx.Agent(ctx, rng.Agent)
	if err != nil {
		if errors.Is(err, ErrAgentMissing) {
			return ErrNotFound
		}
		return err
	}
	if err := c.Require(td.PermRedteamRun, a.Path); err != nil {
		if c.Require(td.PermRedteamRead, a.Path) != nil {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// Detail is a range with its results.
type Detail struct {
	Range   domain.Range
	Results []domain.Result
	Counts  domain.Counts
}

// FinishRange ends a running range (redteam.run): scenarios declared and
// never recorded get a MISSING result, and the state change is conditional
// on the range still running.
func (s *Service) FinishRange(ctx context.Context, id ids.UUID) (Detail, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Detail{}, err
	}
	var out Detail
	err = s.Store.InTx(ctx, c.Org, false, func(ctx context.Context, tx Tx) error {
		rng, err := tx.Range(ctx, id, true)
		if err != nil {
			return err
		}
		if err := rangeAgentFor(ctx, c, tx, rng); err != nil {
			return err
		}
		now, ok, err := tx.Transition(ctx, rng.ID, domain.Finished)
		if err != nil {
			return err
		} else if !ok {
			return ErrNotRunning
		}
		recorded, err := tx.Results(ctx, rng.ID)
		if err != nil {
			return err
		}
		all := domain.Finalize(rng.Scenarios, recorded, now)
		for _, r := range all {
			if r.Verdict != domain.Missing {
				continue
			}
			if _, _, err := tx.InsertResult(ctx, rng.ID, r); err != nil {
				return err
			}
		}
		if all, err = tx.Results(ctx, rng.ID); err != nil {
			return err
		}
		rng.State, rng.Finished = domain.Finished, &now
		out = Detail{Range: rng, Results: all, Counts: domain.Count(all)}
		return tx.Audit(ctx, audit.Event{
			Name: "redteam.range_finished", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "redteam_range", ID: rng.ID.String()},
			Details: map[string]string{
				"pass": strconv.Itoa(out.Counts.Pass), "fail": strconv.Itoa(out.Counts.Fail), "error": strconv.Itoa(out.Counts.Error),
				"skipped": strconv.Itoa(out.Counts.Skipped), "missing": strconv.Itoa(out.Counts.Missing),
			},
		})
	})
	return out, err
}

// GetRange returns a range and its results (redteam.read over its agent).
func (s *Service) GetRange(ctx context.Context, id ids.UUID) (Detail, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Detail{}, err
	}
	var out Detail
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		rng, err := tx.Range(ctx, id, false)
		if err != nil {
			return err
		}
		if err := readable(ctx, c, tx, rng); err != nil {
			return err
		}
		res, err := tx.Results(ctx, rng.ID)
		if err != nil {
			return err
		}
		out = Detail{Range: rng, Results: res, Counts: domain.Count(res)}
		return nil
	})
	return out, err
}

func readable(ctx context.Context, c tenancy.Caller, tx Tx, rng domain.Range) error {
	a, err := tx.Agent(ctx, rng.Agent)
	if err != nil {
		if errors.Is(err, ErrAgentMissing) {
			return ErrNotFound
		}
		return err
	}
	if c.Require(td.PermRedteamRead, a.Path) != nil {
		return ErrNotFound
	}
	return nil
}

// Page is one page of ranges, newest first.
type Page struct {
	Items []domain.Range
	Next  string
}

// ListRanges lists the ranges whose agents the caller reads (redteam.read).
func (s *Service) ListRanges(ctx context.Context, agent *ids.UUID, pr page.Request) (Page, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Page{}, err
	}
	if !c.CanAnywhere(td.PermRedteamRead) {
		return Page{}, td.ErrPermissionDenied(td.PermRedteamRead)
	}
	var out Page
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		after := pr.After
		var visible []domain.Range
		// Scan until a page is full: ranges over agents the caller cannot
		// read are skipped, not counted.
		for len(visible) < pr.Size+1 {
			rows, err := tx.ListRanges(ctx, agent, after, pr.Limit())
			if err != nil {
				return err
			}
			for _, r := range rows {
				if readable(ctx, c, tx, r) == nil {
					visible = append(visible, r)
				}
			}
			if len(rows) < int(pr.Limit()) {
				break
			}
			after = rows[len(rows)-1].ID
		}
		out.Items, out.Next = page.Finish(pr, visible, func(r domain.Range) ids.UUID { return r.ID })
		return nil
	})
	return out, err
}

// ExportAssuranceReport builds a finished range's assurance report as an
// evidence pack (evidence.export, human only; Team licence) and returns the
// pack's id.
func (s *Service) ExportAssuranceReport(ctx context.Context, id ids.UUID) (ids.UUID, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if !c.CanAnywhere(td.PermEvidenceExport) {
		return ids.UUID{}, td.ErrPermissionDenied(td.PermEvidenceExport)
	}
	if s.Exporter == nil {
		return ids.UUID{}, ErrUnwired
	}
	ents, err := s.entitlements(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if !ents.RangeReports() {
		return ids.UUID{}, ErrEdition
	}
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		rng, err := tx.Range(ctx, id, false)
		if err != nil {
			return err
		}
		if err := readable(ctx, c, tx, rng); err != nil {
			return err
		}
		if rng.State != domain.Finished {
			return ErrNotFinished
		}
		return nil
	})
	if err != nil {
		return ids.UUID{}, err
	}
	return s.Exporter.ExportRange(ctx, id)
}
