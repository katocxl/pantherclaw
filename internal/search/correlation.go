// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Incident correlation (G0 M11 part 2 D47; F316, Team): what an incident's
// or case's runs share with other runs in a window — destinations,
// credentials (inferred from the credential versions' lifetimes), operation
// sequences — and the grant and tool changes around them. Every shared
// record is a correlation, never a cause. Each part reads under the
// viewer's own permission and scope for it; the incident or case itself
// must be readable, else it is reported not found.

// BuiltinIncidentCorrelation is the incident-correlation built-in query.
const BuiltinIncidentCorrelation Builtin = "incident_correlation" // F316

// EntityCorrelations is the entity of a correlation's rows; it is not a
// structured-query entity.
const EntityCorrelations Entity = "correlations"

// Correlation labels.
const (
	CorrIncidentRun       = "INCIDENT_RUN"
	CorrSharedDestination = "SHARED_DESTINATION"
	CorrSharedCredential  = "SHARED_CREDENTIAL"
	CorrSharedSequence    = "SHARED_OPERATION_SEQUENCE"
	CorrGrantChange       = "GRANT_CHANGE"
	CorrToolChange        = "TOOL_CHANGE"
)

// Limits on correlation.
const (
	defaultCorrelationDays = 7
	maxCorrelationDays     = 30
	// sequenceLen is how many consecutive operations two runs must share.
	sequenceLen = 3
)

// Editions reads the org's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Errors.
var (
	ErrCorrelationEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"incident correlation needs the Team edition or above")
	ErrSubjectNotFound = pcerr.New(pcerr.NotFound, "NOT_FOUND", "incident or case not found")
)

// validateCorrelation checks incident_correlation's parameters.
func (b BuiltinQuery) validateCorrelation() error {
	for _, used := range b.Params.used() {
		if used != "incident" && used != "case" && used != "days" {
			return ErrInvalidQuery("parameter " + used + " does not apply to " + string(b.Name))
		}
	}
	switch {
	case (b.Params.Incident == nil) == (b.Params.Case == nil):
		return ErrInvalidQuery("one of incident or case is required")
	case b.Params.Days < 0 || b.Params.Days > maxCorrelationDays:
		return ErrInvalidQuery("days must be between 1 and 30")
	}
	return nil
}

// subjectRuns is what a correlation starts from.
type subjectRuns struct {
	at     time.Time
	runs   []dbq.CorrIncidentRunsRow
	agents []ids.UUID
}

// correlationSubject loads the incident or case b names if c may read it.
func correlationSubject(ctx context.Context, c tenancy.Caller, q *dbq.Queries, b BuiltinQuery) (subjectRuns, error) {
	var out subjectRuns
	if b.Params.Incident != nil {
		sc, err := AgentScope(ctx, c, q, td.PermIncidentRead)
		if err != nil || sc.Restricted {
			return out, firstErr(err, ErrSubjectNotFound)
		}
		rows, err := q.SearchIncidents(ctx, dbq.SearchIncidentsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			ID: b.Params.Incident, States: []string{}, Severities: []string{}, PageLimit: 1,
		})
		if err != nil || len(rows) == 0 {
			return out, firstErr(err, ErrSubjectNotFound)
		}
		out.at = rows[0].CreatedAt
		return out, out.addIncident(ctx, c, q, *b.Params.Incident)
	}
	sc, err := AgentScope(ctx, c, q, td.PermCaseRead)
	if err != nil || sc.Restricted {
		return out, firstErr(err, ErrSubjectNotFound)
	}
	rows, err := q.SearchCases(ctx, dbq.SearchCasesParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
		ID: b.Params.Case, States: []string{}, PageLimit: 1,
	})
	if err != nil || len(rows) == 0 {
		return out, firstErr(err, ErrSubjectNotFound)
	}
	out.at = rows[0].CreatedAt
	runs, err := q.CorrCaseRuns(ctx, c.Org, *b.Params.Case)
	if err != nil {
		return out, err
	}
	for _, r := range runs {
		out.runs = append(out.runs, dbq.CorrIncidentRunsRow(r))
	}
	if out.agents, err = q.CaseAgents(ctx, c.Org.UUID(), *b.Params.Case); err != nil {
		return out, err
	}
	if inc := rows[0].IncidentID; inc != nil {
		return out, out.addIncident(ctx, c, q, *inc)
	}
	return out, nil
}

func (s *subjectRuns) addIncident(ctx context.Context, c tenancy.Caller, q *dbq.Queries, inc ids.UUID) error {
	runs, err := q.CorrIncidentRuns(ctx, c.Org, &inc)
	if err != nil {
		return err
	}
	agents, err := q.CorrIncidentAgents(ctx, c.Org, &inc)
	if err != nil {
		return err
	}
	for _, r := range runs {
		if !slices.ContainsFunc(s.runs, func(x dbq.CorrIncidentRunsRow) bool { return x.ID == r.ID }) {
			s.runs = append(s.runs, r)
		}
	}
	for _, a := range agents {
		if !slices.Contains(s.agents, a) {
			s.agents = append(s.agents, a)
		}
	}
	return nil
}

func firstErr(err, otherwise error) error {
	if err != nil {
		return err
	}
	return otherwise
}

func (s Scope) has(a ids.UUID) bool { return s.All || slices.Contains(s.Agents, a) }

// runCorrelation answers incident_correlation in one page.
func (s *Service) runCorrelation(ctx context.Context, c tenancy.Caller, b BuiltinQuery, pr page.Request) (Result, error) {
	if err := b.validateCorrelation(); err != nil {
		return Result{}, err
	}
	if !pr.After.IsZero() {
		return Result{}, page.ErrBadToken // one page
	}
	if s.Editions == nil {
		return Result{}, ErrCorrelationEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return Result{}, err
	}
	if !e.Cases() {
		return Result{}, ErrCorrelationEdition
	}
	var out Result
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.correlate(ctx, c, dbq.New(tx), b)
		return err
	}, db.ReadOnly())
	return out, err
}

func (s *Service) correlate(ctx context.Context, c tenancy.Caller, q *dbq.Queries, b BuiltinQuery) (Result, error) {
	subj, err := correlationSubject(ctx, c, q, b)
	if err != nil {
		return Result{}, err
	}
	days := b.Params.Days
	if days == 0 {
		days = defaultCorrelationDays
	}
	asOf := s.now()
	start := subj.at.Add(-time.Duration(days) * 24 * time.Hour)
	end := asOf.Add(time.Microsecond)
	ev, err := AgentScope(ctx, c, q, td.PermEvidenceRead)
	if err != nil {
		return Result{}, err
	}
	out := Result{Scope: ev, AsOf: asOf, Range: Range{Start: &start, Changing: true}}
	out.Omissions = append(out.Omissions, Omission{
		Code:   "CORRELATION_NOT_CAUSE",
		Detail: "shared destinations, credentials, sequences and changes are correlations, never causes",
	})
	if !ev.All {
		out.Omissions = append(out.Omissions, Omission{
			Code:   omissionScopeLimited,
			Detail: "runs cover only the agents where you hold " + string(td.PermEvidenceRead),
		})
	}
	var runIDs []ids.UUID
	for _, r := range subj.runs {
		if !ev.has(r.AgentID) {
			continue
		}
		runIDs = append(runIDs, r.ID)
		out.Items = append(out.Items, Item{
			Entity: EntityCorrelations, ID: "run:" + r.ID.String(), Time: r.CreatedAt, Label: CorrIncidentRun,
			Fields: fields("run", r.ID.String(), "agent", r.AgentID.String()), Evidence: []string{"run:" + r.ID.String()},
		})
	}
	if runIDs == nil {
		runIDs = []ids.UUID{}
	}
	if !ev.Restricted && len(runIDs) > 0 {
		if err := correlateRuns(ctx, c, q, ev, runIDs, start, end, &out); err != nil {
			return Result{}, err
		}
	}
	if err := correlateChanges(ctx, c, q, subj, runIDs, start, end, &out); err != nil {
		return Result{}, err
	}
	out.Count = len(out.Items)
	if out.Count == 0 {
		out.Empty = EmptyNothingInScope
	}
	return out, nil
}

// correlateRuns adds the destinations, credentials and operation sequences
// the subject runs share with other runs in ev's scope.
func correlateRuns(ctx context.Context, c tenancy.Caller, q *dbq.Queries, ev Scope, runIDs []ids.UUID, start, end time.Time, out *Result) error {
	dests, err := q.CorrSharedDestinations(ctx, dbq.CorrSharedDestinationsParams{
		OrgID: c.Org, RunIds: runIDs, AllAgents: ev.All, Agents: ev.agentList(), StartTime: start, EndTime: end,
	})
	if err != nil {
		return err
	}
	for _, d := range dests {
		out.Items = append(out.Items, Item{
			Entity: EntityCorrelations, ID: "destination:" + d.RunID.String() + ":" + d.Host, Time: d.FirstAt,
			Label: CorrSharedDestination,
			Fields: fields("run", d.RunID.String(), "agent", d.AgentID.String(), "host", d.Host,
				"destination_class", d.DestinationClass, "connection", d.ConnectionID.String(),
				"actions", strconv.FormatInt(d.Actions, 10), "last_at", ts(&d.LastAt), "basis", "OBSERVED"),
			Evidence: []string{"run:" + d.RunID.String(), "connection:" + d.ConnectionID.String()},
		})
	}
	creds, err := q.CorrSharedCredentials(ctx, dbq.CorrSharedCredentialsParams{
		OrgID: c.Org, RunIds: runIDs, AllAgents: ev.All, Agents: ev.agentList(), StartTime: start, EndTime: end,
	})
	if err != nil {
		return err
	}
	for _, r := range creds {
		out.Items = append(out.Items, Item{
			Entity: EntityCorrelations, ID: "credential:" + r.RunID.String() + ":" + r.CredentialID.String(), Time: r.FirstAt,
			Label: CorrSharedCredential,
			Fields: fields("run", r.RunID.String(), "agent", r.AgentID.String(), "credential", r.CredentialID.String(),
				"connection", r.ConnectionID.String(), "credential_version", strconv.Itoa(int(r.Version)),
				"actions", strconv.FormatInt(r.Actions, 10), "last_at", ts(&r.LastAt), "basis", "INFERRED"),
			Evidence: []string{"run:" + r.RunID.String(), "credential:" + r.CredentialID.String()},
		})
	}
	if len(creds) > 0 {
		out.Omissions = append(out.Omissions, Omission{
			Code:   "INFERRED",
			Detail: "which credential version an action used is inferred from the versions' lifetimes",
		})
	}
	ops, err := q.CorrRunOperations(ctx, dbq.CorrRunOperationsParams{
		OrgID: c.Org, AllAgents: ev.All, Agents: ev.agentList(), RunIds: runIDs, StartTime: start, EndTime: end,
	})
	if err != nil {
		return err
	}
	if len(ops) > 500 {
		ops = ops[:500]
		out.Omissions = append(out.Omissions, Omission{Code: "TRUNCATED", Detail: "operation sequences compare at most 500 runs"})
	}
	mine := map[string]bool{}
	for _, o := range ops {
		if slices.Contains(runIDs, o.RunID) {
			for _, g := range ngrams(o.Operations) {
				mine[g] = true
			}
		}
	}
	for _, o := range ops {
		if slices.Contains(runIDs, o.RunID) {
			continue
		}
		for _, g := range ngrams(o.Operations) {
			if mine[g] {
				out.Items = append(out.Items, Item{
					Entity: EntityCorrelations, ID: "sequence:" + o.RunID.String(), Time: o.FirstAt, Label: CorrSharedSequence,
					Fields: fields("run", o.RunID.String(), "agent", o.AgentID.String(),
						"sequence", strings.ReplaceAll(g, "\x00", " > "), "last_at", ts(&o.LastAt), "basis", "OBSERVED"),
					Evidence: []string{"run:" + o.RunID.String()},
				})
				break
			}
		}
	}
	return nil
}

// ngrams returns ops' runs of sequenceLen consecutive operations (the
// whole list when it is shorter but has at least two).
func ngrams(ops []string) []string {
	if len(ops) < 2 {
		return nil
	}
	if len(ops) < sequenceLen {
		return []string{strings.Join(ops, "\x00")}
	}
	out := make([]string, 0, len(ops)-sequenceLen+1)
	for i := 0; i+sequenceLen <= len(ops); i++ {
		out = append(out, strings.Join(ops[i:i+sequenceLen], "\x00"))
	}
	return out
}

// correlateChanges adds the grant changes of the subject's agents (in the
// viewer's grant.read scope) and the tool changes of the connections its
// runs used (package.read and connection.read at the org).
func correlateChanges(ctx context.Context, c tenancy.Caller, q *dbq.Queries, subj subjectRuns, runIDs []ids.UUID, start, end time.Time, out *Result) error {
	gs, err := AgentScope(ctx, c, q, td.PermGrantRead)
	if err != nil {
		return err
	}
	agents := slices.Clone(subj.agents)
	for _, r := range subj.runs {
		if !slices.Contains(agents, r.AgentID) {
			agents = append(agents, r.AgentID)
		}
	}
	hidden := false
	for _, a := range agents {
		if !gs.has(a) {
			hidden = true
			continue
		}
		rows, err := q.InvGrantChanges(ctx, dbq.InvGrantChangesParams{OrgID: c.Org, AgentID: a, StartTime: start, EndTime: end})
		if err != nil {
			return err
		}
		for _, g := range rows {
			out.Items = append(out.Items, Item{
				Entity: EntityCorrelations, ID: "grant:" + g.GrantID.String() + ":" + g.Change + ":" + g.At.UTC().Format(time.RFC3339Nano),
				Time: g.At, Label: CorrGrantChange,
				Fields: fields("grant", g.GrantID.String(), "agent", g.AgentID.String(), "change", g.Change,
					"widens", boolStr(g.Widens), "grantor_kind", g.GrantorKind, "grantor", g.GrantorID.String(), "basis", "OBSERVED"),
				Evidence: []string{"grant:" + g.GrantID.String()},
			})
		}
	}
	if hidden {
		out.Omissions = append(out.Omissions, Omission{
			Code:   omissionScopeLimited,
			Detail: "grant changes cover only the agents where you hold " + string(td.PermGrantRead),
		})
	}
	if len(runIDs) == 0 {
		return nil
	}
	if !c.Can(td.PermPackageRead, td.OrgPath(c.Org)) || !c.Can(td.PermConnectionRead, td.OrgPath(c.Org)) {
		out.Omissions = append(out.Omissions, Omission{
			Code:   omissionRestricted,
			Detail: "tool changes need " + string(td.PermPackageRead) + " and " + string(td.PermConnectionRead) + " across the org",
		})
		return nil
	}
	conns, err := q.CorrRunConnections(ctx, c.Org, runIDs)
	if err != nil || len(conns) == 0 {
		return err
	}
	tools, err := q.InvToolChanges(ctx, dbq.InvToolChangesParams{OrgID: c.Org, ConnectionIds: conns, StartTime: start, EndTime: end})
	if err != nil {
		return err
	}
	for _, t := range tools {
		out.Items = append(out.Items, Item{
			Entity: EntityCorrelations, ID: "tool:" + t.ConnectionID.String() + ":" + t.Change + ":" + t.At.UTC().Format(time.RFC3339Nano),
			Time: t.At, Label: CorrToolChange,
			Fields: fields("connection", t.ConnectionID.String(), "name", t.Connection, "package", t.Package,
				"change", t.Change, "basis", "OBSERVED"),
			Evidence: []string{"connection:" + t.ConnectionID.String()},
		})
	}
	return nil
}
