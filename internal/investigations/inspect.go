// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package investigations

import (
	"context"
	"encoding/base64"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Section is one section of a run inspection (rows26 D20).
type Section int

// Sections, numbered as InspectSection.
const (
	SectionTimeline Section = iota + 1
	SectionLineage
	SectionBudget
	SectionApprovals
	SectionCoverage
	SectionGaps
)

// AllSections are every section, in order.
var AllSections = []Section{SectionTimeline, SectionLineage, SectionBudget, SectionApprovals, SectionCoverage, SectionGaps}

// New gap kinds of an inspection (F229): a decision on a connection whose
// receipt claims no coverage, or coverage below ENFORCED (or expired when
// decided), and a gateway the run used that went unseen for longer than
// its heartbeat window inside the run's window.
const (
	GapNoCoverageClaim       = "NO_COVERAGE_CLAIM"
	GapCoverageBelowEnforced = "COVERAGE_BELOW_ENFORCED"
	GapTelemetry             = "TELEMETRY_GAP"
)

// Bounds of an inspection.
const (
	DefaultTimelinePage = 200
	MaxTimelinePage     = 500
	MaxDownstream       = 200
	maxGatewaySightings = 20000
	// HeartbeatWindow is how long a gateway may go without deciding or
	// renewing its 24-hour certificate before it counts as unseen: the
	// evidence status's gateway staleness (operations, F219).
	HeartbeatWindow = 26 * time.Hour
)

// ErrBadPageToken refuses a timeline page token of another run or a
// malformed one.
var ErrBadPageToken = pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "the timeline page token is not valid for this run")

// SectionScope is a Scope that also answers, per section, whether the
// viewer holds that section's own permission where the run's agent lives
// (HR-401).
type SectionScope interface {
	Scope
	Readable(ctx context.Context, sec Section, agent ids.UUID) (bool, error)
}

// InspectOptions are what an inspection reads.
type InspectOptions struct {
	// Sections asked for; empty for all.
	Sections []Section
	// PageSize is the timeline page (0: DefaultTimelinePage).
	PageSize int
	// PageToken is the previous page's NextPageToken.
	PageToken string
	// WithPhases fills inferred phases (Team, F232).
	WithPhases bool
}

// RunSummary is who ran what under which authority.
type RunSummary struct {
	Run, Agent          ids.UUID
	TaskRef             string // untrusted
	Launcher, Principal *Party
	Grant               *ids.UUID
	State               string
	Start               time.Time
	End                 *time.Time
	EndReason           string
	Parent              *ids.UUID
	Depth               int
}

// ExecutionLink is an automation execution linked to a run.
type ExecutionLink struct {
	Execution, Automation    ids.UUID
	Mode, State, TriggerKind string
	Created                  time.Time
	Ended                    *time.Time
}

// Lineage is where a run sits among runs and automations (F065).
type Lineage struct {
	Parents             []Delegation
	Children            []Lane
	ChildrenTruncated   bool
	Upstream            *ExecutionLink
	Downstream          []ExecutionLink
	DownstreamTruncated bool
}

// BudgetLine is what a run's actions did to one budget account or counter
// (F227). Held, Committed and Released are amounts, or counts for a
// counter; Remaining is filled by the caller from the rule's limit.
type BudgetLine struct {
	Account                   ids.UUID
	IsAccount                 bool
	Rule, Currency            string
	Held, Committed, Released string
	Count                     int64
	Remaining                 string
}

// RouteCoverage is a coverage snapshot a run's decisions claimed.
type RouteCoverage struct {
	Connection      ids.UUID
	Operation       string
	Snapshot        ids.UUID
	State           string
	Reasons         []string
	Computed        time.Time
	StaleAtDecision bool
}

// Inspection is one run end to end (F224). A section is nil or empty when
// it was not asked for, or when the viewer may not read it; the latter are
// listed in Omitted, never returned in part (HR-401).
type Inspection struct {
	Run               RunSummary
	Lineage           *Lineage
	Events            []Event
	Phases            []Phase
	HasTimeline       bool
	NextPageToken     string
	TimelineTruncated bool
	Budget            []BudgetLine
	Approvals         []Approval
	Coverage          []RouteCoverage
	Gaps              []Gap
	Omitted           []Section
	// Grants are the grants the run's actions decided under, for the
	// budget lines' remaining limit.
	Grants       []ids.UUID
	ScopeLimited bool
}

// InspectRun assembles a run's inspection: every section is read only
// when the viewer holds its own permission where the run's agent lives
// (HR-401), and a run outside the viewer's evidence.read is not found.
func InspectRun(ctx context.Context, tx db.TenantTx, s SectionScope, run ids.UUID, o InspectOptions) (Inspection, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	r, err := q.InvRun(ctx, org, run)
	if db.IsNoRows(err) {
		return Inspection{}, ErrRunNotFound
	} else if err != nil {
		return Inspection{}, err
	}
	if ok, err := s.Visible(ctx, r.AgentID); err != nil {
		return Inspection{}, err
	} else if !ok {
		return Inspection{}, ErrRunNotFound
	}
	out := Inspection{Run: RunSummary{
		Run: r.ID, Agent: r.AgentID, TaskRef: r.TaskRef, Launcher: party(r.LauncherUserID, r.LauncherSaID, r.LauncherInstanceID),
		Principal: party(r.PrincipalUserID, r.PrincipalSaID, nil), Grant: r.GrantID, State: r.State, Start: r.CreatedAt,
		End: r.EndedAt, EndReason: str(r.EndReason), Parent: r.ParentRunID, Depth: int(r.Depth),
	}, ScopeLimited: s.Limited()}

	asked := o.Sections
	if len(asked) == 0 {
		asked = AllSections
	}
	read := map[Section]bool{}
	for _, sec := range AllSections {
		if !slices.Contains(asked, sec) {
			continue
		}
		ok, err := s.Readable(ctx, sec, r.AgentID)
		if err != nil {
			return Inspection{}, err
		}
		if !ok {
			out.Omitted = append(out.Omitted, sec)
			continue
		}
		read[sec] = true
	}

	if read[SectionTimeline] || read[SectionGaps] {
		tl, err := RunTimeline(ctx, tx, s, run, o.WithPhases)
		if err != nil {
			return Inspection{}, err
		}
		if read[SectionTimeline] {
			if err := page(&out, tl, run, o); err != nil {
				return Inspection{}, err
			}
		}
		if read[SectionGaps] {
			more, err := RunEvidenceGaps(ctx, tx, run)
			if err != nil {
				return Inspection{}, err
			}
			out.Gaps = append(slices.Clone(tl.Gaps), more...)
			slices.SortStableFunc(out.Gaps, func(a, b Gap) int { return a.At.Compare(b.At) })
		}
	}
	if read[SectionLineage] {
		if out.Lineage, err = lineage(ctx, q, org, s, r); err != nil {
			return Inspection{}, err
		}
	}
	if read[SectionBudget] {
		if out.Budget, err = budget(ctx, q, org, run); err != nil {
			return Inspection{}, err
		}
		if out.Grants, err = q.InvRunGrants(ctx, org, run); err != nil {
			return Inspection{}, err
		}
	}
	if read[SectionApprovals] {
		aps, err := q.InvApprovals(ctx, dbq.InvApprovalsParams{OrgID: org, RunID: &run, MaxRows: MaxApprovals})
		if err != nil {
			return Inspection{}, err
		}
		for _, a := range aps {
			out.Approvals = append(out.Approvals, approval(a))
		}
	}
	if read[SectionCoverage] {
		rows, err := q.InvRunCoverage(ctx, org, run)
		if err != nil {
			return Inspection{}, err
		}
		for _, c := range rows {
			out.Coverage = append(out.Coverage, RouteCoverage{
				Connection: c.ConnectionID, Operation: c.Operation, Snapshot: c.SnapshotID, State: c.State,
				Reasons: c.Reasons, Computed: c.ComputedAt, StaleAtDecision: c.StaleAtDecision,
			})
		}
	}
	return out, nil
}

// page cuts one page of the timeline's events.
func page(out *Inspection, tl Timeline, run ids.UUID, o InspectOptions) error {
	size := o.PageSize
	if size <= 0 {
		size = DefaultTimelinePage
	}
	size = min(size, MaxTimelinePage)
	from := 0
	if o.PageToken != "" {
		var err error
		if from, err = pageOffset(o.PageToken, run); err != nil {
			return err
		}
	}
	from = min(from, len(tl.Events))
	to := min(from+size, len(tl.Events))
	out.HasTimeline, out.Events, out.Phases, out.TimelineTruncated = true, tl.Events[from:to], tl.Phases, tl.Truncated
	if to < len(tl.Events) {
		out.NextPageToken = pageToken(run, to)
	}
	return nil
}

// pageToken is an opaque timeline position: the run and the next event's
// index in the time-ordered events.
func pageToken(run ids.UUID, offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(run.String() + ":" + strconv.Itoa(offset)))
}

func pageOffset(tok string, run ids.UUID) (int, error) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return 0, ErrBadPageToken
	}
	r, n, ok := strings.Cut(string(b), ":")
	if !ok || r != run.String() {
		return 0, ErrBadPageToken
	}
	off, err := strconv.Atoi(n)
	if err != nil || off < 0 {
		return 0, ErrBadPageToken
	}
	return off, nil
}

func lineage(ctx context.Context, q *dbq.Queries, org ids.OrgID, s Scope, r dbq.InvRunRow) (*Lineage, error) {
	l := &Lineage{}
	var err error
	if l.Parents, err = delegation(ctx, q, org, s, r.ID); err != nil {
		return nil, err
	}
	run := r.ID
	kids, err := q.InvRunChildren(ctx, org, &run, MaxChildren+1)
	if err != nil {
		return nil, err
	}
	if len(kids) > MaxChildren {
		kids, l.ChildrenTruncated = kids[:MaxChildren], true
	}
	for _, k := range kids {
		ok, err := s.Visible(ctx, k.AgentID)
		if err != nil {
			return nil, err
		}
		if ok {
			l.Children = append(l.Children, Lane{Run: k.ID, Agent: k.AgentID, State: k.State, Created: k.CreatedAt, Ended: k.EndedAt})
		}
	}
	up, err := q.InvRunUpstreamExecution(ctx, org, run)
	switch {
	case err == nil:
		l.Upstream = &ExecutionLink{
			Execution: up.ID, Automation: up.AutomationID, Mode: up.Mode, State: up.State, TriggerKind: up.TriggerKind,
			Created: up.CreatedAt, Ended: up.EndedAt,
		}
	case !db.IsNoRows(err):
		return nil, err
	}
	down, err := q.InvRunDownstreamExecutions(ctx, dbq.InvRunDownstreamExecutionsParams{
		OrgID: org, Since: r.CreatedAt, RunID: run, MaxRows: MaxDownstream + 1,
	})
	if err != nil {
		return nil, err
	}
	if len(down) > MaxDownstream {
		down, l.DownstreamTruncated = down[:MaxDownstream], true
	}
	for _, e := range down {
		l.Downstream = append(l.Downstream, ExecutionLink{
			Execution: e.ID, Automation: e.AutomationID, Mode: e.Mode, State: e.State, TriggerKind: e.TriggerKind,
			Created: e.CreatedAt, Ended: e.EndedAt,
		})
	}
	return l, nil
}

func budget(ctx context.Context, q *dbq.Queries, org ids.OrgID, run ids.UUID) ([]BudgetLine, error) {
	rows, err := q.InvRunBudget(ctx, org, run)
	if err != nil {
		return nil, err
	}
	out := make([]BudgetLine, 0, len(rows))
	for _, b := range rows {
		l := BudgetLine{Account: b.LineID, IsAccount: b.Account, Rule: b.Rule, Currency: b.Currency, Count: b.Reservations}
		if b.Account {
			l.Held, l.Committed, l.Released = b.Held.String(), b.Committed.String(), b.Released.String()
		} else {
			l.Held, l.Committed, l.Released = strconv.FormatInt(b.HeldCount, 10), strconv.FormatInt(b.CommittedCount, 10),
				strconv.FormatInt(b.ReleasedCount, 10)
		}
		out = append(out, l)
	}
	return out, nil
}

// RunEvidenceGaps returns the coverage and telemetry gaps of a run (F229):
// NO_COVERAGE_CLAIM, COVERAGE_BELOW_ENFORCED and TELEMETRY_GAP, oldest
// first. It reads without a viewer scope: the caller has already checked
// the run's agent (an inspection, or a run-scoped evidence pack).
func RunEvidenceGaps(ctx context.Context, tx db.TenantTx, run ids.UUID) ([]Gap, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	r, err := q.InvRun(ctx, org, run)
	if err != nil {
		return nil, err
	}
	var out []Gap
	cov, err := q.InvRunCoverageGaps(ctx, org, run, MaxTimelineActions)
	if err != nil {
		return nil, err
	}
	for _, c := range cov {
		kind := GapCoverageBelowEnforced
		if c.NoClaim {
			kind = GapNoCoverageClaim
		}
		out = append(out, Gap{Kind: kind, Transaction: c.ID, At: c.CreatedAt, Connection: c.ConnectionID, Operation: c.Operation})
	}
	end, err := q.OpsDBNow(ctx)
	if err != nil {
		return nil, err
	}
	if r.EndedAt != nil {
		end = *r.EndedAt
	} else if r.ExpiresAt.Before(end) {
		end = r.ExpiresAt
	}
	tel, err := telemetryGaps(ctx, q, org, run, r.CreatedAt, end)
	if err != nil {
		return nil, err
	}
	out = append(out, tel...)
	slices.SortStableFunc(out, func(a, b Gap) int { return a.At.Compare(b.At) })
	return out, nil
}

// telemetryGaps finds, for each gateway the run's actions went through,
// every stretch inside [start, end] longer than HeartbeatWindow in which
// the gateway neither decided one of the run's actions nor renewed its
// certificate. A gateway's creation counts as a sighting. A run lives at
// most a day, so the stretch usually began before the run: the gateway was
// already unseen when the run started or continued.
func telemetryGaps(ctx context.Context, q *dbq.Queries, org ids.OrgID, run ids.UUID, start, end time.Time) ([]Gap, error) {
	decided, err := q.InvRunGatewayDecisions(ctx, org, run, maxGatewaySightings)
	if err != nil || len(decided) == 0 {
		return nil, err
	}
	seen := map[ids.UUID][]time.Time{}
	var gateways []ids.UUID
	for _, d := range decided {
		if _, ok := seen[d.GatewayID]; !ok {
			gateways = append(gateways, d.GatewayID)
			seen[d.GatewayID] = []time.Time{d.GatewayCreatedAt}
		}
		seen[d.GatewayID] = append(seen[d.GatewayID], d.CreatedAt)
	}
	renewals, err := q.InvGatewayRenewals(ctx, dbq.InvGatewayRenewalsParams{
		OrgID: org, GatewayIds: gateways, StartTime: start.Add(-HeartbeatWindow), EndTime: end,
	})
	if err != nil {
		return nil, err
	}
	for _, c := range renewals {
		seen[c.GatewayID] = append(seen[c.GatewayID], c.IssuedAt)
	}
	var out []Gap
	for _, g := range gateways {
		out = append(out, silences(g, seen[g], start, end)...)
	}
	return out, nil
}

// silences returns a TELEMETRY_GAP at the start of each stretch inside
// [start, end] longer than HeartbeatWindow without a sighting.
func silences(gateway ids.UUID, sightings []time.Time, start, end time.Time) []Gap {
	slices.SortFunc(sightings, func(a, b time.Time) int { return a.Compare(b) })
	var out []Gap
	gap := func(last time.Time) {
		g := gateway
		out = append(out, Gap{Kind: GapTelemetry, Gateway: &g, At: maxTime(last.Add(HeartbeatWindow), start)})
	}
	// Before the first sighting the gateway did not exist yet, so the
	// stretch starts at the first sighting at or before start, or at the
	// first one after it.
	var last *time.Time
	for i := range sightings {
		t := sightings[i]
		if t.After(end) {
			break
		}
		if last != nil && t.Sub(*last) > HeartbeatWindow && t.After(start) {
			gap(*last)
		}
		last = &t
	}
	if last != nil && end.Sub(*last) > HeartbeatWindow {
		gap(*last)
	}
	return out
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
