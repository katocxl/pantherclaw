// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	notifapp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Notifier enqueues a notification in the caller's transaction
// (notifications/app.Service), so a rolled-back routing sends nothing.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m notifapp.Message) (notifapp.Enqueued, error)
	// FailedSubjects returns the subjects whose notices failed to deliver;
	// only the notifications module reads delivery state (HR-039).
	FailedSubjects(ctx context.Context, tx db.TenantTx, org ids.OrgID, subjectType string, subjects []ids.UUID) ([]ids.UUID, error)
}

// RouteInterval is how often new entries are routed.
const RouteInterval = 15 * time.Second

const (
	// routeBatch caps the entries one run routes per org.
	routeBatch = 100
	// candidateScan caps the people one routing step checks.
	candidateScan = 200
)

// Router routes waitlist entries to their eligible deciders and escalates
// them along the chain of the agent's team or the org (HR-173, decision 8).
// Each step recomputes the eligible deciders, notifies those within its
// scope that were not told yet (personally, at most 50, and the subscribed
// channels when the step says so), reminds or tells the agent's owners when
// the step says so, and records every recipient in waitlist_routes. An
// entry no one may decide is marked NO_ELIGIBLE_DECIDER and the org's
// admins are told once; the entry still ends as its kind says at its
// deadline (F635). No step makes anyone eligible.
type Router struct {
	Pool   *db.Pool
	Notify Notifier
}

// RouteOrg routes the org's new entries, takes the escalation steps that
// are due and marks entries whose notices failed, each entry in its own
// transaction. It returns how many entries it routed or escalated.
func (r *Router) RouteOrg(ctx context.Context, org ids.OrgID) (int, error) {
	var fresh, due []ids.UUID
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if fresh, err = q.UnroutedEntries(ctx, org, routeBatch); err != nil {
			return err
		}
		due, err = q.DueEscalations(ctx, org, routeBatch)
		return err
	}, db.ReadOnly())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range append(fresh, due...) {
		if err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error { return r.step(ctx, tx, org, id) }); err != nil {
			return n, err
		}
		n++
	}
	err = r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error { return r.deliveryHealth(ctx, tx, org) })
	return n, err
}

// step takes an entry's next escalation step: the first one routes it.
func (r *Router) step(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) error {
	q := dbq.New(tx)
	e, err := q.EntryForRouting(ctx, org, id)
	if db.IsNoRows(err) {
		return nil // decided meanwhile
	} else if err != nil {
		return err
	}
	chain, err := chainOf(ctx, q, org, e.TeamID)
	if err != nil {
		return err
	}
	i := int(e.EscalationStep)
	if i >= len(chain) {
		return nil
	}
	s := chain[i]
	ds, err := deciders(ctx, q, org, e)
	if err != nil {
		return err
	}
	told, err := q.EntryRecipients(ctx, org, id)
	if err != nil {
		return err
	}
	base, fam, err := notice(ctx, q, org, e)
	if err != nil {
		return err
	}
	stepNo := int16(i) //nolint:gosec // < MaxSteps
	health := wdomain.HealthOK
	reached := wdomain.Reach(s, ds)
	if len(ds) == 0 {
		health = wdomain.HealthNoDecider
		if err := r.unroutable(ctx, tx, q, org, e, base, fam, stepNo); err != nil {
			return err
		}
	}
	// The deciders this step reaches for the first time.
	var fresh []ids.UUID
	for _, c := range reached {
		if !slices.Contains(told, c.User) {
			fresh = append(fresh, c.User)
		}
	}
	if len(fresh) > 0 || (s.NotifyChannels && len(ds) > 0) {
		m := base
		m.Personal, m.PersonalOnly = fresh, !s.NotifyChannels
		m.DedupeKey = "route:" + id.String() + ":" + strconv.Itoa(i)
		if i > 0 {
			m.Type = fam.escalated
		}
		if err := r.send(ctx, tx, q, org, id, stepNo, "decider", m); err != nil {
			return err
		}
	}
	if s.Remind {
		var again []ids.UUID
		for _, c := range ds { // only people who are still eligible
			if slices.Contains(told, c.User) {
				again = append(again, c.User)
			}
		}
		if len(again) > 0 {
			m := base
			m.Personal, m.PersonalOnly, m.DedupeKey = again, true, "remind:"+id.String()+":"+strconv.Itoa(i)
			m.Type = fam.reminder
			if err := r.send(ctx, tx, q, org, id, stepNo, "decider", m); err != nil {
				return err
			}
		}
	}
	if s.NotifyOwners && e.AgentID != nil {
		if err := r.owners(ctx, tx, q, org, e, base, fam, stepNo, told, ds); err != nil {
			return err
		}
	}
	if i == 0 && e.Kind == wdomain.KindActionHold {
		if err := r.variants(ctx, tx, q, org, e); err != nil {
			return err
		}
	}
	var next *time.Time
	if t := wdomain.StepAt(chain, i+1, e.CreatedAt, e.DeadlineAt); !t.IsZero() && t.Before(e.DeadlineAt) {
		next = &t
	}
	if _, err := q.SetEntryRouting(ctx, dbq.SetEntryRoutingParams{Health: health, Step: stepNo + 1, NextStepAt: next, OrgID: org, ID: id}); err != nil {
		return err
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: routedEvent(i), Actor: pgwaitlist.System, Outcome: audit.Success, ReasonCode: health,
		Object: &audit.Object{Type: "waitlist_entry", ID: id.String()},
		Details: map[string]string{
			"kind": e.Kind, "step": strconv.Itoa(i), "scope": s.Scope, "deciders": strconv.Itoa(len(ds)),
			"notified": strconv.Itoa(len(fresh)),
		},
	})
	return err
}

func routedEvent(step int) string {
	if step == 0 {
		return "waitlist.routed"
	}
	return "waitlist.escalated"
}

// family names the notice types of an entry after its first notice: an
// escalation, a reminder, and "no one can decide it".
type family struct{ escalated, reminder, unroutable string }

var (
	// approvalNotices are a hold's or a restoration's.
	approvalNotices = family{escalated: "approval.escalated", reminder: "approval.reminder", unroutable: "approval.unroutable"}
	// reconciliationNotices are an unknown outcome's, which link to its
	// reconciliation page (G0 M7).
	reconciliationNotices = family{
		escalated: "reconciliation.escalated", reminder: "reconciliation.escalated", unroutable: "reconciliation.escalated",
	}
	// entryNotices are every other kind's.
	entryNotices = family{
		escalated: "waitlist.entry_escalated", reminder: "waitlist.entry_escalated", unroutable: "waitlist.entry_escalated",
	}
)

// unroutable tells the org's admins and Security Admins, once per entry,
// that no one may decide it.
func (r *Router) unroutable(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow,
	base notifapp.Message, fam family, step int16,
) error {
	admins, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin), string(td.RoleSecurityAdmin)})
	if err != nil {
		return err
	}
	m := base
	m.Personal, m.DedupeKey, m.Type = admins, "unroutable:"+e.ID.String(), fam.unroutable
	return r.send(ctx, tx, q, org, e.ID, step, "admin", m)
}

// owners tells the agent's owner and backup owner (decision 8). They get
// no vote unless they are eligible; an eligible one is recorded as a
// decider.
func (r *Router) owners(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow,
	base notifapp.Message, fam family, step int16, told []ids.UUID, ds []wdomain.Candidate,
) error {
	a, err := q.GetAgent(ctx, org, *e.AgentID)
	if err != nil {
		return err
	}
	var owners []ids.UUID
	for _, o := range []*ids.UUID{a.OwnerUserID, a.BackupOwnerUserID} {
		if o != nil && !slices.Contains(told, *o) && !slices.Contains(owners, *o) {
			owners = append(owners, *o)
		}
	}
	if len(owners) == 0 {
		return nil
	}
	m := base
	m.Personal, m.PersonalOnly, m.Type = owners, true, fam.escalated
	m.DedupeKey = "owners:" + e.ID.String() + ":" + strconv.Itoa(int(step))
	kind := "owner"
	if slices.ContainsFunc(ds, func(c wdomain.Candidate) bool { return slices.Contains(owners, c.User) }) {
		kind = "decider"
	}
	return r.send(ctx, tx, q, org, e.ID, step, kind, m)
}

// variants tells the Security Admins, once per request, when a hold is at
// least the third variant of one grant, operation and target within 24
// hours (HR-037, decision 7); the detection rule is M10.
func (r *Router) variants(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow) error {
	req, err := q.GetApprovalRequest(ctx, org, e.SubjectID)
	if err != nil || len(req.VariantKey) == 0 {
		return err
	}
	n, err := q.CountRecentVariants(ctx, org, req.VariantKey)
	if err != nil || n < pgapprovals.VariantThreshold {
		return err
	}
	admins, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleSecurityAdmin)})
	if err != nil {
		return err
	}
	_, err = r.Notify.Enqueue(ctx, tx, notifapp.Message{
		Org: org, Type: "security.variant_suspected", Personal: admins, DedupeKey: "variant:" + req.ID.String(),
		Subject: &notifapp.Subject{Type: "approval_request", ID: req.ID},
		Params: map[string]string{
			"operation": req.Operation, "agent": req.AgentID.String(), "count": strconv.Itoa(int(n)), "request": req.ID.String(),
		},
	})
	return err
}

// send enqueues m and records its recipients.
func (r *Router) send(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, entry ids.UUID, step int16, kind string, m notifapp.Message) error {
	enq, err := r.Notify.Enqueue(ctx, tx, m)
	if err != nil || enq.Duplicate {
		return err
	}
	return recordRoutes(ctx, q, org, entry, step, kind, m.Personal, enq.Channels)
}

// deliveryHealth marks routed open entries whose notices failed to deliver
// DELIVERY_FAILING, audited. Only the notifications module reads delivery
// state, and a failed delivery never counts as a decision (HR-039).
func (r *Router) deliveryHealth(ctx context.Context, tx db.TenantTx, org ids.OrgID) error {
	q := dbq.New(tx)
	open, err := q.HealthyRoutedEntries(ctx, org)
	if err != nil {
		return err
	}
	failed, err := r.Notify.FailedSubjects(ctx, tx, org, "waitlist_entry", open)
	if err != nil || len(failed) == 0 {
		return err
	}
	failing, err := q.MarkDeliveryFailing(ctx, org, failed)
	for _, id := range failing {
		if err != nil {
			break
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "waitlist.delivery_failing", Actor: pgwaitlist.System, Outcome: audit.Failure, ReasonCode: wdomain.HealthDeliveryFailing,
			Object: &audit.Object{Type: "waitlist_entry", ID: id.String()},
		})
	}
	return err
}

// chainOf returns the chain in effect for a team: the team's latest
// revision, else the org's, else decision 8's default.
func chainOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, team *ids.UUID) ([]wdomain.Step, error) {
	if team != nil {
		if c, err := storedChain(ctx, q, org, team); err != nil || c != nil {
			return c.steps(), err
		}
	}
	c, err := storedChain(ctx, q, org, nil)
	if err != nil || c != nil {
		return c.steps(), err
	}
	return wdomain.DefaultChain, nil
}

// Chain is an escalation chain: a team's, the org's (Team zero), or the
// built-in default (Revision 0).
type Chain struct {
	Team      ids.UUID
	Revision  int
	Steps     []wdomain.Step
	CreatedBy string
	CreatedAt time.Time
}

func (c *Chain) steps() []wdomain.Step {
	if c == nil {
		return nil
	}
	return c.Steps
}

// storedChain returns the latest revision of the team's (or, for nil, the
// org's) chain, or nil when none is set.
func storedChain(ctx context.Context, q *dbq.Queries, org ids.OrgID, team *ids.UUID) (*Chain, error) {
	row, err := q.CurrentChain(ctx, org, team)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	c := &Chain{Revision: int(row.Revision), CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt}
	if team != nil {
		c.Team = *team
	}
	return c, json.Unmarshal(row.Steps, &c.Steps)
}

// notice is an entry's notice, with the family of its later notices:
// approval.requested for a hold or a restoration (ids, the operation and
// the deadline only); reconciliation.waiting for an unknown outcome, linked
// to its reconciliation page (G0 M7); else waitlist.entry_created.
func notice(ctx context.Context, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow) (notifapp.Message, family, error) {
	m := notifapp.Message{Org: org, Subject: &notifapp.Subject{Type: "waitlist_entry", ID: e.ID}}
	deadline := e.DeadlineAt.UTC().Format(time.RFC3339)
	switch e.Kind {
	case wdomain.KindActionHold, wdomain.KindRestoration:
		req, err := q.GetApprovalRequest(ctx, org, e.SubjectID)
		if err != nil {
			return m, approvalNotices, err
		}
		m.Type, m.Params = "approval.requested", map[string]string{
			"operation": req.Operation, "agent": req.AgentID.String(), "deadline": deadline, "request": req.ID.String(),
		}
		return m, approvalNotices, nil
	case wdomain.KindReconciliation:
		k, err := q.ReconciliationOfTransaction(ctx, org, e.SubjectID)
		switch {
		case db.IsNoRows(err): // an entry without its task: the generic notice
		case err != nil:
			return m, reconciliationNotices, err
		default:
			t, err := q.TransactionOfRun(ctx, org, e.SubjectID)
			if err != nil {
				return m, reconciliationNotices, err
			}
			m.Type, m.Params = "reconciliation.waiting", map[string]string{
				"operation": t.Operation, "agent": t.AgentID.String(), "reconciliation": k.String(),
			}
			return m, reconciliationNotices, nil
		}
	}
	m.Type, m.Params = "waitlist.entry_created", map[string]string{"kind": e.Kind, "deadline": deadline}
	return m, entryNotices, nil
}

func recordRoutes(ctx context.Context, q *dbq.Queries, org ids.OrgID, entry ids.UUID, step int16, kind string, users, channels []ids.UUID) error {
	for _, u := range users {
		if err := q.InsertWaitlistRoute(ctx, dbq.InsertWaitlistRouteParams{
			OrgID: org, ID: ids.NewV7(), EntryID: entry, Step: step, Kind: kind, UserID: &u,
		}); err != nil {
			return err
		}
	}
	for _, c := range channels {
		if err := q.InsertWaitlistRoute(ctx, dbq.InsertWaitlistRouteParams{
			OrgID: org, ID: ids.NewV7(), EntryID: entry, Step: step, Kind: "channel", ChannelID: &c,
		}); err != nil {
			return err
		}
	}
	return nil
}

// deciders returns an entry's eligible deciders, nearest binding first
// (HR-173): the enabled people holding a deciding role where the agent
// lives, kept only if they may respond now. Holds and restorations follow
// the approval rules (a step-up's named person is always one); the other
// kinds need the kind's permission and exclude the requester.
func deciders(ctx context.Context, q *dbq.Queries, org ids.OrgID, e dbq.EntryForRoutingRow) ([]wdomain.Candidate, error) {
	p := dbq.DeciderCandidatesParams{
		OrgID: org, BusinessUnitID: e.BusinessUnitID, TeamID: e.TeamID, EnvironmentID: e.EnvironmentID, Lim: candidateScan,
	}
	if e.Kind != wdomain.KindActionHold && e.Kind != wdomain.KindRestoration {
		perm, ok := wdomain.DeciderPermission(e.Kind)
		if !ok {
			return nil, nil
		}
		p.Roles = rolesWith(perm)
		cs, err := candidates(ctx, q, p, nil)
		return slices.DeleteFunc(cs, func(c wdomain.Candidate) bool {
			return e.RequestedBy != nil && *e.RequestedBy == td.PrincipalRef{Kind: td.KindUser, ID: c.User}.String()
		}), err
	}
	el, err := pgapprovals.LoadEligibility(ctx, q, org, e.SubjectID, nil)
	if err != nil {
		return nil, err
	}
	var named []ids.UUID
	for _, r := range el.Requirements {
		switch r.Kind {
		case apdomain.KindApproval:
			p.Roles = append(p.Roles, r.Role)
		case apdomain.KindRestore:
			p.Roles = append(p.Roles, rolesWith(td.PermAgentRestore)...)
		case apdomain.KindStepUp:
			if u, err := apdomain.StepUpUser(r, el.Context.Run); err == nil {
				named = append(named, u)
			}
		}
	}
	cs, err := candidates(ctx, q, p, named)
	if err != nil || len(cs) == 0 {
		return nil, err
	}
	users := make([]ids.UUID, len(cs))
	for i, c := range cs {
		users[i] = c.User
	}
	if el, err = pgapprovals.LoadEligibility(ctx, q, org, e.SubjectID, users); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(cs, func(c wdomain.Candidate) bool {
		return !slices.ContainsFunc(el.Requirements, func(r apdomain.Requirement) bool {
			ok, _ := apdomain.MayRespond(r, el.People[c.User], el.Context)
			return ok
		})
	}), nil
}

// candidates are the people holding p.Roles where the agent lives, and the
// named people at the nearest rank, sorted by rank.
func candidates(ctx context.Context, q *dbq.Queries, p dbq.DeciderCandidatesParams, named []ids.UUID) ([]wdomain.Candidate, error) {
	var out []wdomain.Candidate
	for _, u := range named {
		out = append(out, wdomain.Candidate{User: u, Rank: wdomain.RankNear})
	}
	if len(p.Roles) > 0 {
		rows, err := q.DeciderCandidates(ctx, p)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if !slices.ContainsFunc(out, func(c wdomain.Candidate) bool { return c.User == r.UserID }) {
				out = append(out, wdomain.Candidate{User: r.UserID, Rank: int(r.Rank)})
			}
		}
	}
	slices.SortStableFunc(out, func(a, b wdomain.Candidate) int { return a.Rank - b.Rank })
	return out, nil
}

// rolesWith lists the default roles holding p.
func rolesWith(p td.Permission) []string {
	var out []string
	for _, r := range td.Roles() {
		if r.Has(p) {
			out = append(out, string(r.Name))
		}
	}
	return out
}

// RouteOrgArgs asks for one org's new entries to be routed. Job args carry
// ids only (HR-056).
type RouteOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (RouteOrgArgs) Kind() string { return "waitlist.route_org" }

// InsertOpts keeps one queued job per org.
func (RouteOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type routeOrgWorker struct {
	river.WorkerDefaults[RouteOrgArgs]
	router *Router
	log    *slog.Logger
}

func (w *routeOrgWorker) Work(ctx context.Context, job *river.Job[RouteOrgArgs]) error {
	n, err := w.router.RouteOrg(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "waitlist.routed", slog.String("org", job.Args.Org.String()), slog.Int("entries", n))
	}
	return err
}

// RouteDispatchArgs fans routing out to every active org.
type RouteDispatchArgs struct{}

// Kind implements river.JobArgs.
func (RouteDispatchArgs) Kind() string { return "waitlist.route_dispatch" }

type routeDispatchWorker struct {
	river.WorkerDefaults[RouteDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *routeDispatchWorker) Work(ctx context.Context, _ *river.Job[RouteDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, db.ListActiveOrgs, 10000)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("waitlist routing: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: RouteOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterRouting adds the routing workers to reg.
func RegisterRouting(reg *jobs.Registry, router *Router, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[RouteOrgArgs](reg, &routeOrgWorker{router: router, log: log}); err != nil {
		return err
	}
	return jobs.Register[RouteDispatchArgs](reg, &routeDispatchWorker{pool: router.Pool})
}

// RoutingPeriodicJobs returns the routing schedule.
func RoutingPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(RouteInterval),
			func() (river.JobArgs, *river.InsertOpts) { return RouteDispatchArgs{}, nil }, nil),
	}
}
