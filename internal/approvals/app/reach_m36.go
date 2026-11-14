// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Approval reach (G0 M36 D1063..D1065): fatigue metrics and flags,
// deputies and read-only approval groups. None of them approves anything,
// changes who is eligible (HR-173) or writes an approval response
// (HR-789): fatigue flags and deputies change only who is routed and told
// first (HR-791, HR-790); an unanswered hold stays held, then expires.

// Errors of approval reach.
var (
	ErrFatigueEdition = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "approval fatigue needs the Team edition or above")
	ErrFatigueWindow  = pcerr.New(pcerr.InvalidArgument, "FATIGUE_WINDOW_INVALID", "the window is 1 hour, 24 hours or 7 days")
	ErrRoutingInvalid = pcerr.New(pcerr.InvalidArgument, "FATIGUE_ROUTING_INVALID", "fatigue routing is route or off")
	ErrDeputyInvalid  = pcerr.New(pcerr.InvalidArgument, "DEPUTY_INVALID",
		"a deputy window ends after it starts, in the future, at most 30 days after it starts, and names someone else")
	ErrDeputyNotMember = pcerr.New(pcerr.FailedPrecondition, "DEPUTY_NOT_ELIGIBLE",
		"the deputy must be an active member who may respond to approvals")
	ErrDeputyOverlap  = pcerr.New(pcerr.AlreadyExists, "DEPUTY_OVERLAP", "this person already has a deputy for part of that time")
	ErrDeputyNotFound = pcerr.New(pcerr.NotFound, "DEPUTY_NOT_FOUND", "deputy window not found")
	ErrGroupBy        = pcerr.New(pcerr.InvalidArgument, "GROUP_BY_INVALID", "group by VARIANT, AGENT, RUN or OPERATION")
)

// Fatigue thresholds (D1063).
const (
	// FlagRateApprovals: approvals in the last hour.
	FlagRateApprovals = 30
	// FlagFastSeconds and FlagFastMinApprovals: a median below FlagFastSeconds
	// over at least FlagFastApprovals approvals in the last hour.
	FlagFastSeconds      = 5
	FlagFastMinApprovals = 10
	// FlagNoDeclineApprovals: approvals in the last 24 hours with no
	// decline.
	FlagNoDeclineApprovals = 50
	// FatigueInterval is how often deciders are checked.
	FatigueInterval = 15 * time.Minute
	// MaxDeputyWindow bounds a deputy window.
	MaxDeputyWindow = 30 * 24 * time.Hour
)

// Fatigue flag reasons.
const (
	FlagApprovalRate  = "APPROVAL_RATE"
	FlagFastApprovals = "FAST_APPROVALS"
	FlagNoDeclines    = "NO_DECLINES"
)

// Fatigue routing settings.
const (
	RoutingRoute = "route"
	RoutingOff   = "off"
)

// FatigueWindows are the windows GetApprovalFatigue measures.
var FatigueWindows = []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

// systemActor is the fatigue job's audit actor.
var systemActor = evdomain.Actor{Type: "system", ID: "approval-fatigue"}

// teamFatigue fails closed without entitlements wired.
func (s *Service) teamFatigue(ctx context.Context) error {
	if s.Ents == nil {
		return ErrFatigueEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.TeamWaitlist() {
		return ErrFatigueEdition
	}
	return nil
}

// FatigueFlag is a flag that has not cleared.
type FatigueFlag struct {
	Reason            string
	Approvals         int
	Flagged, ClearsAt time.Time
}

// DeciderFatigue is one decider's measures over a window.
type DeciderFatigue struct {
	Decider                          ids.UUID
	Approvals, Declines, PeakPerHour int64
	NightApprovals, LongestStreak    int64
	MedianSeconds, ApproveShare      float64
	Flags                            []FatigueFlag
}

// Fatigue is GetApprovalFatigue's answer.
type Fatigue struct {
	Deciders []DeciderFatigue
	Routing  string
	Start    time.Time
}

// share is approved / (approved + declined), 0 without either.
func share(approved, declined int64) float64 {
	if approved+declined == 0 {
		return 0
	}
	return float64(approved) / float64(approved+declined)
}

// routingOf returns the org's fatigue routing (route without a row).
func routingOf(ctx context.Context, q *dbq.Queries, org ids.OrgID) (string, error) {
	r, err := q.GetFatigueRouting(ctx, org)
	if db.IsNoRows(err) {
		return RoutingRoute, nil
	} else if err != nil {
		return "", err
	}
	return r.Routing, nil
}

// GetFatigue reports per decider how they approved over window (1 h, 24 h
// or 7 d), with their flags and the org's routing (D1063, Team, read only).
func (s *Service) GetFatigue(ctx context.Context, window time.Duration, decider *ids.UUID) (Fatigue, error) {
	if !slices.Contains(FatigueWindows, window) {
		return Fatigue{}, ErrFatigueWindow
	}
	if err := s.teamFatigue(ctx); err != nil {
		return Fatigue{}, err
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Fatigue{}, err
	}
	if err := c.Require(td.PermWaitlistRead, td.OrgPath(c.Org)); err != nil {
		return Fatigue{}, err
	}
	out := Fatigue{Start: time.Now().Add(-window)}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ApprovalFatigue(ctx, c.Org, out.Start, decider)
		if err != nil {
			return err
		}
		var users []ids.UUID
		if decider != nil {
			users = []ids.UUID{*decider}
		}
		flags, err := q.ActiveFatigueFlags(ctx, c.Org, decider == nil, users)
		if err != nil {
			return err
		}
		for _, r := range rows {
			d := DeciderFatigue{
				Decider: r.UserID, Approvals: r.Approvals, Declines: r.Declines, PeakPerHour: r.PeakPerHour,
				NightApprovals: r.NightApprovals, LongestStreak: r.LongestStreak, MedianSeconds: r.MedianSeconds,
				ApproveShare: share(r.Approvals, r.Declines),
			}
			for _, f := range flags {
				if f.UserID == r.UserID {
					d.Flags = append(d.Flags, FatigueFlag{Reason: f.Reason, Approvals: int(f.Approvals), Flagged: f.FlaggedAt, ClearsAt: f.ClearsAt})
				}
			}
			out.Deciders = append(out.Deciders, d)
		}
		out.Routing, err = routingOf(ctx, q, c.Org)
		return err
	}, db.ReadOnly())
	return out, err
}

// SetFatigueRouting sets the org's fatigue routing (D1063, Team), audited.
// Neither setting changes who is eligible.
func (s *Service) SetFatigueRouting(ctx context.Context, routing string) (string, error) {
	if routing != RoutingRoute && routing != RoutingOff {
		return "", ErrRoutingInvalid
	}
	if err := s.teamFatigue(ctx); err != nil {
		return "", err
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return "", err
	}
	if err := c.Require(td.PermWaitlistManage, td.OrgPath(c.Org)); err != nil {
		return "", err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := dbq.New(tx).SetFatigueRouting(ctx, c.Org, routing, c.Principal.String()); err != nil {
			return err
		}
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.ApprovalFatigueRoutingSet, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: c.Org.String()}, Details: map[string]string{"routing": routing},
		})
		return err
	})
	return routing, err
}

// fatigueReasons returns the flags an hour's and a day's measures raise,
// with the approvals each measured (D1063).
func fatigueReasons(hour, day *dbq.ApprovalFatigueRow) map[string]int64 {
	out := map[string]int64{}
	if hour != nil {
		if hour.Approvals >= FlagRateApprovals {
			out[FlagApprovalRate] = hour.Approvals
		}
		if hour.TimedApprovals >= FlagFastMinApprovals && hour.MedianSeconds < FlagFastSeconds {
			out[FlagFastApprovals] = hour.TimedApprovals
		}
	}
	if day != nil && day.Approvals >= FlagNoDeclineApprovals && day.Declines == 0 {
		out[FlagNoDeclines] = day.Approvals
	}
	return out
}

// FlagFatigue checks the org's deciders and raises the flags their last
// hour and day call for, each audited (approval.fatigue_flagged), at most
// one live flag per person and reason. Outside the Team edition it does
// nothing. A flag only changes routing order; it never decides.
func (s *Service) FlagFatigue(ctx context.Context, org ids.OrgID) (int, error) {
	if err := s.teamFatigue(ctx); err != nil {
		if errors.Is(err, ErrFatigueEdition) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now := time.Now()
		hours, err := q.ApprovalFatigue(ctx, org, now.Add(-time.Hour), nil)
		if err != nil {
			return err
		}
		days, err := q.ApprovalFatigue(ctx, org, now.Add(-24*time.Hour), nil)
		if err != nil {
			return err
		}
		byUser := map[ids.UUID][2]*dbq.ApprovalFatigueRow{}
		for i := range hours {
			v := byUser[hours[i].UserID]
			v[0] = &hours[i]
			byUser[hours[i].UserID] = v
		}
		for i := range days {
			v := byUser[days[i].UserID]
			v[1] = &days[i]
			byUser[days[i].UserID] = v
		}
		users := make([]ids.UUID, 0, len(byUser))
		for u := range byUser {
			users = append(users, u)
		}
		slices.SortFunc(users, func(a, b ids.UUID) int { return bytes.Compare(a[:], b[:]) })
		for _, u := range users {
			v := byUser[u]
			reasons := fatigueReasons(v[0], v[1])
			for _, reason := range []string{FlagApprovalRate, FlagFastApprovals, FlagNoDeclines} {
				count, ok := reasons[reason]
				if !ok {
					continue
				}
				f, err := q.InsertFatigueFlag(ctx, dbq.InsertFatigueFlagParams{
					OrgID: org, ID: ids.NewV7(), UserID: u, Reason: reason, Approvals: int32(min(count, 1<<30)), //nolint:gosec // bounded
				})
				if db.IsNoRows(err) {
					continue // still flagged for this reason
				} else if err != nil {
					return err
				}
				if _, err := audit.Record(ctx, tx, audit.Event{
					Name: auditkind.ApprovalFatigueFlagged, Actor: systemActor, Outcome: audit.Success, ReasonCode: reason,
					Object: &audit.Object{Type: "user", ID: u.String()},
					Details: map[string]string{
						"user": u.String(), "reason": reason, "approvals": strconv.FormatInt(count, 10),
						"clears_at": f.ClearsAt.UTC().Format(time.RFC3339),
					},
				}); err != nil {
					return err
				}
				n++
			}
		}
		return nil
	})
	return n, err
}

// FatigueOrgArgs asks for one org's deciders to be checked (ids only,
// HR-056).
type FatigueOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (FatigueOrgArgs) Kind() string { return "approvals.fatigue_org" }

// InsertOpts keeps one queued job per org.
func (FatigueOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type fatigueOrgWorker struct {
	river.WorkerDefaults[FatigueOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *fatigueOrgWorker) Work(ctx context.Context, job *river.Job[FatigueOrgArgs]) error {
	n, err := w.svc.FlagFatigue(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "approvals.fatigue_flagged", slog.String("org", job.Args.Org.String()), slog.Int("flags", n))
	}
	return err
}

// FatigueDispatchArgs fans the fatigue check out to every active org.
type FatigueDispatchArgs struct{}

// Kind implements river.JobArgs.
func (FatigueDispatchArgs) Kind() string { return "approvals.fatigue_dispatch" }

type fatigueDispatchWorker struct {
	river.WorkerDefaults[FatigueDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *fatigueDispatchWorker) Work(ctx context.Context, _ *river.Job[FatigueDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("approval fatigue: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: FatigueOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterFatigue adds the fatigue workers to reg.
func RegisterFatigue(reg *jobs.Registry, svc *Service, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[FatigueOrgArgs](reg, &fatigueOrgWorker{svc: svc, log: log}); err != nil {
		return err
	}
	return jobs.Register[FatigueDispatchArgs](reg, &fatigueDispatchWorker{pool: svc.Pool})
}

// FatiguePeriodicJobs schedules the fatigue check every 15 minutes.
func FatiguePeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(FatigueInterval),
			func() (river.JobArgs, *river.InsertOpts) { return FatigueDispatchArgs{}, nil }, nil),
	}
}

// ---- Deputies (D1064, FQ36-3) ----

// Deputy is a deputy window.
type Deputy = dbq.PcApprovalDeputy

// mayRespondSomewhere reports whether the user is ACTIVE and holds a role
// with approval.respond at any scope.
func mayRespondSomewhere(ctx context.Context, q *dbq.Queries, org ids.OrgID, user ids.UUID) (bool, error) {
	u, err := q.GetUser(ctx, org, user)
	if db.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if u.State != "ACTIVE" {
		return false, nil
	}
	bs, err := q.BindingsOfUser(ctx, org, &user)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(bs, func(b dbq.PcRoleBinding) bool {
		r, ok := td.LookupRole(td.RoleName(b.Role))
		return ok && r.Has(td.PermApprovalRespond)
	}), nil
}

// personCaller returns the caller when it is a person.
func personCaller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if c.Principal.Kind != td.KindUser || c.Credential == tenancy.CredAPIKey || c.Credential == tenancy.CredSupportSession {
		return c, ErrHumanSession
	}
	return c, nil
}

// SetDeputy names deputy for person's absence from start (now when zero)
// to end (D1064), audited. A person sets their own; waitlist.manage sets
// one for someone else. The deputy is an ACTIVE member with
// approval.respond and never the person; a person's windows never overlap.
// It changes routing and notices only.
func (s *Service) SetDeputy(ctx context.Context, person *ids.UUID, deputy ids.UUID, start, end time.Time) (Deputy, error) {
	c, err := personCaller(ctx)
	if err != nil {
		return Deputy{}, err
	}
	target := c.Principal.ID
	if person != nil && *person != target {
		if err := c.Require(td.PermWaitlistManage, td.OrgPath(c.Org)); err != nil {
			return Deputy{}, err
		}
		target = *person
	}
	now := time.Now()
	if start.IsZero() {
		start = now
	}
	if deputy == target || !end.After(start) || !end.After(now) || end.Sub(start) > MaxDeputyWindow {
		return Deputy{}, ErrDeputyInvalid
	}
	var out Deputy
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetUser(ctx, c.Org, target); db.IsNoRows(err) {
			return ErrDeputyInvalid
		} else if err != nil {
			return err
		}
		if ok, err := mayRespondSomewhere(ctx, q, c.Org, deputy); err != nil {
			return err
		} else if !ok {
			return ErrDeputyNotMember
		}
		if err := q.LockDeputyPerson(ctx, c.Org.UUID(), target); err != nil {
			return err
		}
		n, err := q.OverlappingDeputies(ctx, dbq.OverlappingDeputiesParams{OrgID: c.Org, PersonID: target, EndsAt: end, StartsAt: start})
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrDeputyOverlap
		}
		out, err = q.InsertApprovalDeputy(ctx, dbq.InsertApprovalDeputyParams{
			OrgID: c.Org, ID: ids.NewV7(), PersonID: target, DeputyID: deputy, StartsAt: start, EndsAt: end,
			CreatedBy: c.Principal.String(),
		})
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.ApprovalDeputySet, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "approval_deputy", ID: out.ID.String()},
			Details: map[string]string{
				"person": target.String(), "deputy": deputy.String(),
				"starts_at": start.UTC().Format(time.RFC3339), "ends_at": end.UTC().Format(time.RFC3339),
			},
		})
		return err
	})
	return out, err
}

// CancelDeputy ends a deputy window at once, audited: the person's own, or
// anyone's with waitlist.manage. Another person's window is not found
// without it.
func (s *Service) CancelDeputy(ctx context.Context, id ids.UUID) (Deputy, error) {
	c, err := personCaller(ctx)
	if err != nil {
		return Deputy{}, err
	}
	var out Deputy
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		d, err := q.GetApprovalDeputy(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrDeputyNotFound
		} else if err != nil {
			return err
		}
		if d.PersonID != c.Principal.ID && !c.Can(td.PermWaitlistManage, td.OrgPath(c.Org)) {
			return ErrDeputyNotFound
		}
		if err := q.LockDeputyPerson(ctx, c.Org.UUID(), d.PersonID); err != nil {
			return err
		}
		by := c.Principal.String()
		out, err = q.CancelApprovalDeputy(ctx, &by, c.Org, id)
		if db.IsNoRows(err) {
			return ErrDeputyNotFound
		} else if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.ApprovalDeputyCancelled, Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "approval_deputy", ID: id.String()},
			Details: map[string]string{"person": d.PersonID.String(), "deputy": d.DeputyID.String()},
		})
		return err
	})
	return out, err
}

// ListDeputies lists the caller's deputy windows, or another person's or
// everyone's (all) with waitlist.manage.
func (s *Service) ListDeputies(ctx context.Context, person *ids.UUID, all, includeEnded bool) ([]Deputy, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	var filter *ids.UUID
	switch {
	case all:
		if err := c.Require(td.PermWaitlistManage, td.OrgPath(c.Org)); err != nil {
			return nil, err
		}
		filter = person
	case person != nil && *person != c.Principal.ID:
		if err := c.Require(td.PermWaitlistManage, td.OrgPath(c.Org)); err != nil {
			return nil, err
		}
		filter = person
	default:
		if c.Principal.Kind != td.KindUser {
			return nil, ErrHumanSession
		}
		me := c.Principal.ID
		filter = &me
	}
	var out []Deputy
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ListApprovalDeputies(ctx, c.Org, filter, includeEnded)
		return err
	}, db.ReadOnly())
	return out, err
}

// ---- Approval groups (D1065) ----

// Grouping keys.
const (
	GroupByVariant   = "VARIANT"
	GroupByAgent     = "AGENT"
	GroupByRun       = "RUN"
	GroupByOperation = "OPERATION"
)

// groupScan bounds the requests ListGroups reads.
const groupScan = 5 * page.Max

// Group is one group of requests the caller may see. BatchEligible says
// whether they could be reviewed as one batch on the approval page; it
// approves nothing (HR-175, HR-176).
type Group struct {
	Key           string
	Count         int
	Requests      []ids.UUID
	BatchEligible bool
}

func groupKey(by string, r Request) string {
	switch by {
	case GroupByVariant:
		return hex.EncodeToString(r.VariantKey)
	case GroupByAgent:
		if r.AgentID != nil {
			return r.AgentID.String()
		}
	case GroupByRun:
		if r.RunID != nil {
			return r.RunID.String()
		}
	case GroupByOperation:
		return r.Operation
	}
	return ""
}

// ListGroups groups the requests the caller may see (List's visibility,
// T-037) by variant, agent, run or operation, largest first. It reads only.
func (s *Service) ListGroups(ctx context.Context, by string, states []apdomain.State) ([]Group, error) {
	if !slices.Contains([]string{GroupByVariant, GroupByAgent, GroupByRun, GroupByOperation}, by) {
		return nil, ErrGroupBy
	}
	var rows []Request
	token := ""
	for len(rows) < groupScan {
		pr, err := page.Parse(page.Max, token)
		if err != nil {
			return nil, err
		}
		p, err := s.List(ctx, pr, ListFilter{States: states})
		if err != nil {
			return nil, err
		}
		rows = append(rows, p.Items...)
		if p.Next == "" {
			break
		}
		token = p.Next
	}
	index := map[string]int{}
	var groups []Group
	members := map[string][]Request{}
	for _, r := range rows {
		k := groupKey(by, r)
		i, ok := index[k]
		if !ok {
			i = len(groups)
			index[k] = i
			groups = append(groups, Group{Key: k})
		}
		g := &groups[i]
		g.Count++
		if len(g.Requests) < apdomain.MaxBatch {
			g.Requests = append(g.Requests, r.ID)
			members[k] = append(members[k], r)
		}
	}
	if err := s.markBatchable(ctx, groups, members); err != nil {
		return nil, err
	}
	slices.SortStableFunc(groups, func(a, b Group) int { return b.Count - a.Count })
	return groups, nil
}

// markBatchable sets BatchEligible on the groups whose requests (all of
// them, at most 25) are held actions of one operation and definition, each
// batchable by its own requirements, reversibility and value (HR-175,
// HR-176, Team edition). It reads only; the approval page checks again.
func (s *Service) markBatchable(ctx context.Context, groups []Group, members map[string][]Request) error {
	if s.Defs == nil {
		return nil
	}
	if err := s.teamWaitlist(ctx); err != nil {
		if errors.Is(err, ErrEditionRequired) {
			return nil
		}
		return err
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		ceilings, err := batchCeilings(ctx, q, c.Org)
		if err != nil {
			return err
		}
		for i := range groups {
			g := &groups[i]
			if g.Count > apdomain.MaxBatch || g.Count < 1 {
				continue
			}
			ok, err := s.groupBatchable(ctx, tx, q, c.Org, members[g.Key], ceilings)
			if err != nil {
				return err
			}
			g.BatchEligible = ok
		}
		return nil
	}, db.ReadOnly())
}

// groupBatchable mirrors batchItem's batchability without locking.
func (s *Service) groupBatchable(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, rs []Request,
	ceilings map[string]string,
) (bool, error) {
	shared := ""
	for _, r := range rs {
		if r.SubjectKind != subjectAction {
			return false, nil
		}
		e, err := pgapprovals.LoadEligibility(ctx, q, org, r.ID, nil)
		if skipRow(err) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		var a actionir.ActionIR
		if json.Unmarshal(r.ActionIr, &a) != nil {
			return false, nil //nolint:nilerr // malformed actions are reviewed alone
		}
		d, _, err := s.Defs.PinnedInTx(ctx, tx, org, a.Definition)
		if err != nil {
			return false, nil //nolint:nilerr // a definition that cannot be read is reviewed alone
		}
		vals, err := d.DecodeParams(a.Params)
		if err != nil {
			return false, nil //nolint:nilerr // parameters that do not decode are reviewed alone
		}
		if ok, _ := apdomain.Batchable(e.Requirements, string(d.Reversibility), singleMoney(vals), ceilings); !ok {
			return false, nil
		}
		key := r.Operation + " " + a.Definition.Digest
		if shared == "" {
			shared = key
		} else if key != shared {
			return false, nil
		}
	}
	return shared != "", nil
}
