// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"errors"
	"fmt"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// The platform-event consumer (D18, D19, D23, D58): one cursor per org,
// moved by compare-and-set with everything the batch fired, so each feed
// entry is considered once per org.
const (
	// FeedInterval is how often the consumer looks at every org.
	FeedInterval = 5 * time.Second
	// MaxFeedBatches bounds one org's job.
	MaxFeedBatches = 20
	// MaxThresholdGroups bounds an automation's live threshold groups.
	MaxThresholdGroups = 1000
	// ThresholdRetention is how long counts are kept.
	ThresholdRetention = 24 * time.Hour
)

// ErrCursorMoved reports a concurrent consumer; the next job continues.
var ErrCursorMoved = errors.New("triggers: feed cursor moved")

// FeedResult is one batch's outcome.
type FeedResult struct {
	From, To int64
	Events   int
	Fired    int
}

type listener struct {
	a     Automation
	event *autodomain.EventWhen
	thr   *autodomain.ThresholdWhen
}

// ProcessFeed considers the next batch of org's feed against every event
// and threshold trigger.
func (s *Service) ProcessFeed(ctx context.Context, org ids.OrgID) (FeedResult, error) {
	var res FeedResult
	err := s.d.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		res = FeedResult{}
		q := dbq.New(tx)
		head, err := feed.Reader{}.Head(ctx, tx)
		if err != nil {
			return err
		}
		cur, err := q.EnsureAutomationFeedCursor(ctx, org, head)
		if err != nil {
			return err
		}
		events, err := feed.Reader{}.After(ctx, tx, cur, feed.MaxBatch)
		if err != nil || len(events) == 0 {
			return err
		}
		res.From, res.To = cur, events[len(events)-1].Seq
		ls, err := s.listeners(ctx, q, org)
		if err != nil {
			return err
		}
		if len(ls) > 0 {
			now, err := q.DBNow(ctx)
			if err != nil {
				return err
			}
			closing, err := s.closingCases(ctx, q, org, events)
			if err != nil {
				return err
			}
			lins, err := s.lineages(ctx, q, org, events)
			if err != nil {
				return err
			}
			for i, e := range events {
				if e.Test {
					continue
				}
				res.Events++
				n, err := s.consider(ctx, tx, ls, e, Facts{CaseClosed: closing[e.ID]}, lins[i], now)
				if err != nil {
					return err
				}
				res.Fired += n
			}
			if _, err := q.PruneThresholdCounts(ctx, org, now.Add(-ThresholdRetention)); err != nil {
				return err
			}
		}
		n, err := q.AdvanceAutomationFeedCursor(ctx, res.To, org, cur)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrCursorMoved
		}
		return nil
	})
	return res, err
}

func (s *Service) listeners(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]listener, error) {
	var out []listener
	for _, member := range []string{"event", "threshold"} {
		rows, err := q.ActiveAutomationsWithTrigger(ctx, org, member)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			a, err := automationOf(r.ID, r.Name, r.State, r.Rollout, r.ServiceAccountID, r.OwnerUserID, r.VersionID, r.Definition)
			if err != nil {
				s.d.Log.WarnContext(ctx, "automations.feed_definition", "automation", r.ID.String())
				continue
			}
			switch {
			case a.Def.When.Event != nil && KnownEvent(a.Def.When.Event.On):
				out = append(out, listener{a: a, event: a.Def.When.Event})
			case a.Def.When.Threshold != nil && KnownEvent(a.Def.When.Threshold.On):
				out = append(out, listener{a: a, thr: a.Def.When.Threshold})
			}
		}
	}
	return out, nil
}

func (s *Service) closingCases(ctx context.Context, q *dbq.Queries, org ids.OrgID, events []feed.Event) (map[ids.UUID]bool, error) {
	var idsOf []ids.UUID
	for _, e := range events {
		if e.Kind == kindCase {
			idsOf = append(idsOf, e.ID)
		}
	}
	out := map[ids.UUID]bool{}
	if len(idsOf) == 0 {
		return out, nil
	}
	rows, err := q.CaseStatesOfLedgerEntries(ctx, org, idsOf)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.LedgerEntryID] = true
	}
	return out, nil
}

// lineages finds, per event, the lineage it inherits (D23): an event an
// automation's identity recorded (its execution from the audit details),
// or one about a run or grant of an automation execution, descends from
// that execution's trigger.
func (s *Service) lineages(ctx context.Context, q *dbq.Queries, org ids.OrgID, events []feed.Event) ([]Lineage, error) {
	var sas, runs, grants []ids.UUID
	for _, e := range events {
		if e.ActorType == "service_account" {
			if id, err := ids.ParseUUID(e.ActorID); err == nil {
				sas = append(sas, id)
			}
		}
		if v, ok := e.Subject(reflexdomain.SubjectRun); ok {
			if id, err := ids.ParseUUID(v); err == nil {
				runs = append(runs, id)
			}
		}
		if v, ok := e.Subject(reflexdomain.SubjectGrant); ok {
			if id, err := ids.ParseUUID(v); err == nil {
				grants = append(grants, id)
			}
		}
	}
	saAuto := map[ids.UUID]ids.UUID{}
	if len(sas) > 0 {
		rows, err := q.ServiceAccountAutomations(ctx, org, sas)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			saAuto[r.ID] = r.AutomationID
		}
	}
	runExec := map[string]ids.UUID{}
	if len(runs) > 0 {
		rows, err := q.RunsAutomationExecution(ctx, org, runs)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			runExec[r.ID.String()] = r.ExecutionID
		}
	}
	grantExec := map[string]ids.UUID{}
	if len(grants) > 0 {
		rows, err := q.GrantsAutomationExecution(ctx, org, grants)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			grantExec[r.ID.String()] = r.ExecutionID
		}
	}
	execs := map[ids.UUID]Lineage{}
	lineageOf := func(exec ids.UUID) (Lineage, error) {
		if l, ok := execs[exec]; ok {
			return l, nil
		}
		l, err := s.lineageOfExecution(ctx, q, org, &exec)
		if err != nil {
			return Lineage{}, err
		}
		execs[exec] = l
		return l, nil
	}
	out := make([]Lineage, len(events))
	for i, e := range events {
		var cands []Lineage
		if x, err := ids.ParseUUID(e.Attrs["execution"]); err == nil && !x.IsZero() {
			l, err := lineageOf(x)
			if err != nil {
				return nil, err
			}
			cands = append(cands, l)
		}
		for _, x := range []ids.UUID{runExec[subjectOf(e, reflexdomain.SubjectRun)], grantExec[subjectOf(e, reflexdomain.SubjectGrant)]} {
			if x.IsZero() {
				continue
			}
			l, err := lineageOf(x)
			if err != nil {
				return nil, err
			}
			cands = append(cands, l)
		}
		if id, err := ids.ParseUUID(e.ActorID); err == nil && e.ActorType == "service_account" {
			if a, ok := saAuto[id]; ok {
				// Recorded by an automation's identity without an execution
				// we can find: at least that automation is upstream.
				cands = append(cands, Lineage{Root: e.ID, Ancestry: []ids.UUID{a}, Depth: 1})
			}
		}
		out[i] = Union(cands...)
	}
	return out, nil
}

func subjectOf(e feed.Event, t reflexdomain.SubjectType) string {
	v, _ := e.Subject(t)
	return v
}

// consider fires the event and threshold triggers e matches.
func (s *Service) consider(ctx context.Context, tx db.TenantTx, ls []listener, e feed.Event, f Facts, lin Lineage, now time.Time) (int, error) {
	fired := 0
	for _, l := range ls {
		var on, where string
		if l.event != nil {
			on, where = l.event.On, l.event.Where
		} else {
			on, where = l.thr.On, l.thr.Where
		}
		if !Means(on, e, f) {
			continue
		}
		if ok, err := MatchEvent(ctx, where, e); err != nil || !ok {
			continue
		}
		if l.event != nil {
			params, perr := ExtractFields(l.event.Params, func(p string) (string, bool) { return eventField(e, p) })
			out, ok := s.FireInSavepoint(ctx, tx, Candidate{
				Automation: l.a, Kind: autodomain.TriggerEvent, Authenticity: autodomain.AuthPlatformFeed,
				Detail:    map[string]string{"seq": fmt.Sprint(e.Seq), "entry": e.ID.String(), "kind": e.Kind, "event": on},
				SourceRef: "event:" + on + ":" + e.ID.String(), Params: params, ParamErr: perr, Subjects: e.Subjects,
				Evidence: evidenceOf(e), Lineage: lin, BaseKey: eventKeyOf(e), OccurredAt: e.OccurredAt, QueueOK: true,
			})
			if ok && out.State.Started() {
				fired++
			}
			continue
		}
		n, err := s.count(ctx, tx, l, e, lin, now)
		if err != nil {
			return fired, err
		}
		fired += n
	}
	return fired, nil
}

func eventKeyOf(e feed.Event) string { return EventKey(e.ID) }

func evidenceOf(e feed.Event) []reflexdomain.EvidenceRef {
	return []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceLedger, ID: e.ID}}
}

// groupOf is a threshold's group key for e.
func groupOf(by string, e feed.Event) string {
	switch by {
	case "agent":
		return "agent:" + subjectOf(e, reflexdomain.SubjectAgent)
	case "connection":
		return "connection:" + subjectOf(e, reflexdomain.SubjectConnection)
	case "operation":
		return "operation:" + e.Operation
	}
	return "all"
}

// count adds e to its threshold group (never an event the automation's
// own work caused, D58) and fires when the window's sum reaches at_least,
// once per window bucket.
func (s *Service) count(ctx context.Context, tx db.TenantTx, l listener, e feed.Event, lin Lineage, now time.Time) (int, error) {
	if lin.Contains(l.a.ID) {
		return 0, nil
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	over := l.thr.Over.D()
	if over <= 0 || l.thr.AtLeast < 1 {
		return 0, nil
	}
	group := truncate(groupOf(l.thr.GroupBy, e), 300)
	since := now.Add(-over)
	minute := e.OccurredAt.UTC().Truncate(time.Minute)
	if minute.Before(since) {
		return 0, nil
	}
	held, err := q.ThresholdGroupWindow(ctx, dbq.ThresholdGroupWindowParams{OrgID: org, AutomationID: l.a.ID, GroupKey: group, Since: since})
	if err != nil {
		return 0, err
	}
	if held.Total == 0 {
		groups, err := q.CountThresholdGroups(ctx, org, l.a.ID, since)
		if err != nil {
			return 0, err
		}
		if int(groups) >= MaxThresholdGroups {
			return 0, s.failure(ctx, tx, reflexdomain.Failure{
				Org: org, Kind: FailureThresholdOverflow,
				DedupeKey: FailureThresholdOverflow + ":" + l.a.ID.String() + ":" + now.UTC().Format("2006-01-02T15"),
				Summary: fmt.Sprintf("Threshold of automation %s has more than %d groups in its window; new groups are not counted.",
					l.a.Name, MaxThresholdGroups),
				NextStep: "Group by a coarser field, or narrow `where`.",
				Scope:    []reflexdomain.Subject{{Type: reflexdomain.SubjectAutomation, ID: l.a.ID.String()}},
				Owner:    &reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: l.a.Owner.String()},
			})
		}
	}
	var root *ids.UUID
	if lin.Depth > 0 {
		root = &lin.Root
	}
	if err := q.AddThresholdCount(ctx, dbq.AddThresholdCountParams{
		OrgID: org, AutomationID: l.a.ID, GroupKey: group, Minute: minute, Ancestry: nonNilSlice(lin.Ancestry),
		Depth: int32(lin.Depth), RootTriggerID: root, //nolint:gosec // depth is 0..4
	}); err != nil {
		return 0, err
	}
	w, err := q.ThresholdGroupWindow(ctx, dbq.ThresholdGroupWindowParams{OrgID: org, AutomationID: l.a.ID, GroupKey: group, Since: since})
	if err != nil {
		return 0, err
	}
	if int(w.Total) < l.thr.AtLeast {
		return 0, nil
	}
	tl := Lineage{Ancestry: w.Ancestry, Depth: int(w.Depth)}
	if tl.Depth > 0 && !w.RootTriggerID.IsZero() {
		tl.Root = w.RootTriggerID
	} else if tl.Depth > 0 {
		tl.Root = e.ID
	}
	if len(tl.Ancestry) > autodomain.MaxAncestry {
		tl.Ancestry = tl.Ancestry[:autodomain.MaxAncestry+1] // refused as too wide
	}
	bucket := time.Unix(0, 0).Add(now.Sub(time.Unix(0, 0)).Truncate(over)).UTC()
	out, ok := s.FireInSavepoint(ctx, tx, Candidate{
		Automation: l.a, Kind: autodomain.TriggerThreshold, Authenticity: autodomain.AuthPlatformFeed,
		Detail: map[string]string{
			"event": l.thr.On, "group": group, "count": fmt.Sprint(w.Total), "window": over.String(), "entry": e.ID.String(),
		},
		SourceRef: "threshold:" + l.thr.On + ":" + group, Subjects: e.Subjects, Evidence: evidenceOf(e), Lineage: tl,
		BaseKey: ThresholdKey(l.a.ID, group, bucket), OccurredAt: e.OccurredAt, QueueOK: true,
	})
	if ok && out.State.Started() {
		return 1, nil
	}
	return 0, nil
}
