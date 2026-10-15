// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import (
	"cmp"
	"context"
	"slices"
	"time"

	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ItemKind is what a work-queue item is about (F211).
type ItemKind string

// Item kinds, in the order they rank at equal severity.
const (
	KindIncident           ItemKind = "INCIDENT"
	KindAlert              ItemKind = "ALERT"
	KindProtectionFailure  ItemKind = "PROTECTION_FAILURE"
	KindWaitingDecision    ItemKind = "WAITING_DECISION"
	KindAuthorityExpansion ItemKind = "AUTHORITY_EXPANSION"
)

var kindOrder = map[ItemKind]int{
	KindIncident: 5, KindAlert: 4, KindProtectionFailure: 3, KindWaitingDecision: 2, KindAuthorityExpansion: 1,
}

var severityOrder = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

// Action is a scoped action the viewer may take on an item: its name, the
// permission it needs and the object it acts on ("<kind>:<id>"). Only
// actions the viewer holds the permission for at the item are listed.
type Action struct {
	Name       string
	Permission td.Permission
	Target     string
}

// Item is one work-queue item.
type Item struct {
	Kind     ItemKind
	ID       string
	Title    string
	Severity string
	State    string
	Since    time.Time
	Deadline *time.Time
	Agents   []string
	Actions  []Action
	Test     bool
}

// Queue is the ranked work queue.
type Queue struct {
	Items []Item
	AsOf  time.Time
	// Whole reports that the viewer reads across the whole organization;
	// otherwise items about agents outside its scope are left out.
	Whole bool
	// Truncated reports that a source held more rows than were read.
	Truncated bool
	// Pending lists queue sources this server does not report yet.
	Pending []string
}

// Queue limits.
const (
	maxRows          = 1000
	maxQueue         = 200
	decisionHorizon  = time.Hour
	expansionHorizon = 24 * time.Hour
)

// pendingSources are queue sources whose streams have not landed.
var pendingSources = []string{"unconfirmed containment", "export delivery failing", "posture findings"}

// GetWorkQueue returns the viewer's ranked work queue (F211): active
// incidents, open alerts, protection failures, waiting decisions near their
// deadline and authority expansion of the last day, highest severity
// first.
func (s *Service) GetWorkQueue(ctx context.Context) (Queue, error) {
	var out Queue
	err := s.read(ctx, func(ctx context.Context, v *viewer) error {
		var err error
		out, err = workQueue(ctx, v)
		return err
	})
	return out, err
}

// actions keeps the candidate actions the viewer may take on a row about
// agents.
func (v *viewer) actions(ctx context.Context, agents []string, cands ...Action) ([]Action, error) {
	var out []Action
	for _, a := range cands {
		if !a.Permission.Known() || !v.c.CanAnywhere(a.Permission) {
			continue
		}
		ok, err := v.covers(ctx, a.Permission, agents)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func workQueue(ctx context.Context, v *viewer) (Queue, error) {
	now, err := v.q.OpsDBNow(ctx)
	if err != nil {
		return Queue{}, err
	}
	now = now.UTC()
	out := Queue{AsOf: now, Whole: v.whole(td.PermOperationsRead), Pending: pendingSources}
	push := func(it Item, perm td.Permission) error {
		ok, err := v.covers(ctx, perm, it.Agents)
		if ok {
			out.Items = append(out.Items, it)
		}
		return err
	}
	if err := incidentItems(ctx, v, &out, push); err != nil {
		return Queue{}, err
	}
	if err := failureItems(ctx, v, now, &out, push); err != nil {
		return Queue{}, err
	}
	if err := decisionItems(ctx, v, now, &out, push); err != nil {
		return Queue{}, err
	}
	if err := expansionItems(ctx, v, now, &out, push); err != nil {
		return Queue{}, err
	}
	if out.Whole {
		es, err := evidenceStatus(ctx, v)
		if err != nil {
			return Queue{}, err
		}
		for _, src := range es.Sources {
			if src.Gap() && src.Kind != SourceSDK && src.Kind != SourceHook && src.Kind != SourceSandbox {
				since := now
				if src.LastSeen != nil {
					since = *src.LastSeen
				}
				out.Items = append(out.Items, Item{
					Kind: KindProtectionFailure, ID: src.Kind + ":" + src.ID, Title: gapTitle(src), Severity: "HIGH",
					State: string(src.Freshness), Since: since,
				})
			}
		}
	}
	slices.SortStableFunc(out.Items, func(a, b Item) int {
		return cmp.Or(
			cmp.Compare(severityOrder[b.Severity], severityOrder[a.Severity]),
			cmp.Compare(kindOrder[b.Kind], kindOrder[a.Kind]),
			b.Since.Compare(a.Since),
		)
	})
	if len(out.Items) > maxQueue {
		out.Items, out.Truncated = out.Items[:maxQueue], true
	}
	return out, nil
}

func gapTitle(s SourceStatus) string {
	name := s.Name
	if name == "" {
		name = s.Kind
	}
	if s.LastSeen == nil {
		return name + " never seen"
	}
	return name + " not seen since " + s.LastSeen.Format(time.RFC3339)
}

type pushFn func(Item, td.Permission) error

func incidentItems(ctx context.Context, v *viewer, out *Queue, push pushFn) error {
	incs, err := v.q.OpsActiveIncidents(ctx, v.c.Org)
	if err != nil {
		return err
	}
	out.Truncated = out.Truncated || len(incs) >= maxRows
	for _, r := range incs {
		target := "incident:" + r.ID.String()
		acts, err := v.actions(ctx, r.Agents, Action{"assign", td.PermIncidentManage, target},
			Action{"set_state", td.PermIncidentManage, target})
		if err != nil {
			return err
		}
		if err := push(Item{
			Kind: KindIncident, ID: r.ID.String(), Title: r.Title, Severity: r.Severity, State: r.State,
			Since: r.CreatedAt, Agents: r.Agents, Actions: acts, Test: r.Test,
		}, td.PermIncidentRead); err != nil {
			return err
		}
	}
	alerts, err := v.q.OpsOpenAlerts(ctx, v.c.Org)
	if err != nil {
		return err
	}
	out.Truncated = out.Truncated || len(alerts) >= maxRows
	for _, r := range alerts {
		sev := r.Severity
		if r.Attention == "PAGE" {
			sev = "CRITICAL"
		}
		target := "alert:" + r.ID.String()
		cands := []Action{{"promote", td.PermIncidentManage, target}}
		for _, a := range r.Agents {
			cands = append(cands, Action{"suspend_agent", td.PermAgentManage, "agent:" + a})
		}
		acts, err := v.actions(ctx, r.Agents, cands...)
		if err != nil {
			return err
		}
		if err := push(Item{
			Kind: KindAlert, ID: r.ID.String(), Title: r.Title, Severity: sev, State: r.State, Since: r.FirstSeen,
			Agents: r.Agents, Actions: acts, Test: r.Test,
		}, td.PermIncidentRead); err != nil {
			return err
		}
	}
	return nil
}

func failureItems(ctx context.Context, v *viewer, now time.Time, out *Queue, push pushFn) error {
	fs, err := v.q.OpsOpenFailures(ctx, v.c.Org)
	if err != nil {
		return err
	}
	out.Truncated = out.Truncated || len(fs) >= maxRows
	for _, r := range fs {
		sev := "MEDIUM"
		if now.After(r.Deadline) {
			sev = "HIGH"
		}
		target := "failure:" + r.ID.String()
		acts, err := v.actions(ctx, r.Agents, Action{"assign", td.PermIncidentManage, target},
			Action{"resolve", td.PermIncidentManage, target})
		if err != nil {
			return err
		}
		d := r.Deadline.UTC()
		if err := push(Item{
			Kind: KindProtectionFailure, ID: r.ID.String(), Title: r.Summary, Severity: sev, State: r.State,
			Since: r.FirstSeen, Deadline: &d, Agents: r.Agents, Actions: acts,
		}, td.PermIncidentRead); err != nil {
			return err
		}
	}
	return nil
}

func decisionItems(ctx context.Context, v *viewer, now time.Time, out *Queue, push pushFn) error {
	rows, err := v.q.OpsWaitingApprovals(ctx, v.c.Org)
	if err != nil {
		return err
	}
	out.Truncated = out.Truncated || len(rows) >= maxRows
	for _, r := range rows {
		left := r.DeadlineAt.Sub(now)
		if left > decisionHorizon {
			break // soonest deadline first
		}
		sev := "MEDIUM"
		if left <= 15*time.Minute {
			sev = "HIGH"
		}
		agents := []string{r.AgentID.String()}
		acts, err := v.actions(ctx, agents, Action{"open_approval", td.PermApprovalRespond, "approval:" + r.ID.String()})
		if err != nil {
			return err
		}
		d := r.DeadlineAt.UTC()
		if err := push(Item{
			Kind: KindWaitingDecision, ID: r.ID.String(), Title: r.Operation + " waits for a decision", Severity: sev,
			State: r.State, Since: r.CreatedAt, Deadline: &d, Agents: agents, Actions: acts,
		}, td.PermApprovalRead); err != nil {
			return err
		}
	}
	return nil
}

func expansionItems(ctx context.Context, v *viewer, now time.Time, out *Queue, push pushFn) error {
	rows, err := v.q.OpsAuthorityExpansion(ctx, v.c.Org, now.Add(-expansionHorizon))
	if err != nil {
		return err
	}
	out.Truncated = out.Truncated || len(rows) >= maxRows
	for _, r := range rows {
		sev, title := "LOW", "new grant"
		if r.Widens {
			sev, title = "MEDIUM", "grant widened"
		}
		agents := []string{r.AgentID.String()}
		acts, err := v.actions(ctx, agents, Action{"revoke_grant", td.PermGrantRevoke, "grant:" + r.GrantID.String()})
		if err != nil {
			return err
		}
		if err := push(Item{
			Kind: KindAuthorityExpansion, ID: r.ID.String(), Title: title, Severity: sev, State: "ACTIVE",
			Since: r.CreatedAt, Agents: agents, Actions: acts,
		}, td.PermGrantRead); err != nil {
			return err
		}
	}
	return nil
}
