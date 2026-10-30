// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package operations

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ItemKind is what a work-queue item is about (F211).
type ItemKind string

// Item kinds, in the order they rank at equal severity.
const (
	KindIncident               ItemKind = "INCIDENT"
	KindAlert                  ItemKind = "ALERT"
	KindProtectionFailure      ItemKind = "PROTECTION_FAILURE"
	KindWaitingDecision        ItemKind = "WAITING_DECISION"
	KindAuthorityExpansion     ItemKind = "AUTHORITY_EXPANSION"
	KindUnconfirmedContainment ItemKind = "UNCONFIRMED_CONTAINMENT"
	KindPostureFinding         ItemKind = "POSTURE_FINDING"
	// KindAutomationException is an open owned failure an automation raised
	// (G0 M11 D38), routed to the automation's owner.
	KindAutomationException ItemKind = "AUTOMATION_EXCEPTION"
	// KindDiscoveryChange is a scan discovery that vanished or changed on an
	// open or claimed agent (PN-001.3, D114, D116), read with agent.read.
	KindDiscoveryChange ItemKind = "DISCOVERY_CHANGE"
)

var kindOrder = map[ItemKind]int{
	KindIncident: 8, KindUnconfirmedContainment: 7, KindAlert: 6, KindProtectionFailure: 5, KindAutomationException: 4,
	KindWaitingDecision: 3, KindPostureFinding: 2, KindAuthorityExpansion: 1, KindDiscoveryChange: 0,
}

// AutomationFailurePrefix starts every owned failure kind an automation
// raises (D38): those queue as automation exceptions, read with
// automation.read or by their owner (D73 A3); the rest are protection
// failures, read with incident.read.
const AutomationFailurePrefix = "automation."

func failureKind(kind string) ItemKind {
	if strings.HasPrefix(kind, AutomationFailurePrefix) {
		return KindAutomationException
	}
	return KindProtectionFailure
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
	// Whole reports that the viewer reads every source across the whole
	// organization; otherwise items about agents outside its scope, or of
	// kinds it may not read, are left out (Pending says which kinds).
	Whole bool
	// Truncated reports that a source held more visible rows than were
	// read, or that the queue held more than it lists.
	Truncated bool
	// Pending lists the sources the queue does not report: not available,
	// outside the viewer's permissions, or truncated.
	Pending []string
	// Counts are the items per kind and Critical the CRITICAL ones, counted
	// before the queue is cut to its length (D69 M4).
	Counts   map[ItemKind]int
	Critical int
}

// Queue limits.
const (
	maxRows          = 1000
	maxQueue         = 200
	decisionHorizon  = time.Hour
	expansionHorizon = 24 * time.Hour
	// discoveryHorizon is how long a discovery change stays queued (D116).
	discoveryHorizon = 7 * 24 * time.Hour
)

// GetWorkQueue returns the viewer's ranked work queue (F211): active
// incidents, open alerts, protection failures, waiting decisions near their
// deadline and authority expansion of the last day, highest severity
// first.
func (s *Service) GetWorkQueue(ctx context.Context) (Queue, error) {
	if _, err := operator(ctx); err != nil {
		return Queue{}, err
	}
	x, err := s.readSources(ctx)
	if err != nil {
		return Queue{}, err
	}
	var out Queue
	err = s.read(ctx, func(ctx context.Context, v *viewer) error {
		var err error
		out, err = workQueue(ctx, v, x)
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

// sqlScope is the viewer's scope for p as the queue queries take it.
func (v *viewer) sqlScope(ctx context.Context, p td.Permission) (bool, []string, error) {
	sc, err := v.scope(ctx, p)
	if err != nil {
		return false, nil, err
	}
	agents := make([]string, 0, len(sc.Agents))
	for _, a := range sc.Agents {
		agents = append(agents, a.String())
	}
	return sc.All, agents, nil
}

// builder collects the queue.
type builder struct {
	v   *viewer
	now time.Time
	out *Queue
}

// readable reports whether the viewer may read a kind anywhere; when not,
// the queue says the kind is outside its permissions (D69 M3).
func (b *builder) readable(kind string, p td.Permission) bool {
	if b.v.c.CanAnywhere(p) {
		return true
	}
	b.out.Pending = append(b.out.Pending, kind+": outside your permissions")
	return false
}

// cut trims a source read with maxRows+1 rows to maxRows and notes the
// truncation, which is among visible rows only (D60).
func cut[T any](b *builder, kind string, rows []T) []T {
	if len(rows) <= maxRows {
		return rows
	}
	b.out.Truncated = true
	b.out.Pending = append(b.out.Pending, kind+": more exist than were read")
	return rows[:maxRows]
}

func workQueue(ctx context.Context, v *viewer, x external) (Queue, error) {
	now, err := v.q.OpsDBNow(ctx)
	if err != nil {
		return Queue{}, err
	}
	now = now.UTC()
	out := Queue{AsOf: now, Pending: x.notes(), Counts: map[ItemKind]int{}}
	b := &builder{v: v, now: now, out: &out}
	// Whole only when the viewer holds every kind's read permission across
	// the org (D69 M3); a source not reported is listed in Pending.
	out.Whole = v.whole(td.PermOperationsRead) && v.whole(td.PermIncidentRead) && v.whole(td.PermApprovalRead) &&
		v.whole(td.PermGrantRead) && v.whole(td.PermContainmentRead) && v.whole(td.PermPostureRead) && v.whole(td.PermAutomationRead) &&
		v.whole(td.PermAgentRead)
	for _, step := range []func(context.Context, *builder) error{
		incidentItems, failureItems, automationItems, decisionItems, expansionItems, discoveryItems,
	} {
		if err := step(ctx, b); err != nil {
			return Queue{}, err
		}
	}
	if err := containmentItems(ctx, b, x); err != nil {
		return Queue{}, err
	}
	if err := findingItems(ctx, b, x); err != nil {
		return Queue{}, err
	}
	if v.whole(td.PermOperationsRead) {
		es, err := evidenceStatus(ctx, v, x)
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
	for _, it := range out.Items {
		out.Counts[it.Kind]++
		if it.Severity == "CRITICAL" {
			out.Critical++
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

func incidentItems(ctx context.Context, b *builder) error {
	v := b.v
	if !b.readable("incidents and alerts", td.PermIncidentRead) {
		return nil
	}
	all, agents, err := v.sqlScope(ctx, td.PermIncidentRead)
	if err != nil {
		return err
	}
	incs, err := v.q.OpsActiveIncidents(ctx, dbq.OpsActiveIncidentsParams{OrgID: v.c.Org, AllAgents: all, Agents: agents, MaxRows: maxRows + 1})
	if err != nil {
		return err
	}
	for _, r := range cut(b, "incidents", incs) {
		target := "incident:" + r.ID.String()
		acts, err := v.actions(ctx, r.Agents, Action{"assign", td.PermIncidentManage, target},
			Action{"set_state", td.PermIncidentManage, target})
		if err != nil {
			return err
		}
		b.out.Items = append(b.out.Items, Item{
			Kind: KindIncident, ID: r.ID.String(), Title: r.Title, Severity: r.Severity, State: r.State,
			Since: r.CreatedAt, Agents: r.Agents, Actions: acts, Test: r.Test,
		})
	}
	alerts, err := v.q.OpsOpenAlerts(ctx, dbq.OpsOpenAlertsParams{OrgID: v.c.Org, AllAgents: all, Agents: agents, MaxRows: maxRows + 1})
	if err != nil {
		return err
	}
	for _, r := range cut(b, "alerts", alerts) {
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
		b.out.Items = append(b.out.Items, Item{
			Kind: KindAlert, ID: r.ID.String(), Title: r.Title, Severity: sev, State: r.State, Since: r.FirstSeen,
			Agents: r.Agents, Actions: acts, Test: r.Test,
		})
	}
	return nil
}

func failureItems(ctx context.Context, b *builder) error {
	v := b.v
	if !b.readable("owned failures", td.PermIncidentRead) {
		return nil
	}
	all, agents, err := v.sqlScope(ctx, td.PermIncidentRead)
	if err != nil {
		return err
	}
	fs, err := v.q.OpsOpenFailures(ctx, dbq.OpsOpenFailuresParams{OrgID: v.c.Org, AllAgents: all, Agents: agents, MaxRows: maxRows + 1})
	if err != nil {
		return err
	}
	for _, r := range cut(b, "owned failures", fs) {
		sev := "MEDIUM"
		if b.now.After(r.Deadline) {
			sev = "HIGH"
		}
		target := "failure:" + r.ID.String()
		acts, err := v.actions(ctx, r.Agents, Action{"assign", td.PermIncidentManage, target},
			Action{"resolve", td.PermIncidentManage, target})
		if err != nil {
			return err
		}
		d := r.Deadline.UTC()
		b.out.Items = append(b.out.Items, Item{
			Kind: KindProtectionFailure, ID: r.ID.String(), Title: r.Summary, Severity: sev, State: r.State,
			Since: r.FirstSeen, Deadline: &d, Agents: r.Agents, Actions: acts,
		})
	}
	return nil
}

// automationItems queues open automation exceptions (D38, D73 A3): every
// one for a caller with automation.read at the org, else the ones routed
// to the caller. Assigning and resolving them stay incident.manage
// actions, offered only to holders.
func automationItems(ctx context.Context, b *builder) error {
	v := b.v
	all := v.c.Can(td.PermAutomationRead, td.OrgPath(v.c.Org))
	if !all {
		b.out.Pending = append(b.out.Pending, "automation exceptions: only those routed to you")
	}
	fs, err := v.q.OpsOpenAutomationFailures(ctx, dbq.OpsOpenAutomationFailuresParams{
		OrgID: v.c.Org, AllOwners: all, OwnerID: v.c.Principal.ID.String(), MaxRows: maxRows + 1,
	})
	if err != nil {
		return err
	}
	for _, r := range cut(b, "automation exceptions", fs) {
		sev := "MEDIUM"
		if b.now.After(r.Deadline) {
			sev = "HIGH"
		}
		target := "failure:" + r.ID.String()
		acts, err := v.actions(ctx, r.Agents, Action{"assign", td.PermIncidentManage, target},
			Action{"resolve", td.PermIncidentManage, target})
		if err != nil {
			return err
		}
		d := r.Deadline.UTC()
		b.out.Items = append(b.out.Items, Item{
			Kind: failureKind(r.Kind), ID: r.ID.String(), Title: r.Summary, Severity: sev, State: r.State,
			Since: r.FirstSeen, Deadline: &d, Agents: r.Agents, Actions: acts,
		})
	}
	return nil
}

func decisionItems(ctx context.Context, b *builder) error {
	v := b.v
	if !b.readable("waiting decisions", td.PermApprovalRead) {
		return nil
	}
	all, agents, err := v.sqlScope(ctx, td.PermApprovalRead)
	if err != nil {
		return err
	}
	rows, err := v.q.OpsWaitingApprovals(ctx, dbq.OpsWaitingApprovalsParams{
		OrgID: v.c.Org, Horizon: b.now.Add(decisionHorizon), AllAgents: all, Agents: agents, MaxRows: maxRows + 1,
	})
	if err != nil {
		return err
	}
	for _, r := range cut(b, "waiting decisions", rows) {
		sev := "MEDIUM"
		if r.DeadlineAt.Sub(b.now) <= 15*time.Minute {
			sev = "HIGH"
		}
		agentIDs := []string{}
		if r.AgentID != nil {
			agentIDs = append(agentIDs, r.AgentID.String())
		}
		// An automation gate is decided by automation.approve holders (D84).
		perm := td.PermApprovalRespond
		if r.SubjectKind == "AUTOMATION_GATE" {
			perm = td.PermAutomationApprove
		}
		acts, err := v.actions(ctx, agentIDs, Action{"open_approval", perm, "approval:" + r.ID.String()})
		if err != nil {
			return err
		}
		d := r.DeadlineAt.UTC()
		b.out.Items = append(b.out.Items, Item{
			Kind: KindWaitingDecision, ID: r.ID.String(), Title: r.Operation + " waits for a decision", Severity: sev,
			State: r.State, Since: r.CreatedAt, Deadline: &d, Agents: agentIDs, Actions: acts,
		})
	}
	return nil
}

func expansionItems(ctx context.Context, b *builder) error {
	v := b.v
	if !b.readable("authority expansion", td.PermGrantRead) {
		return nil
	}
	all, agents, err := v.sqlScope(ctx, td.PermGrantRead)
	if err != nil {
		return err
	}
	rows, err := v.q.OpsAuthorityExpansion(ctx, dbq.OpsAuthorityExpansionParams{
		OrgID: v.c.Org, Since: b.now.Add(-expansionHorizon), AllAgents: all, Agents: agents, MaxRows: maxRows + 1,
	})
	if err != nil {
		return err
	}
	for _, r := range cut(b, "authority expansion", rows) {
		sev, title := "LOW", "new grant"
		if r.Widens {
			sev, title = "MEDIUM", "grant widened"
		}
		agentIDs := []string{r.AgentID.String()}
		acts, err := v.actions(ctx, agentIDs, Action{"revoke_grant", td.PermGrantRevoke, "grant:" + r.GrantID.String()})
		if err != nil {
			return err
		}
		b.out.Items = append(b.out.Items, Item{
			Kind: KindAuthorityExpansion, ID: r.ID.String(), Title: title, Severity: sev, State: "ACTIVE",
			Since: r.CreatedAt, Agents: agentIDs, Actions: acts,
		})
	}
	return nil
}

var containmentSeverity = map[string]string{"FAILED": "CRITICAL", "UNSUPPORTED": "HIGH", "PARTIAL": "HIGH", "REQUESTED": "MEDIUM"}

// containmentItems queues containment not yet confirmed on every material
// path (D22, F211), which the response port read under the caller's
// containment.read at the org.
func containmentItems(ctx context.Context, b *builder, x external) error {
	if x.containmentTruncated {
		b.out.Truncated = true
		b.out.Pending = append(b.out.Pending, "unconfirmed containment: more exist than were read")
	}
	for _, a := range x.containment {
		sev, ok := containmentSeverity[a.Status]
		if !ok {
			continue // confirmed
		}
		var agents []string
		if a.ScopeType == "agent" {
			agents = []string{a.ScopeID}
		}
		target := "response_action:" + a.ID.String()
		acts, err := b.v.actions(ctx, agents, Action{"open_response_action", td.PermContainmentRead, target})
		if err != nil {
			return err
		}
		title := "containment " + a.Status
		if a.Control != "" {
			title = a.Control + " on " + a.ScopeType + " " + a.Status
		}
		b.out.Items = append(b.out.Items, Item{
			Kind: KindUnconfirmedContainment, ID: a.ID.String(), Title: title, Severity: sev, State: a.Status,
			Since: a.Requested, Agents: agents, Actions: acts,
		})
	}
	return nil
}

// findingItems queues open posture findings (D30), which the posture port
// read under the caller's posture.read (only those it may read).
func findingItems(ctx context.Context, b *builder, x external) error {
	for _, f := range x.findings {
		var agents []string
		if f.Agent != nil {
			agents = []string{f.Agent.String()}
		}
		target := "posture_finding:" + f.ID.String()
		acts, err := b.v.actions(ctx, agents, Action{"assign", td.PermPostureManage, target})
		if err != nil {
			return err
		}
		b.out.Items = append(b.out.Items, Item{
			Kind: KindPostureFinding, ID: f.ID.String(), Title: f.Title, Severity: f.Severity, State: f.State,
			Since: f.Since, Agents: agents, Actions: acts,
		})
	}
	return nil
}

// discoveryItems queues continuous discovery's changes (PN-001.3, D114,
// D116): discoveries people were told vanished and not seen since, and the
// material changes on open or claimed discoveries of the last week. Both
// only inform: neither changed the agent (HR-458).
func discoveryItems(ctx context.Context, b *builder) error {
	v := b.v
	if !b.readable("discovery changes", td.PermAgentRead) {
		return nil
	}
	all, agents, err := v.sqlScope(ctx, td.PermAgentRead)
	if err != nil {
		return err
	}
	rows, err := v.q.OpsDiscoveryChanges(ctx, dbq.OpsDiscoveryChangesParams{
		OrgID: v.c.Org, AllAgents: all, Agents: agents, Since: b.now.Add(-discoveryHorizon), MaxRows: maxRows + 1,
	})
	if err != nil {
		return err
	}
	for _, r := range cut(b, "discovery changes", rows) {
		title := "discovery not seen in recent scans"
		if r.Change == "CHANGED" {
			title = "discovery changed what it may do"
		}
		if r.Kind != "" {
			title = r.Kind + " " + title
		}
		since := b.now
		if r.Since != nil {
			since = *r.Since
		}
		b.out.Items = append(b.out.Items, Item{
			Kind: KindDiscoveryChange, ID: r.ID.String(), Title: title, Severity: "MEDIUM", State: r.Change,
			Since: since, Agents: []string{r.AgentID.String()},
		})
	}
	return nil
}
