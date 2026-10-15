// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// Errors of the incident use cases.
var (
	ErrNotFound       = pcerr.New(pcerr.NotFound, "NOT_FOUND", "not found")
	ErrHumanOnly      = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrEdition        = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "this needs a higher edition")
	ErrState          = pcerr.New(pcerr.FailedPrecondition, "INVALID_STATE", "not allowed in the current state")
	ErrAlreadyLinked  = pcerr.New(pcerr.FailedPrecondition, "ALREADY_LINKED", "the alert already belongs to an incident")
	ErrInvalidSubject = pcerr.New(pcerr.InvalidArgument, "INVALID_SUBJECT", "invalid subject")
)

// Incidents serves alerts, incidents, suppressions and owned failures.
type Incidents struct {
	Pool  *db.Pool
	Hooks *Hooks
	Now   func() time.Time
}

func (s *Incidents) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// reader returns the caller; reads need incident.read somewhere, rows are
// filtered by where their agents live (D8).
func reader(ctx context.Context) (tenancy.Caller, error) {
	return tenancy.CallerFrom(ctx)
}

// manager returns a person holding incident.manage at the org.
func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermIncidentManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, nil
}

// visibility decides which rows a caller may read: incident.read at the
// org reads everything; otherwise a row is readable when it names agents
// and the caller holds incident.read where each of them lives (D8). A row
// naming no agent needs the org-level permission.
type visibility struct {
	org   bool
	scope *tapp.AgentScope
}

func newVisibility(c tenancy.Caller, q *dbq.Queries) *visibility {
	return &visibility{
		org: c.Can(td.PermIncidentRead, td.OrgPath(c.Org)), scope: tapp.NewAgentScope(c, q, td.PermIncidentRead),
	}
}

// agentID parses an agent subject's id.
func agentID(s string) (ids.UUID, bool) {
	id, err := ids.ParseUUID(s)
	return id, err == nil
}

func (v *visibility) subjects(ctx context.Context, subs []reflexdomain.Subject) (bool, error) {
	if v.org {
		return true, nil
	}
	agents := 0
	for _, s := range subs {
		if s.Type != reflexdomain.SubjectAgent {
			continue
		}
		id, valid := agentID(s.ID)
		if !valid {
			return false, nil
		}
		ok, err := v.scope.Can(ctx, id)
		if db.IsNoRows(err) {
			return false, nil
		}
		if err != nil || !ok {
			return false, err
		}
		agents++
	}
	return agents > 0, nil
}

func (v *visibility) alert(ctx context.Context, a dbq.PcAlert) (bool, error) {
	subs, err := Subjects(a.Subjects)
	if err != nil {
		return false, err
	}
	return v.subjects(ctx, subs)
}

// Subjects decodes stored subjects.
func Subjects(raw []byte) ([]reflexdomain.Subject, error) {
	var subs []reflexdomain.Subject
	if len(raw) == 0 {
		return nil, nil
	}
	err := json.Unmarshal(raw, &subs)
	return subs, err
}

// requireRead fails unless the caller holds incident.read anywhere it
// could use: at the org, or on some agent (checked per row).
func requireRead(c tenancy.Caller) error {
	if !c.CanAnywhere(td.PermIncidentRead) {
		return pcerr.New(pcerr.PermissionDenied, "PERMISSION_DENIED", "missing permission "+string(td.PermIncidentRead))
	}
	return nil
}

// AlertPage is one page of alerts.
type AlertPage struct {
	Items []dbq.PcAlert
	Next  string
}

// AlertFilter narrows ListAlerts.
type AlertFilter struct {
	States   []string
	Rule     string
	Incident *ids.UUID
}

// ListAlerts lists the alerts the caller may read, newest first; a page
// holds fewer than its size when some are hidden.
func (s *Incidents) ListAlerts(ctx context.Context, f AlertFilter, size int32, token string) (AlertPage, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return AlertPage{}, err
	}
	c, err := reader(ctx)
	if err != nil {
		return AlertPage{}, err
	}
	if err := requireRead(c); err != nil {
		return AlertPage{}, err
	}
	var out AlertPage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		states := f.States
		if states == nil {
			states = []string{}
		}
		// Hidden alerts are filtered in SQL before paging, so neither the page
		// nor its next token reveals them (D60).
		all, visible, err := newVisibility(c, q).scope.Visible(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ListAlerts(ctx, dbq.ListAlertsParams{
			OrgID: c.Org, AllAgents: all, VisibleAgents: nonNil(visible), Before: p.After, States: states, RuleID: f.Rule,
			IncidentID: f.Incident, PageLimit: p.Limit(),
		})
		if err != nil {
			return err
		}
		out.Items, out.Next = page.Finish(p, rows, func(a dbq.PcAlert) ids.UUID { return a.ID })
		return nil
	}, db.ReadOnly())
	return out, err
}

// AlertDetail is one alert with its evidence, events and possibly related
// alerts.
type AlertDetail struct {
	Alert    dbq.PcAlert
	Evidence []dbq.PcAlertEvidence
	Events   []dbq.PcAlertEvent
	Related  []dbq.PcAlert
}

// GetAlert returns one alert the caller may read.
func (s *Incidents) GetAlert(ctx context.Context, id ids.UUID) (AlertDetail, error) {
	c, err := reader(ctx)
	if err != nil {
		return AlertDetail{}, err
	}
	if err := requireRead(c); err != nil {
		return AlertDetail{}, err
	}
	var out AlertDetail
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.GetAlert(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		v := newVisibility(c, q)
		if ok, err := v.alert(ctx, a); err != nil {
			return err
		} else if !ok {
			return ErrNotFound
		}
		out.Alert = a
		if out.Evidence, err = q.AlertEvidence(ctx, c.Org, id); err != nil {
			return err
		}
		if out.Events, err = q.AlertEvents(ctx, c.Org, id); err != nil {
			return err
		}
		all, visible, err := v.scope.Visible(ctx)
		if err != nil {
			return err
		}
		out.Related, err = q.PossibleRelatedAlerts(ctx, dbq.PossibleRelatedAlertsParams{
			OrgID: c.Org, AllAgents: all, VisibleAgents: nonNil(visible), RuleID: a.RuleID, ID: a.ID, DedupeKey: a.DedupeKey,
			Since: s.now().Add(-GroupWindow),
		})
		return err
	}, db.ReadOnly())
	return out, err
}

// alertMoves are the allowed manual alert transitions. A suppressed alert
// only leaves SUPPRESSED through a bypass or by its suppression ending.
var alertMoves = map[string][]string{
	alerts.StateOpen:         {alerts.StateAcknowledged, alerts.StateResolved},
	alerts.StateAcknowledged: {alerts.StateResolved, alerts.StateOpen},
	alerts.StateResolved:     {alerts.StateOpen},
	// A responder may settle a suppressed alert without waiting for the
	// suppression to end (D59 M1).
	alerts.StateSuppressed: {alerts.StateAcknowledged, alerts.StateResolved, alerts.StateOpen},
}

// SetAlertState moves an alert and records a STATE event (HR-243).
func (s *Incidents) SetAlertState(ctx context.Context, id ids.UUID, to, note string) (dbq.PcAlert, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcAlert{}, err
	}
	var out dbq.PcAlert
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.LockAlert(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if !contains(alertMoves[a.State], to) {
			return ErrState
		}
		if a.State == alerts.StateResolved && to == alerts.StateOpen {
			// A resolved alert reopens only while no other open alert holds
			// its dedupe key; it is audited and returned like any move (D59 L7).
			if err := reopenResolved(ctx, q, c, a, note); err != nil {
				return err
			}
		} else {
			if err := one(q.SetAlertState(ctx, dbq.SetAlertStateParams{ToState: to, OrgID: c.Org, ID: id, FromState: a.State})); err != nil {
				return err
			}
			if err := alertEvent(ctx, q, c, id, "STATE", a.State, to, note); err != nil {
				return err
			}
		}
		if err := s.audit(ctx, tx, c, "incident.alert_state_set", "alert", id, map[string]string{"from": a.State, "to": to}); err != nil {
			return err
		}
		out, err = q.GetAlert(ctx, c.Org, id)
		return err
	})
	return out, err
}

func reopenResolved(ctx context.Context, q *dbq.Queries, c tenancy.Caller, a dbq.PcAlert, note string) error {
	n, err := q.SetAlertState(ctx, dbq.SetAlertStateParams{ToState: alerts.StateOpen, OrgID: c.Org, ID: a.ID, FromState: a.State})
	if db.IsUniqueViolation(err) {
		return ErrState
	}
	if err != nil || n != 1 {
		return firstErr(err, ErrState)
	}
	return alertEvent(ctx, q, c, a.ID, "STATE", a.State, alerts.StateOpen, note)
}

func alertEvent(ctx context.Context, q *dbq.Queries, c tenancy.Caller, alert ids.UUID, kind, from, to, note string) error {
	act := c.Actor()
	return q.InsertAlertEvent(ctx, dbq.InsertAlertEventParams{
		OrgID: c.Org, ID: ids.NewV7(), AlertID: alert, Kind: kind, ActorType: act.Type, ActorID: act.ID,
		FromValue: opt(from), ToValue: opt(to), Note: opt(note),
	})
}

func incidentEvent(ctx context.Context, q *dbq.Queries, c tenancy.Caller, incident ids.UUID, kind, from, to, note string,
	alert *ids.UUID,
) error {
	act := c.Actor()
	return q.InsertIncidentEvent(ctx, dbq.InsertIncidentEventParams{
		OrgID: c.Org, ID: ids.NewV7(), IncidentID: incident, Kind: kind, ActorType: act.Type, ActorID: act.ID,
		FromValue: opt(from), ToValue: opt(to), AlertID: alert, Note: opt(note),
	})
}

// PromoteAlert opens an incident from an alert the caller may read.
func (s *Incidents) PromoteAlert(ctx context.Context, id ids.UUID, note string) (dbq.PcIncident, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcIncident{}, err
	}
	var out dbq.PcIncident
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.LockAlert(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if a.IncidentID != nil {
			return ErrAlreadyLinked
		}
		inc, err := q.InsertIncident(ctx, dbq.InsertIncidentParams{
			OrgID: c.Org, ID: ids.NewV7(), Title: a.Title, Severity: a.Severity, GroupKey: a.GroupKey,
			OpenedBy: "user:" + c.Principal.ID.String(), Test: a.Test,
		})
		if err != nil {
			return err
		}
		if err := incidentEvent(ctx, q, c, inc.ID, "OPENED", "", "OPEN", note, &a.ID); err != nil {
			return err
		}
		if err := alertEvent(ctx, q, c, a.ID, "PROMOTE", "", inc.ID.String(), note); err != nil {
			return err
		}
		act := c.Actor()
		if err := attach(ctx, q, c.Org, inc.ID, a.ID, a.Severity, act.Type, act.ID); err != nil {
			return err
		}
		subs, err := Subjects(a.Subjects)
		if err != nil {
			return err
		}
		if err := IncidentEntry(ctx, tx, inc, subs); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "incident.alert_promoted", "incident", inc.ID, map[string]string{"alert": a.ID.String()}); err != nil {
			return err
		}
		out, err = q.GetIncident(ctx, c.Org, inc.ID)
		return err
	})
	return out, err
}

// LinkAlert attaches an alert to an open incident.
func (s *Incidents) LinkAlert(ctx context.Context, alert, incident ids.UUID) (dbq.PcAlert, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcAlert{}, err
	}
	var out dbq.PcAlert
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.LockAlert(ctx, c.Org, alert)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		inc, err := q.LockIncident(ctx, c.Org, incident)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if a.IncidentID != nil {
			return ErrAlreadyLinked
		}
		if inc.State == "RESOLVED" {
			return ErrState
		}
		act := c.Actor()
		if err := attach(ctx, q, c.Org, inc.ID, a.ID, a.Severity, act.Type, act.ID); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "incident.alert_linked", "incident", inc.ID, map[string]string{"alert": a.ID.String()}); err != nil {
			return err
		}
		out, err = q.GetAlert(ctx, c.Org, alert)
		return err
	})
	return out, err
}

// IncidentPage is one page of incidents.
type IncidentPage struct {
	Items []dbq.PcIncident
	Next  string
}

// ListIncidents lists the incidents the caller may read: with incident.read
// at the org every incident, otherwise those whose alerts all name agents
// the caller may read.
func (s *Incidents) ListIncidents(ctx context.Context, states []string, size int32, token string) (IncidentPage, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return IncidentPage{}, err
	}
	c, err := reader(ctx)
	if err != nil {
		return IncidentPage{}, err
	}
	if err := requireRead(c); err != nil {
		return IncidentPage{}, err
	}
	if states == nil {
		states = []string{}
	}
	var out IncidentPage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		all, visible, err := newVisibility(c, q).scope.Visible(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ListIncidents(ctx, dbq.ListIncidentsParams{
			OrgID: c.Org, AllAgents: all, VisibleAgents: nonNil(visible), Before: p.After, States: states, PageLimit: p.Limit(),
		})
		if err != nil {
			return err
		}
		out.Items, out.Next = page.Finish(p, rows, func(i dbq.PcIncident) ids.UUID { return i.ID })
		return nil
	}, db.ReadOnly())
	return out, err
}

func incidentVisible(ctx context.Context, q *dbq.Queries, v *visibility, inc dbq.PcIncident) (bool, error) {
	if v.org {
		return true, nil
	}
	as, err := q.IncidentAlerts(ctx, inc.OrgID, &inc.ID)
	if err != nil || len(as) == 0 {
		return false, err
	}
	for _, a := range as {
		if ok, err := v.alert(ctx, a); err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

// IncidentDetail is one incident with its alerts, history and retry
// groups.
type IncidentDetail struct {
	Incident dbq.PcIncident
	Alerts   []dbq.PcAlert
	Events   []dbq.PcIncidentEvent
	Retries  []RetryGroup
}

// RetryGroup is the alerts about one transaction (D15).
type RetryGroup struct {
	Transaction   ids.UUID
	Count         int
	First, Latest time.Time
	Executed      bool
}

// GetIncident returns one incident the caller may read.
func (s *Incidents) GetIncident(ctx context.Context, id ids.UUID) (IncidentDetail, error) {
	c, err := reader(ctx)
	if err != nil {
		return IncidentDetail{}, err
	}
	if err := requireRead(c); err != nil {
		return IncidentDetail{}, err
	}
	var out IncidentDetail
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		inc, err := q.GetIncident(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		v := newVisibility(c, q)
		if ok, err := incidentVisible(ctx, q, v, inc); err != nil {
			return err
		} else if !ok {
			return ErrNotFound
		}
		out.Incident = inc
		if out.Alerts, err = q.IncidentAlerts(ctx, c.Org, &id); err != nil {
			return err
		}
		if out.Events, err = q.IncidentEvents(ctx, c.Org, id); err != nil {
			return err
		}
		out.Retries, err = retryGroups(ctx, q, c.Org, out.Alerts)
		return err
	}, db.ReadOnly())
	return out, err
}

// retryGroups groups an incident's alerts by the transaction they name,
// with first and latest time, count and whether any attempt executed.
func retryGroups(ctx context.Context, q *dbq.Queries, org ids.OrgID, as []dbq.PcAlert) ([]RetryGroup, error) {
	by := map[string]*RetryGroup{}
	var order []string
	for _, a := range as {
		subs, err := Subjects(a.Subjects)
		if err != nil {
			return nil, err
		}
		for _, sub := range subs {
			if sub.Type != reflexdomain.SubjectTransaction {
				continue
			}
			g, ok := by[sub.ID]
			if !ok {
				id, err := ids.ParseUUID(sub.ID)
				if err != nil {
					continue
				}
				g = &RetryGroup{Transaction: id, First: a.FirstSeen, Latest: a.LastSeen}
				by[sub.ID] = g
				order = append(order, sub.ID)
			}
			g.Count += int(a.Count)
			if a.FirstSeen.Before(g.First) {
				g.First = a.FirstSeen
			}
			if a.LastSeen.After(g.Latest) {
				g.Latest = a.LastSeen
			}
		}
	}
	out := make([]RetryGroup, 0, len(order))
	for _, k := range order {
		g := by[k]
		t, err := q.TransactionSummary(ctx, org, g.Transaction)
		if err == nil {
			g.Executed = t.PermitState != nil && *t.PermitState != "ISSUED" && *t.PermitState != "RELEASED"
		} else if !db.IsNoRows(err) {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, nil
}

// AssignIncident sets an incident's owner.
func (s *Incidents) AssignIncident(ctx context.Context, id, owner ids.UUID) (dbq.PcIncident, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcIncident{}, err
	}
	var out dbq.PcIncident
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		inc, err := q.LockIncident(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := one(q.AssignIncident(ctx, &owner, c.Org, id)); err != nil {
			if isFK(err) {
				return ErrNotFound
			}
			return err
		}
		from := ""
		if inc.OwnerID != nil {
			from = inc.OwnerID.String()
		}
		if err := incidentEvent(ctx, q, c, id, "OWNER", from, owner.String(), "", nil); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "incident.assigned", "incident", id, map[string]string{"owner": owner.String()}); err != nil {
			return err
		}
		out, err = q.GetIncident(ctx, c.Org, id)
		return err
	})
	return out, err
}

var incidentMoves = map[string][]string{
	"OPEN":      {"CONTAINED", "RESOLVED"},
	"CONTAINED": {"OPEN", "RESOLVED"},
	"RESOLVED":  {"OPEN"},
}

// SetIncidentState moves an incident. Closing it lifts no containment
// (HR-250): controls lift only through restoration.
func (s *Incidents) SetIncidentState(ctx context.Context, id ids.UUID, to, note string) (dbq.PcIncident, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcIncident{}, err
	}
	var out dbq.PcIncident
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		inc, err := q.LockIncident(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if !contains(incidentMoves[inc.State], to) {
			return ErrState
		}
		if err := one(q.SetIncidentState(ctx, dbq.SetIncidentStateParams{ToState: to, OrgID: c.Org, ID: id, FromState: inc.State})); err != nil {
			return err
		}
		if err := incidentEvent(ctx, q, c, id, "STATE", inc.State, to, note, nil); err != nil {
			return err
		}
		from := inc.State
		inc.State = to
		if err := IncidentEntry(ctx, tx, inc, nil); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "incident.state_set", "incident", id, map[string]string{"from": from, "to": to}); err != nil {
			return err
		}
		out, err = q.GetIncident(ctx, c.Org, id)
		return err
	})
	return out, err
}

// Suppression is a suppression with the subjects bypasses took out of it.
type Suppression struct {
	dbq.PcSuppression
	Broken []string
}

// SuppressionRequest describes a suppression.
type SuppressionRequest struct {
	Rule        string
	Subjects    []reflexdomain.Subject
	MaxSeverity reflexdomain.Severity
	Reason      string
	ExpiresIn   time.Duration
}

// MaxSuppression is the longest a suppression lasts (HR-242).
const MaxSuppression = 30 * 24 * time.Hour

// CreateSuppression stores a suppression (Team, HR-242): scope, reason and
// an expiry at most 30 days out are required.
func (s *Incidents) CreateSuppression(ctx context.Context, r SuppressionRequest) (Suppression, error) {
	c, err := manager(ctx)
	if err != nil {
		return Suppression{}, err
	}
	if s.Hooks == nil || !s.Hooks.ents(ctx).ReflexTeam() {
		return Suppression{}, ErrEdition
	}
	switch {
	case r.Rule == "" || len(r.Rule) > 128:
		return Suppression{}, pcerr.New(pcerr.InvalidArgument, "INVALID_RULE", "a suppression names one rule")
	case strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 500:
		return Suppression{}, pcerr.New(pcerr.InvalidArgument, "INVALID_REASON", "a suppression needs a reason")
	case r.ExpiresIn <= 0 || r.ExpiresIn > MaxSuppression:
		return Suppression{}, pcerr.New(pcerr.InvalidArgument, "INVALID_EXPIRY", "a suppression expires within 30 days")
	case !r.MaxSeverity.Valid():
		return Suppression{}, pcerr.New(pcerr.InvalidArgument, "INVALID_SEVERITY", "unknown severity")
	case len(r.Subjects) > reflexdomain.MaxSubjects:
		return Suppression{}, ErrInvalidSubject
	}
	for _, sub := range r.Subjects {
		if !sub.Valid() {
			return Suppression{}, ErrInvalidSubject
		}
	}
	subs := r.Subjects
	if subs == nil {
		subs = []reflexdomain.Subject{}
	}
	raw, err := json.Marshal(subs)
	if err != nil {
		return Suppression{}, err
	}
	var out Suppression
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		// The database clock bounds the expiry (the insert trigger checks it).
		var dbNow time.Time
		if err := tx.QueryRow(ctx, "SELECT now()").Scan(&dbNow); err != nil {
			return err
		}
		sup, err := q.InsertSuppression(ctx, dbq.InsertSuppressionParams{
			OrgID: c.Org, ID: ids.NewV7(), RuleID: r.Rule, Subjects: raw, MaxSeverity: string(r.MaxSeverity),
			Reason: strings.TrimSpace(r.Reason), CreatedBy: c.Principal.ID, ExpiresAt: dbNow.Add(r.ExpiresIn),
		})
		if err != nil {
			return err
		}
		out = Suppression{PcSuppression: sup}
		return s.audit(ctx, tx, c, "incident.suppression_created", "suppression", sup.ID, map[string]string{
			"rule": r.Rule, "max_severity": string(r.MaxSeverity), "subjects": itoa(len(r.Subjects)),
			"expires_at": sup.ExpiresAt.UTC().Format(time.RFC3339),
		})
	})
	return out, err
}

// SuppressionPage is one page of suppressions.
type SuppressionPage struct {
	Items []Suppression
	Next  string
}

// ListSuppressions lists suppressions (incident.read at the org).
func (s *Incidents) ListSuppressions(ctx context.Context, active bool, size int32, token string) (SuppressionPage, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return SuppressionPage{}, err
	}
	c, err := reader(ctx)
	if err != nil {
		return SuppressionPage{}, err
	}
	if err := c.Require(td.PermIncidentRead, td.OrgPath(c.Org)); err != nil {
		return SuppressionPage{}, err
	}
	var out SuppressionPage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListSuppressions(ctx, dbq.ListSuppressionsParams{OrgID: c.Org, ActiveOnly: active, Before: p.After, PageLimit: p.Limit()})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(p, rows, func(x dbq.PcSuppression) ids.UUID { return x.ID })
		for _, r := range rows {
			sup, err := withBreaks(ctx, q, r)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, sup)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

func withBreaks(ctx context.Context, q *dbq.Queries, r dbq.PcSuppression) (Suppression, error) {
	bs, err := q.SuppressionBreaks(ctx, r.OrgID, r.ID)
	if err != nil {
		return Suppression{}, err
	}
	out := Suppression{PcSuppression: r}
	for _, b := range bs {
		if !contains(out.Broken, b.Subject) {
			out.Broken = append(out.Broken, b.Subject)
		}
	}
	return out, nil
}

// EndSuppression ends a suppression now.
func (s *Incidents) EndSuppression(ctx context.Context, id ids.UUID, reason string) (Suppression, error) {
	c, err := manager(ctx)
	if err != nil {
		return Suppression{}, err
	}
	var out Suppression
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.EndSuppression(ctx, dbq.EndSuppressionParams{EndedBy: &c.Principal.ID, EndReason: &reason, OrgID: c.Org, ID: id})
		if err != nil {
			return err
		}
		r, err := q.GetSuppression(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		// Its suppressed alerts open again (D59 M1).
		if err := alerts.ReopenUnsuppressed(ctx, tx); err != nil {
			return err
		}
		if out, err = withBreaks(ctx, q, r); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "incident.suppression_ended", "suppression", id, nil)
	})
	return out, err
}

// FailurePage is one page of owned failures.
type FailurePage struct {
	Items []dbq.PcOperationalFailure
	Next  string
}

// ListFailures lists owned failures (incident.read at the org).
func (s *Incidents) ListFailures(ctx context.Context, states []string, size int32, token string) (FailurePage, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return FailurePage{}, err
	}
	c, err := reader(ctx)
	if err != nil {
		return FailurePage{}, err
	}
	if err := c.Require(td.PermIncidentRead, td.OrgPath(c.Org)); err != nil {
		return FailurePage{}, err
	}
	if states == nil {
		states = []string{}
	}
	var out FailurePage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListFailures(ctx, dbq.ListFailuresParams{OrgID: c.Org, Before: p.After, States: states, PageLimit: p.Limit()})
		if err != nil {
			return err
		}
		out.Items, out.Next = page.Finish(p, rows, func(x dbq.PcOperationalFailure) ids.UUID { return x.ID })
		return nil
	}, db.ReadOnly())
	return out, err
}

// AssignFailure sets a failure's owner to a user.
func (s *Incidents) AssignFailure(ctx context.Context, id, owner ids.UUID) (dbq.PcOperationalFailure, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcOperationalFailure{}, err
	}
	var out dbq.PcOperationalFailure
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetUser(ctx, c.Org, owner); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		t, o := string(reflexdomain.SubjectUser), owner.String()
		n, err := q.AssignFailure(ctx, dbq.AssignFailureParams{OwnerType: &t, OwnerID: &o, OrgID: c.Org, ID: id})
		if err != nil {
			return err
		}
		if out, err = q.GetFailure(ctx, c.Org, id); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		return s.audit(ctx, tx, c, "incident.failure_assigned", "failure", id, map[string]string{"owner": o})
	})
	return out, err
}

// ResolveFailure records how a failure was resolved.
func (s *Incidents) ResolveFailure(ctx context.Context, id ids.UUID, resolution string) (dbq.PcOperationalFailure, error) {
	c, err := manager(ctx)
	if err != nil {
		return dbq.PcOperationalFailure{}, err
	}
	var out dbq.PcOperationalFailure
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.ResolveFailure(ctx, dbq.ResolveFailureParams{ResolvedBy: &c.Principal.ID, Resolution: &resolution, OrgID: c.Org, ID: id})
		if err != nil {
			return err
		}
		if out, err = q.GetFailure(ctx, c.Org, id); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		return s.audit(ctx, tx, c, "incident.failure_resolved", "failure", id, map[string]string{"kind": out.Kind})
	})
	return out, err
}

// Sink returns the core FailureSink.
func Sink() *failures.Sink { return &failures.Sink{} }

func (s *Incidents) audit(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name, objType string, id ids.UUID,
	details map[string]string,
) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: id.String()}, Details: details,
	})
	return err
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func isFK(err error) bool { return db.IsForeignKeyViolation(err) }

// one turns an :execrows result into ErrState unless exactly one row
// changed.
func one(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
