// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds Reflex's use cases (G0 M10 D14–D18): the Raiser's
// suppression, incident grouping and notification hooks, the alert,
// incident, suppression and owned-failure services behind
// IncidentService, the custom detection rules behind DetectionService and
// the daily digest.
package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// GroupWindow is how recently an incident's group must have been seen for
// an alert to attach to it (F603: 24 hours).
const GroupWindow = 24 * time.Hour

// Entitlements reads the server's current edition.
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Notifier enqueues notifications in the caller's transaction.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// ContainmentReader says what containment applies to a signal's subjects
// now (the response stream's read port); nil means "unknown".
type ContainmentReader interface {
	ContainmentSummary(ctx context.Context, tx db.TenantTx, subjects []reflexdomain.Subject) (string, error)
}

// Hooks are the Raiser's suppression, incident and notification steps.
type Hooks struct {
	Ents        Entitlements
	Notify      Notifier
	Containment ContainmentReader
	Now         func() time.Time
}

func (h *Hooks) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Hooks) ents(ctx context.Context) billing.Entitlements {
	if h.Ents != nil {
		if e, err := h.Ents.Current(ctx); err == nil {
			return e
		}
	}
	return billing.CommunityEntitlements()
}

// Raiser returns the core Raiser with these hooks.
func (h *Hooks) Raiser() *alerts.Raiser {
	return &alerts.Raiser{Hooks: alerts.Hooks{Suppress: h.Suppress, After: h.After}}
}

// Break reasons (D16).
const (
	BreakSeverity          = "SEVERITY_ABOVE_MAX"
	BreakSubjectOutside    = "SUBJECT_OUTSIDE_SCOPE"
	BreakFailedContainment = "FAILED_CONTAINMENT"
)

// Suppress returns the active suppression s falls under (Team, F616,
// HR-242). A signal above the suppression's max severity, naming a subject
// outside its scope, or from response (failed containment) bypasses it:
// the bypass is recorded as a break for each subject, and the suppression
// no longer covers those subjects.
func (h *Hooks) Suppress(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal) (*ids.UUID, []alerts.Break, error) {
	if s.RuleID == "" || !h.ents(ctx).ReflexTeam() {
		return nil, nil, nil
	}
	q := dbq.New(tx)
	sups, err := q.ActiveSuppressions(ctx, tx.OrgID(), s.RuleID)
	if err != nil || len(sups) == 0 {
		return nil, nil, err
	}
	var bypassed []alerts.Break
	for _, sup := range sups {
		var scope []reflexdomain.Subject
		if err := json.Unmarshal(sup.Subjects, &scope); err != nil {
			return nil, nil, err
		}
		reason := ""
		switch {
		case s.Source == reflexdomain.SourceResponse:
			reason = BreakFailedContainment
		case s.Severity.Rank() > reflexdomain.Severity(sup.MaxSeverity).Rank():
			reason = BreakSeverity
		default:
			in, outside := inScope(scope, s.Subjects)
			if outside {
				reason = BreakSubjectOutside
			} else if !in {
				continue
			}
		}
		broken := false
		for _, sub := range s.Subjects {
			b, err := q.SuppressionBroken(ctx, tx.OrgID(), sup.ID, sub.String())
			if err != nil {
				return nil, nil, err
			}
			broken = broken || b
		}
		if reason == "" && !broken {
			id := sup.ID
			return &id, bypassed, nil
		}
		if reason != "" {
			bypassed = append(bypassed, alerts.Break{Suppression: sup.ID, Reason: reason, Subjects: s.Subjects})
		}
	}
	return nil, bypassed, nil
}

// inScope reports whether the subjects fall inside a suppression's scope
// and whether any of them is outside it. An empty scope covers every
// subject. For each subject type the scope names, the signal's subjects of
// that type must all be listed; a signal with none of them is not in scope.
func inScope(scope, subjects []reflexdomain.Subject) (in, outside bool) {
	if len(scope) == 0 {
		return true, false
	}
	matched := false
	for _, t := range reflexdomain.SubjectTypes() {
		if !slices.ContainsFunc(scope, func(x reflexdomain.Subject) bool { return x.Type == t }) {
			continue
		}
		for _, sub := range subjects {
			if sub.Type != t {
				continue
			}
			if slices.Contains(scope, sub) {
				matched = true
			} else {
				return false, true
			}
		}
	}
	return matched, false
}

// After groups the alert into an incident and sends its notifications. A
// suppressed alert never notifies, pages or opens an incident (HR-242).
func (h *Hooks) After(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal, r alerts.Raised) error {
	q := dbq.New(tx)
	if r.State == alerts.StateSuppressed {
		return nil
	}
	ents := h.ents(ctx)
	incident, opened, err := h.group(ctx, tx, q, s, r, ents)
	if err != nil {
		return err
	}
	if !ents.ReflexTeam() || h.Notify == nil {
		return nil
	}
	if r.New && r.Attention.AtLeast(reflexdomain.AttentionAlert) {
		if err := h.notifyAlert(ctx, tx, s, r); err != nil {
			return err
		}
	}
	if opened {
		return h.notifyIncident(ctx, tx, s, incident)
	}
	return nil
}

// group attaches the alert to an incident (D15). PAGE and INCIDENT
// attention open or attach in every edition; with Team, any alert attaches
// to the open incident of its evidence-based group seen within a day.
// Test alerts never join incidents.
func (h *Hooks) group(ctx context.Context, tx db.TenantTx, q *dbq.Queries, s reflexdomain.Signal, r alerts.Raised,
	ents billing.Entitlements,
) (ids.UUID, bool, error) {
	if r.Incident != nil || s.Test || !r.Attention.AtLeast(reflexdomain.AttentionAlert) {
		return ids.UUID{}, false, nil
	}
	escalates := r.Attention.AtLeast(reflexdomain.AttentionIncident)
	if !escalates && !ents.ReflexTeam() {
		return ids.UUID{}, false, nil
	}
	org := tx.OrgID()
	if s.GroupKey != "" {
		g, err := q.FindGroupIncident(ctx, org, s.GroupKey, h.now().Add(-GroupWindow))
		switch {
		case err == nil:
			return g.ID, false, attach(ctx, q, org, g.ID, r.Alert, string(s.Severity), "system", "reflex")
		case !db.IsNoRows(err):
			return ids.UUID{}, false, err
		}
	}
	if !escalates {
		return ids.UUID{}, false, nil
	}
	inc, err := q.InsertIncident(ctx, dbq.InsertIncidentParams{
		OrgID: org, ID: ids.NewV7(), Title: s.Title, Severity: string(s.Severity), GroupKey: s.GroupKey,
		OpenedBy: "alert:" + r.Alert.String(),
	})
	if err != nil {
		return ids.UUID{}, false, err
	}
	state := "OPEN"
	if err := q.InsertIncidentEvent(ctx, dbq.InsertIncidentEventParams{
		OrgID: org, ID: ids.NewV7(), IncidentID: inc.ID, Kind: "OPENED", ActorType: "system", ActorID: "reflex",
		ToValue: &state, AlertID: &r.Alert,
	}); err != nil {
		return ids.UUID{}, false, err
	}
	if err := IncidentEntry(ctx, tx, inc, s.Subjects); err != nil {
		return ids.UUID{}, false, err
	}
	return inc.ID, true, attach(ctx, q, org, inc.ID, r.Alert, string(s.Severity), "system", "reflex")
}

// attach links an alert to an incident with a LINK event and raises the
// incident's severity to the alert's when higher.
func attach(ctx context.Context, q *dbq.Queries, org ids.OrgID, incident, alert ids.UUID, severity, actorType, actorID string) error {
	n, err := q.AttachAlert(ctx, &incident, org, alert)
	if err != nil || n == 0 {
		return err
	}
	if err := q.InsertIncidentEvent(ctx, dbq.InsertIncidentEventParams{
		OrgID: org, ID: ids.NewV7(), IncidentID: incident, Kind: "LINK", ActorType: actorType, ActorID: actorID, AlertID: &alert,
	}); err != nil {
		return err
	}
	to := incident.String()
	if err := q.InsertAlertEvent(ctx, dbq.InsertAlertEventParams{
		OrgID: org, ID: ids.NewV7(), AlertID: alert, Kind: "LINK", ActorType: actorType, ActorID: actorID, ToValue: &to,
	}); err != nil {
		return err
	}
	raised, err := q.RaiseIncidentSeverity(ctx, severity, org, incident)
	if err != nil || raised == 0 {
		return err
	}
	return q.InsertIncidentEvent(ctx, dbq.InsertIncidentEventParams{
		OrgID: org, ID: ids.NewV7(), IncidentID: incident, Kind: "SEVERITY", ActorType: actorType, ActorID: actorID,
		ToValue: &severity, AlertID: &alert,
	})
}

// IncidentEntry writes the reflex.incident ledger entry of an incident
// change (D6): ids, state, severity and subjects only.
func IncidentEntry(ctx context.Context, tx db.TenantTx, inc dbq.PcIncident, subjects []reflexdomain.Subject) error {
	if subjects == nil {
		subjects = []reflexdomain.Subject{}
	}
	if len(subjects) > 16 {
		subjects = subjects[:16]
	}
	body, err := canonical(map[string]any{
		"id": inc.ID.String(), "state": inc.State, "severity": inc.Severity, "attention": string(reflexdomain.AttentionIncident),
		"subjects": subjects, "group": inc.GroupKey,
	})
	if err != nil {
		return err
	}
	if _, err := ledger.Append(ctx, tx, reflexdomain.KindIncident, alerts.Actor, body); err != nil {
		return fmt.Errorf("reflex: incident entry: %w", err)
	}
	return nil
}
