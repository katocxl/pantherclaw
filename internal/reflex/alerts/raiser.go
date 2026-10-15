// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package alerts turns Reflex signals into alerts (G0 M10 D14): the store
// side of the Raiser port. A signal at FINDING or above becomes an alert,
// or counts into the open alert with the same dedupe key and appends its
// evidence (HR-243); a LIVE signal becomes a reflex.live ledger entry; a
// TELEMETRY signal is not written. A test signal is capped at ALERT and
// never pages (F616).
package alerts

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Actor is how Reflex appears in the ledger.
var Actor = evdomain.Actor{Type: "system", ID: "reflex"}

// Alert states.
const (
	StateOpen         = "OPEN"
	StateAcknowledged = "ACKNOWLEDGED"
	StateResolved     = "RESOLVED"
	StateSuppressed   = "SUPPRESSED"
)

// Raised is what Raise did with a signal.
type Raised struct {
	// Alert is the alert the signal created or counted into; zero when the
	// signal was LIVE or TELEMETRY.
	Alert ids.UUID
	// New reports a new alert rather than a repeat.
	New bool
	// State is the alert's state after the signal.
	State string
	// Attention is the signal's attention after the test cap.
	Attention reflexdomain.Attention
	// Incident is the alert's incident, if it has one.
	Incident *ids.UUID
	// Count is how many signals the alert has counted.
	Count int
}

// Hooks extend the store-level Raiser with suppression, incident grouping
// and notifications (phase B). Each may be nil.
type Hooks struct {
	// Suppress returns the active suppression the signal falls under, if
	// any, and records breaks (D16).
	Suppress func(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal) (*ids.UUID, error)
	// After runs once the alert is written: incidents, notifications.
	After func(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal, r Raised) error
}

// Raiser is the core Raiser implementation.
type Raiser struct {
	Hooks Hooks
}

var _ reflexdomain.Raiser = (*Raiser)(nil)

// Raise implements reflexdomain.Raiser.
func (r *Raiser) Raise(ctx context.Context, ptx pgx.Tx, s reflexdomain.Signal) (ids.UUID, error) {
	tx, err := db.AdoptTenantTx(ctx, ptx, s.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	res, err := r.RaiseTx(ctx, tx, s)
	return res.Alert, err
}

// RaiseTx raises s in a tenant transaction and says what it did.
func (r *Raiser) RaiseTx(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal) (Raised, error) {
	if s.Org != tx.OrgID() {
		return Raised{}, db.ErrTenantMismatch
	}
	if err := s.Validate(); err != nil {
		return Raised{}, err
	}
	if err := audit.ValidateDetails(s.Facts); err != nil {
		return Raised{}, fmt.Errorf("%w: %w", reflexdomain.ErrInvalidSignal, err)
	}
	s = Cap(s)
	switch s.Attention {
	case reflexdomain.AttentionTelemetry:
		return Raised{Attention: s.Attention}, nil
	case reflexdomain.AttentionLive:
		if _, err := ledger.Append(ctx, tx, reflexdomain.KindLive, Actor, entryBody(s, ids.UUID{}, "")); err != nil {
			return Raised{}, fmt.Errorf("alerts: live entry: %w", err)
		}
		return Raised{Attention: s.Attention}, nil
	}
	var suppression *ids.UUID
	if r.Hooks.Suppress != nil {
		var err error
		if suppression, err = r.Hooks.Suppress(ctx, tx, s); err != nil {
			return Raised{}, err
		}
	}
	res, err := Write(ctx, tx, s, suppression)
	if err != nil {
		return Raised{}, err
	}
	if r.Hooks.After != nil {
		if err := r.Hooks.After(ctx, tx, s, res); err != nil {
			return Raised{}, err
		}
	}
	return res, nil
}

// Cap applies the attention rules every alert follows: a test signal is
// capped at ALERT (F616).
func Cap(s reflexdomain.Signal) reflexdomain.Signal {
	if s.Test && s.Attention.AtLeast(reflexdomain.AttentionIncident) {
		s.Attention = reflexdomain.AttentionAlert
	}
	if s.DedupeKey == "" {
		s.DedupeKey = DedupeKey(s)
	}
	return s
}

// DedupeKey is the default dedupe key: source, rule and subjects.
func DedupeKey(s reflexdomain.Signal) string {
	var b strings.Builder
	b.WriteString(s.Source + "|" + s.RuleID)
	for _, sub := range s.Subjects {
		b.WriteString("|" + sub.String())
	}
	k := b.String()
	if len(k) > reflexdomain.MaxKey {
		k = k[:reflexdomain.MaxKey]
	}
	return k
}

// Write stores the alert of a FINDING-or-above signal, or counts it into
// the open alert with the same dedupe key, and appends its evidence. A new
// alert also writes a reflex.alert ledger entry and a RAISED event.
func Write(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal, suppression *ids.UUID) (Raised, error) {
	q := dbq.New(tx)
	subjects, err := json.Marshal(nonNil(s.Subjects))
	if err != nil {
		return Raised{}, err
	}
	facts, err := json.Marshal(nonNilMap(s.Facts), json.Deterministic(true))
	if err != nil {
		return Raised{}, err
	}
	state := StateOpen
	if suppression != nil {
		state = StateSuppressed
	}
	row, err := q.UpsertAlert(ctx, dbq.UpsertAlertParams{
		OrgID: s.Org, ID: ids.NewV7(), Source: s.Source, RuleID: s.RuleID, RuleVersion: s.RuleVersion,
		RuleDigest: s.RuleDigest, PackVersion: s.PackVersion, Title: s.Title, Summary: s.Summary,
		Severity: string(s.Severity), Attention: string(s.Attention), Basis: string(s.Basis), Subjects: subjects,
		Atlas: nonNilStrings(s.ATLAS), Owasp: nonNilStrings(s.OWASP), Facts: facts, GroupKey: s.GroupKey,
		DedupeKey: s.DedupeKey, State: state, SuppressionID: suppression, OccurredAt: s.OccurredAt, Test: s.Test,
	})
	if err != nil {
		return Raised{}, fmt.Errorf("alerts: write: %w", err)
	}
	for _, e := range s.Evidence {
		if err := q.InsertAlertEvidence(ctx, dbq.InsertAlertEvidenceParams{
			OrgID: s.Org, ID: ids.NewV7(), AlertID: row.ID, Kind: e.Kind, RefID: e.ID, OccurredAt: s.OccurredAt,
		}); err != nil {
			return Raised{}, fmt.Errorf("alerts: evidence: %w", err)
		}
	}
	res := Raised{
		Alert: row.ID, New: row.Inserted, State: row.State, Attention: s.Attention, Incident: row.IncidentID,
		Count: int(row.Count),
	}
	if !row.Inserted {
		return res, nil
	}
	if err := q.InsertAlertEvent(ctx, dbq.InsertAlertEventParams{
		OrgID: s.Org, ID: ids.NewV7(), AlertID: row.ID, Kind: "RAISED", ActorType: Actor.Type, ActorID: Actor.ID,
		ToValue: &row.State,
	}); err != nil {
		return Raised{}, fmt.Errorf("alerts: event: %w", err)
	}
	if _, err := ledger.Append(ctx, tx, reflexdomain.KindAlert, Actor, entryBody(s, row.ID, row.State)); err != nil {
		return Raised{}, fmt.Errorf("alerts: ledger: %w", err)
	}
	return res, nil
}

// entryBody is the canonical ledger body of an alert or live event: ids,
// rule references and subjects only, at most 8 KiB (D6).
func entryBody(s reflexdomain.Signal, id ids.UUID, state string) []byte {
	type body struct {
		ID          string                 `json:"id,omitzero"`
		Source      string                 `json:"source"`
		Rule        string                 `json:"rule,omitzero"`
		RuleVersion string                 `json:"rule_version,omitzero"`
		RuleDigest  string                 `json:"rule_digest,omitzero"`
		PackVersion string                 `json:"pack_version,omitzero"`
		Severity    string                 `json:"severity"`
		Attention   string                 `json:"attention"`
		Basis       string                 `json:"basis"`
		State       string                 `json:"state,omitzero"`
		Subjects    []reflexdomain.Subject `json:"subjects"`
		Evidence    []string               `json:"evidence,omitzero"`
		Test        bool                   `json:"test,omitzero"`
	}
	b := body{
		Source: s.Source, Rule: s.RuleID, RuleVersion: s.RuleVersion, RuleDigest: s.RuleDigest, PackVersion: s.PackVersion,
		Severity: string(s.Severity), Attention: string(s.Attention), Basis: string(s.Basis), State: state,
		Subjects: nonNil(s.Subjects), Test: s.Test,
	}
	if !id.IsZero() {
		b.ID = id.String()
	}
	for _, e := range s.Evidence {
		b.Evidence = append(b.Evidence, e.Kind+":"+e.ID.String())
	}
	for {
		out, err := evdomain.CanonicalBody(b)
		if err == nil && len(out) <= reflexdomain.MaxLedgerBody {
			return out
		}
		switch {
		case len(b.Evidence) > 0:
			b.Evidence = b.Evidence[:len(b.Evidence)/2]
		case len(b.Subjects) > 1:
			b.Subjects = b.Subjects[:len(b.Subjects)/2]
		default:
			out, _ := evdomain.CanonicalBody(body{ID: b.ID, Source: b.Source, Rule: b.Rule, Severity: b.Severity,
				Attention: b.Attention, Basis: b.Basis, State: b.State, Subjects: []reflexdomain.Subject{}, Test: b.Test})
			return out
		}
	}
}

func nonNil(s []reflexdomain.Subject) []reflexdomain.Subject {
	if s == nil {
		return []reflexdomain.Subject{}
	}
	return s
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
