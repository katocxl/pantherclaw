// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app stores posture findings and drives their lifecycle (G0 M10
// D30; F265, F268; HR-255). A recomputation reconciles the findings with
// what the new exposure snapshot shows; people assign, test, accept for a
// while or mark evidence incomplete. Only a recomputation remediates.
// Every state change adds an event and a posture.finding ledger entry.
package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/posture/domain"
)

// Errors.
var (
	ErrNotFound   = errors.New("posture: finding not found")
	ErrTransition = domain.ErrTransition
	ErrAcceptance = domain.ErrAcceptance
)

var errNote = errors.New("posture: a note is 1..1000 characters")

// LedgerKind is the ledger entry kind of a finding's state change (D6).
const LedgerKind = "posture.finding"

// System is the actor of a recomputation's changes.
var System = evdomain.Actor{Type: "system", ID: "exposure"}

// Inputs builds posture derivation's inputs from a recomputation.
func Inputs(rec exapp.Recomputed) domain.Inputs {
	l := rec.Loaded
	in := domain.Inputs{
		Now: l.Inputs.Now, Rights: rec.Rights, Unverified: l.Unverified, Irreversible: l.Irreversible,
	}
	for _, a := range l.Agents {
		in.Agents = append(in.Agents, domain.Agent{ID: a.ID, Owned: a.Owned})
	}
	for _, g := range l.Grants {
		in.Grants = append(in.Grants, domain.GrantInfo{ID: g.ID, Unbounded: g.Unbounded, CreatedAt: g.CreatedAt})
	}
	for _, c := range l.Credentials {
		in.Credentials = append(in.Credentials, domain.CredentialInfo{Connection: c.ConnectionID, Name: c.Name, CreatedAt: c.CreatedAt})
	}
	for _, f := range l.Overreach {
		in.CoverageFindings = append(in.CoverageFindings, domain.CoverageFinding{
			ID: f.ID, Connection: f.ConnectionID, Agent: f.AgentID, Subject: f.Subject, Excess: f.Excess, Severity: f.Severity,
		})
	}
	return in
}

// Summary counts what a reconciliation did.
type Summary map[domain.ActionKind]int

// FindingHook is told, in the reconciliation's transaction, of every
// finding a reconciliation opened, saw, moved or remediated (G0 M16 D91:
// suggestions follow unused-authority findings).
type FindingHook interface {
	FindingChanged(ctx context.Context, tx db.TenantTx, finding ids.UUID, kind domain.Kind, act domain.ActionKind) error
}

// Reconcile brings the org's findings in line with a recomputation, in the
// same transaction.
func Reconcile(ctx context.Context, tx db.TenantTx, rec exapp.Recomputed) (Summary, error) {
	return ReconcileWith(ctx, tx, rec, nil)
}

// ReconcileWith is Reconcile that also tells hook (nil: nobody) of each
// finding it touched.
func ReconcileWith(ctx context.Context, tx db.TenantTx, rec exapp.Recomputed, hook FindingHook) (Summary, error) {
	q, org := dbq.New(tx), tx.OrgID()
	rows, err := q.PostureFindingsForReconcile(ctx, org)
	if err != nil {
		return nil, err
	}
	stored := make([]domain.Finding, 0, len(rows))
	for _, r := range rows {
		stored = append(stored, domain.Finding{
			ID: r.ID, Kind: domain.Kind(r.Kind), Fingerprint: r.Fingerprint, State: domain.State(r.State), Paths: r.AffectedPaths,
			AcceptedUntil: r.AcceptedUntil, Connection: r.ConnectionID, PathsTruncated: r.PathsTruncated,
		})
	}
	in := Inputs(rec)
	// Activated, unconfirmed GitHub App key rotations (G0 M20 S20c, D259).
	rots, err := q.UnconfirmedRotations(ctx, org)
	if err != nil {
		return nil, err
	}
	for _, r := range rots {
		in.Rotations = append(in.Rotations, domain.RotationInfo{ID: r.ID, Connection: r.ConnectionID, Name: r.ConnectionName, Since: r.Since})
	}
	cands := domain.Derive(in)
	acts := domain.Reconcile(stored, cands, domain.Snapshot{
		Now: rec.Loaded.Inputs.Now, Rights: rec.Rights, Truncated: rec.Snapshot.Truncated, Gaps: rec.Snapshot.Gaps,
	})
	sum := Summary{}
	snap := rec.Snapshot.ID
	at := rec.Snapshot.ComputedAt
	for _, a := range acts {
		var id ids.UUID
		var kind domain.Kind
		if a.Finding != nil {
			id, kind = a.Finding.ID, a.Finding.Kind
		} else if a.Candidate != nil {
			kind = a.Candidate.Kind
		}
		switch a.Kind {
		case domain.ActOpen:
			f, err := insert(ctx, q, org, *a.Candidate, snap, at)
			if err != nil {
				return nil, err
			}
			id = f.ID
			if err := record(ctx, tx, id, "OPENED", nil, domain.Open, System, "", &snap); err != nil {
				return nil, err
			}
		case domain.ActSeen:
			if err := see(ctx, q, org, a.Finding.ID, *a.Candidate, snap, at); err != nil {
				return nil, err
			}
		case domain.ActReopen, domain.ActExpire:
			if a.Candidate != nil {
				if err := see(ctx, q, org, a.Finding.ID, *a.Candidate, snap, at); err != nil {
					return nil, err
				}
			}
			kind := "REOPENED"
			if a.Kind == domain.ActExpire {
				kind = "EXPIRED"
			}
			if err := move(ctx, tx, a.Finding.ID, a.Finding.State, domain.Open, moveOpts{}, kind, System, "", &snap); err != nil {
				return nil, err
			}
		case domain.ActRemediate:
			if err := move(ctx, tx, a.Finding.ID, a.Finding.State, domain.Remediated, moveOpts{proof: &snap}, "REMEDIATED",
				System, "", &snap); err != nil {
				return nil, err
			}
		case domain.ActIncomplete:
			if err := move(ctx, tx, a.Finding.ID, a.Finding.State, domain.EvidenceIncomplete, moveOpts{}, "EVIDENCE_INCOMPLETE",
				System, "the recomputation could not read every path", &snap); err != nil {
				return nil, err
			}
		}
		if hook != nil {
			if err := hook.FindingChanged(ctx, tx, id, kind, a.Kind); err != nil {
				return nil, err
			}
		}
		sum[a.Kind]++
	}
	return sum, nil
}

func detailOf(c domain.Candidate) ([]byte, error) {
	if c.Detail == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(c.Detail)
}

func insert(ctx context.Context, q *dbq.Queries, org ids.OrgID, c domain.Candidate, snap ids.UUID, at time.Time) (dbq.PcPostureFinding, error) {
	detail, err := detailOf(c)
	if err != nil {
		return dbq.PcPostureFinding{}, err
	}
	return q.InsertPostureFinding(ctx, dbq.InsertPostureFindingParams{
		OrgID: org, ID: ids.NewV7(), Kind: string(c.Kind), RootCause: c.RootCause, AgentID: c.Agent, ConnectionID: c.Connection,
		GrantID: c.Grant, CoverageFindingID: c.CoverageFinding, Title: c.Title, Detail: detail, AffectedPaths: c.Paths, PathsTruncated: c.PathsTruncated,
		Severity: c.Severity, Fingerprint: c.Fingerprint(), SnapshotID: snap, SeenAt: at,
	})
}

func see(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, c domain.Candidate, snap ids.UUID, at time.Time) error {
	detail, err := detailOf(c)
	if err != nil {
		return err
	}
	_, err = q.SeePostureFinding(ctx, dbq.SeePostureFindingParams{
		OrgID: org, ID: id, Title: c.Title, Detail: detail, AffectedPaths: c.Paths, PathsTruncated: c.PathsTruncated, Severity: c.Severity, SnapshotID: snap,
		SeenAt: at, AgentID: c.Agent, ConnectionID: c.Connection, GrantID: c.Grant, CoverageFindingID: c.CoverageFinding,
	})
	return err
}

type moveOpts struct {
	owner  *ids.UUID
	until  *time.Time
	reason *string
	proof  *ids.UUID
}

// move changes a finding's state from from (conditional), adds the event
// and the ledger entry.
func move(ctx context.Context, tx db.TenantTx, id ids.UUID, from, to domain.State, o moveOpts, kind string,
	actor evdomain.Actor, note string, snap *ids.UUID,
) error {
	if !domain.CanMove(from, to) {
		return ErrTransition
	}
	_, err := dbq.New(tx).MovePostureFinding(ctx, dbq.MovePostureFindingParams{
		OrgID: tx.OrgID(), ID: id, FromState: string(from), ToState: string(to), OwnerUserID: o.owner,
		AcceptedUntil: o.until, AcceptedReason: o.reason, RemediatedSnapshotID: o.proof,
	})
	if db.IsNoRows(err) {
		return ErrTransition // the state changed under us
	} else if err != nil {
		return err
	}
	f := from
	if err := record(ctx, tx, id, kind, &f, to, actor, note, snap); err != nil {
		return err
	}
	details := map[string]string{"from": string(from), "to": string(to)}
	if o.owner != nil {
		details["owner"] = o.owner.String()
	}
	if o.until != nil {
		details["until"] = o.until.UTC().Format(time.RFC3339)
	}
	return auditMove(ctx, tx, id, kind, actor, note, details)
}

func record(ctx context.Context, tx db.TenantTx, id ids.UUID, kind string, from *domain.State, to domain.State,
	actor evdomain.Actor, note string, snap *ids.UUID,
) error {
	var fs, n *string
	if from != nil {
		s := string(*from)
		fs = &s
	}
	if note != "" {
		n = &note
	}
	if err := dbq.New(tx).InsertPostureFindingEvent(ctx, dbq.InsertPostureFindingEventParams{
		OrgID: tx.OrgID(), ID: ids.NewV7(), FindingID: id, Kind: kind, FromState: fs, ToState: string(to),
		Actor: actorString(actor), Note: n, SnapshotID: snap,
	}); err != nil {
		return err
	}
	body := map[string]string{"finding": id.String(), "event": kind, "to": string(to)}
	if fs != nil {
		body["from"] = *fs
	}
	if snap != nil {
		body["snapshot"] = snap.String()
	}
	b, err := evdomain.CanonicalBody(body)
	if err != nil {
		return err
	}
	_, err = ledger.Append(ctx, tx, LedgerKind, actor, b)
	return err
}

func actorString(a evdomain.Actor) string {
	s := a.Type + ":" + a.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// Get reads a finding.
func Get(ctx context.Context, tx db.TenantTx, id ids.UUID) (dbq.PcPostureFinding, error) {
	f, err := dbq.New(tx).GetPostureFinding(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return f, ErrNotFound
	}
	return f, err
}

// Assign gives an open finding an owner (OPEN or EVIDENCE_INCOMPLETE ->
// ASSIGNED).
func Assign(ctx context.Context, tx db.TenantTx, id, owner ids.UUID, actor evdomain.Actor) error {
	f, err := Get(ctx, tx, id)
	if err != nil {
		return err
	}
	return move(ctx, tx, id, domain.State(f.State), domain.Assigned, moveOpts{owner: &owner}, "ASSIGNED", actor, "", nil)
}

// StartTesting marks an assigned finding's fix under test.
func StartTesting(ctx context.Context, tx db.TenantTx, id ids.UUID, actor evdomain.Actor, note string) error {
	f, err := Get(ctx, tx, id)
	if err != nil {
		return err
	}
	return move(ctx, tx, id, domain.State(f.State), domain.Testing, moveOpts{}, "TESTING", actor, note, nil)
}

// Accept accepts an active finding for a while: a reason and an expiry
// within 90 days of the database's time (HR-255).
func Accept(ctx context.Context, tx db.TenantTx, id ids.UUID, until time.Time, reason string, actor evdomain.Actor) error {
	f, err := Get(ctx, tx, id)
	if err != nil {
		return err
	}
	now, err := dbq.New(tx).DBNow(ctx)
	if err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if err := domain.CheckAcceptance(now, until, reason); err != nil {
		return err
	}
	return move(ctx, tx, id, domain.State(f.State), domain.AcceptedTemporarily, moveOpts{until: &until, reason: &reason},
		"ACCEPTED", actor, reason, nil)
}

// MarkEvidenceIncomplete records that the evidence to decide an active
// finding is missing.
func MarkEvidenceIncomplete(ctx context.Context, tx db.TenantTx, id ids.UUID, note string, actor evdomain.Actor) error {
	f, err := Get(ctx, tx, id)
	if err != nil {
		return err
	}
	return move(ctx, tx, id, domain.State(f.State), domain.EvidenceIncomplete, moveOpts{}, "EVIDENCE_INCOMPLETE", actor, note, nil)
}

// Reopen puts a finding back in the queue.
func Reopen(ctx context.Context, tx db.TenantTx, id ids.UUID, note string, actor evdomain.Actor) error {
	f, err := Get(ctx, tx, id)
	if err != nil {
		return err
	}
	return move(ctx, tx, id, domain.State(f.State), domain.Open, moveOpts{}, "REOPENED", actor, note, nil)
}

// Note adds a note to a finding's history without changing it.
func Note(ctx context.Context, tx db.TenantTx, id ids.UUID, note string, actor evdomain.Actor) error {
	f, err := Get(ctx, tx, id)
	if err != nil {
		return err
	}
	if n := len([]rune(strings.TrimSpace(note))); n == 0 || n > 1000 {
		return errNote
	}
	if err := record(ctx, tx, id, "NOTE", nil, domain.State(f.State), actor, strings.TrimSpace(note), nil); err != nil {
		return err
	}
	return auditMove(ctx, tx, id, "NOTE", actor, note, map[string]string{"state": f.State})
}

// auditMove writes audit.posture.finding_<event> for a person's or a
// service account's change (D6, D63 M6): who, which finding, from and to,
// and the reason or note. A recomputation's own changes are the ledger's
// posture.finding entries and need no audit event.
func auditMove(ctx context.Context, tx db.TenantTx, id ids.UUID, kind string, actor evdomain.Actor, note string,
	details map[string]string,
) error {
	if actor == System {
		return nil
	}
	if note = strings.TrimSpace(note); note != "" {
		details["note"] = truncate(note, 500)
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "posture.finding_" + strings.ToLower(kind), Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "posture_finding", ID: id.String()}, Details: details,
	})
	return err
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
