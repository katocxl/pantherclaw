// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Ledger kinds of coverage (HR-217, design decision 17).
const (
	LedgerKind             = "coverage.snapshot"
	InvalidationLedgerKind = "coverage.invalidation"
)

// Actor is who records the snapshots coverage computes itself.
var Actor = evdomain.Actor{Type: "system", ID: "coverage-reassess"}

// EntryScope is a scope as the ledger names it.
type EntryScope struct {
	Agent      string `json:"agent"`
	Connection string `json:"connection"`
	Operation  string `json:"operation"`
}

// Entry is the ledger body of a coverage snapshot: what a receipt's
// coverage claim is checked against (HR-217). The full record stays in
// the snapshot row; routes_digest binds its routes to the entry. Ids are
// canonical UUID strings, as receipts and pclaw verify name them.
type Entry struct {
	V            int        `json:"v"`
	Scope        EntryScope `json:"scope"`
	State        string     `json:"state"`
	Snapshot     string     `json:"snapshot"`
	ComputedAt   string     `json:"computed_at"`
	ExpiresAt    string     `json:"expires_at,omitzero"`
	Exclusions   []string   `json:"exclusions"`
	RoutesDigest string     `json:"routes_digest"`
	Closure      string     `json:"closure,omitzero"`
}

// InvalidationEntry is the ledger body of a coverage invalidation, which
// a lapsed claim names as its reason; ids are canonical UUID strings.
type InvalidationEntry struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	Connection string `json:"connection"`
	Agent      string `json:"agent,omitzero"`
	Kind       string `json:"kind"`
	Subject    string `json:"subject,omitzero"`
	OccurredAt string `json:"occurred_at"`
}

// Snapshot is the computed record of one scope, kept as the snapshot
// row's body; its ledger entry is the Entry made from it. Ids are
// canonical UUID strings, like the ledger's.
type Snapshot struct {
	V          int             `json:"v"`
	ID         string          `json:"id"`
	Agent      string          `json:"agent"`
	Connection string          `json:"connection"`
	Operation  string          `json:"operation"`
	State      string          `json:"state"`
	Reasons    []string        `json:"reasons"`
	Routes     []SnapshotRoute `json:"routes"`
	Closure    string          `json:"closure,omitzero"`
	ExpiresAt  string          `json:"expires_at,omitzero"`
	Excluded   bool            `json:"excluded,omitzero"`
	Exclusions []string        `json:"exclusions,omitzero"`
	// LastValid is the last ENFORCED snapshot a downgrade follows (F442);
	// Cause the invalidation that asked for this reassessment.
	LastValid  string `json:"last_valid,omitzero"`
	Cause      string `json:"cause,omitzero"`
	ComputedAt string `json:"computed_at"`
	// Seen are the scope's pending changes this computation read (HR-211):
	// a claim on the snapshot lapses on a change it did not see, or on one
	// at or after its computation, as pclaw verify checks it.
	Seen []string `json:"seen,omitzero"`
}

// SnapshotRoute is one route of a snapshot. routes_digest is the SHA-256
// of the canonical (JCS) {"routes": [...]} of these, ids as canonical UUID
// strings, so anyone holding the exported routes can recompute it.
type SnapshotRoute struct {
	Kind    string `json:"kind"`
	Channel string `json:"channel,omitzero"`
	Locator string `json:"locator,omitzero"`
	Route   string `json:"route,omitzero"`
	Status  string `json:"status"`
	Closure string `json:"closure,omitzero"`
}

// same reports whether two snapshots record the same coverage, whatever
// caused them and when.
func (s Snapshot) same(o Snapshot) bool {
	s.ID, o.ID, s.Cause, o.Cause, s.ComputedAt, o.ComputedAt, s.Seen, o.Seen = "", "", "", "", "", "", nil, nil
	a, errA := json.Marshal(s)
	b, errB := json.Marshal(o)
	return errA == nil && errB == nil && string(a) == string(b)
}

func optID(id ids.UUID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}

func snapshotOf(sc domain.Scope, r domain.Result, exclusions []domain.Exclusion) Snapshot {
	s := Snapshot{
		V: 1, Agent: sc.Agent.String(), Connection: sc.Connection.String(), Operation: sc.Operation, State: r.State.String(),
		Reasons: slices.Clone(r.Reasons), Closure: optString(r.Closure), Excluded: r.Excluded, Routes: []SnapshotRoute{},
	}
	if s.Reasons == nil {
		s.Reasons = []string{}
	}
	if r.ExpiresAt != nil {
		s.ExpiresAt = evdomain.Timestamp(*r.ExpiresAt)
	}
	for _, x := range exclusions {
		s.Exclusions = append(s.Exclusions, x.ID.String())
	}
	s.Routes = append(s.Routes, RoutesOf(r)...)
	return s
}

// reassess computes one scope's coverage and, when it differs from the
// scope's current snapshot, records a new snapshot: a ledger entry and its
// row, in tx. It reports whether it recorded one.
func (s *Service) reassess(ctx context.Context, tx db.TenantTx, sc domain.Scope, cause *ids.UUID, actor evdomain.Actor,
	pkgs packages,
) (bool, error) {
	q := dbq.New(tx)
	if err := q.LockCoverageScope(ctx, tx.OrgID().UUID(), sc.Agent, sc.Connection); err != nil {
		return false, err
	}
	now := s.now()
	e, err := s.evidence(ctx, tx, sc, now, pkgs)
	if err != nil {
		return false, err
	}
	r := domain.Compute(e)
	next := snapshotOf(sc, r, e.Exclusions)
	seen, err := q.CoverageChangesPending(ctx, tx.OrgID(), sc.Connection, &sc.Agent)
	if err != nil {
		return false, err
	}
	for _, ch := range seen {
		next.Seen = append(next.Seen, ch.ID.String())
	}
	current, err := q.CurrentCoverageSnapshot(ctx, dbq.CurrentCoverageSnapshotParams{
		OrgID: tx.OrgID(), AgentID: sc.Agent, ConnectionID: sc.Connection, Operation: sc.Operation,
	})
	var lastValid *ids.UUID
	switch {
	case err == nil:
		var prev Snapshot
		if err := json.Unmarshal(current.Body, &prev); err != nil {
			return false, err
		}
		if r.State != domain.Enforced {
			if current.State == domain.Enforced.String() {
				lastValid = &current.ID
			} else {
				lastValid = current.LastValidID
			}
			next.LastValid = optString(lastValid)
		}
		// A change always records a snapshot, even an unchanged one: a claim
		// on a snapshot computed before a change has lapsed, so a claim that
		// did not must name one computed after it (HR-217).
		if prev.same(next) && cause == nil {
			return false, nil
		}
	case !db.IsNoRows(err):
		return false, err
	}
	id := ids.NewV7()
	next.ID, next.Cause, next.ComputedAt = id.String(), optString(cause), evdomain.Timestamp(now)
	body, err := evdomain.CanonicalBody(next)
	if err != nil {
		return false, err
	}
	entryBody, err := entryOf(next)
	if err != nil {
		return false, err
	}
	entry, err := ledger.Append(ctx, tx, LedgerKind, actor, entryBody)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(entryBody)
	_, err = q.InsertCoverageSnapshot(ctx, dbq.InsertCoverageSnapshotParams{
		OrgID: tx.OrgID(), ID: id, AgentID: sc.Agent, ConnectionID: sc.Connection, Operation: sc.Operation,
		State: r.State.String(), Reasons: next.Reasons, ClosureID: r.Closure, LastValidID: lastValid,
		InvalidationID: cause, Body: body, BodySha256: digest[:], LedgerEntryID: entry.ID, ExpiresAt: r.ExpiresAt,
		ComputedAt: now.Truncate(time.Microsecond),
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// entryOf is the canonical ledger body of a snapshot (HR-217): its scope,
// state, times, exclusions and closure, and the SHA-256 of the canonical
// {"routes": [...]} of its record.
func entryOf(s Snapshot) ([]byte, error) {
	routes, err := evdomain.CanonicalBody(struct {
		Routes []SnapshotRoute `json:"routes"`
	}{s.Routes})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(routes)
	e := Entry{
		V: 1, Scope: EntryScope{Agent: s.Agent, Connection: s.Connection, Operation: s.Operation}, State: s.State,
		Snapshot: s.ID, ComputedAt: s.ComputedAt, ExpiresAt: s.ExpiresAt, Exclusions: s.Exclusions,
		RoutesDigest: "sha256:" + hex.EncodeToString(digest[:]), Closure: s.Closure,
	}
	if e.Exclusions == nil {
		e.Exclusions = []string{}
	}
	return evdomain.CanonicalBody(e)
}

// optString returns id as a canonical UUID string, or "" when nil.
func optString(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// RoutesOf is a computed result's routes as a snapshot records them.
func RoutesOf(r domain.Result) []SnapshotRoute {
	out := make([]SnapshotRoute, 0, len(r.Routes))
	for _, rt := range r.Routes {
		out = append(out, SnapshotRoute{
			Kind: string(rt.Kind), Channel: string(rt.Channel), Locator: rt.Locator, Route: optID(rt.Route),
			Status: string(rt.Status), Closure: optID(rt.Closure),
		})
	}
	return out
}
