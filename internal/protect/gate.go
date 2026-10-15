// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"maps"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Change states.
const (
	StatePending   = "PENDING"
	StateApplied   = "APPLIED"
	StateEmergency = "EMERGENCY"
	StateDeclined  = "DECLINED"
	StateExpired   = "EXPIRED"
	StateVoided    = "VOIDED"
)

// Void reasons.
const (
	reasonSuperseded  = "SUPERSEDED"
	reasonCompromised = "AUTHOR_COMPROMISED"
	reasonEmergency   = "EMERGENCY"
)

// Request is a change request the Gate opens (internal/changes, D6).
type Request struct {
	Domain, Kind string
	// Subject is the stored protected change (or, for a CLEAR, the
	// compromise).
	Subject  ids.UUID
	Digest   []byte
	Summary  map[string]string
	Required int
	// By is the requester (a person).
	By tenancy.Caller
}

// Requests opens and voids change requests: internal/changes's BINDING
// ceremony (D6). Without it no protected change can be requested, so a
// category that is on refuses its changes (ErrUnavailable).
type Requests interface {
	Open(ctx context.Context, tx db.TenantTx, r Request) (ids.UUID, error)
	Void(ctx context.Context, tx db.TenantTx, id ids.UUID, reason string) error
}

// Checker reports whether a person is marked compromised (D11's
// CompromiseChecker as protect reads it).
type Checker interface {
	CompromisedTx(ctx context.Context, tx db.TenantTx, user ids.UUID) (bool, error)
}

// Gate holds widening changes of protected categories for a distinct
// publisher (D42). A nil *Gate protects nothing: every change applies as
// it did before protected changes existed.
type Gate struct {
	Requests   Requests
	Compromise Checker
	appliers   map[Surface]Applier
}

// Register sets the Applier that re-runs a surface's stored changes.
func (g *Gate) Register(s Surface, a Applier) {
	if g.appliers == nil {
		g.appliers = map[Surface]Applier{}
	}
	g.appliers[s] = a
}

// Hold applies c through apply when its category is OFF (or ctx is the
// confirmed re-run of this change) and returns nil. With the category on it
// stores c PENDING with a change request instead, without calling apply,
// and returns the PendingError the surface reports once its transaction
// commits. fallback is a second category that protects the same change
// (package activation is TOOL_MEANING and CONSEQUENCE_RULES, D42a (2));
// the first one that is on names the request.
func (g *Gate) Hold(ctx context.Context, tx db.TenantTx, author tenancy.Caller, c Change, apply func(context.Context) error, fallback ...Category) (*PendingError, error) {
	if g == nil {
		return nil, apply(ctx)
	}
	if c.SubjectID.IsZero() {
		c.SubjectID = SubjectID(c.Surface, c.Subject)
	}
	if isApplying(ctx, c.Surface, c.SubjectID) {
		return nil, apply(ctx)
	}
	q := dbq.New(tx)
	on := false
	for _, cat := range append([]Category{c.Category}, fallback...) {
		mode, err := q.ProtectedCategoryMode(ctx, tx.OrgID(), string(cat))
		if err != nil {
			return nil, err
		}
		if Mode(mode) == ModeDistinctPublisher {
			c.Category, on = cat, true
			break
		}
	}
	if !on {
		return nil, apply(ctx)
	}
	return g.store(ctx, tx, author, c, StatePending)
}

// store records c and opens its change request.
func (g *Gate) store(ctx context.Context, tx db.TenantTx, author tenancy.Caller, c Change, state string) (*PendingError, error) {
	if !author.Human() {
		return nil, ErrHuman
	}
	if g.Requests == nil {
		return nil, ErrUnavailable
	}
	if !c.Category.Valid() || c.Subject == "" || len(c.Widening) == 0 || c.Surface.Permission() == "" {
		return nil, ErrInvalid
	}
	payload, err := json.Marshal(c.Payload, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("protect: payload: %w", err)
	}
	if c.SubjectID.IsZero() {
		c.SubjectID = SubjectID(c.Surface, c.Subject)
	}
	sum, err := digest(tx.OrgID(), c, payload)
	if err != nil {
		return nil, err
	}
	summary := maps.Clone(c.Summary)
	if summary == nil {
		summary = map[string]string{}
	}
	summary["surface"], summary["subject"], summary["widening"] = string(c.Surface), c.Subject, strings.Join(c.Widening, ",")
	summary["author"] = author.Principal.String()
	sb, err := json.Marshal(summary, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	// A newer change for the same subject replaces the older pending one
	// (D42a (3)).
	older, err := q.VoidPendingProtectedChanges(ctx, dbq.VoidPendingProtectedChangesParams{
		Reason: reasonSuperseded, OrgID: org, Surface: string(c.Surface), SubjectID: c.SubjectID,
	})
	if err != nil {
		return nil, err
	}
	for _, o := range older {
		if o.ChangeRequestID != nil {
			if err := g.Requests.Void(ctx, tx, *o.ChangeRequestID, reasonSuperseded); err != nil {
				return nil, err
			}
		}
	}
	row, err := q.InsertProtectedChange(ctx, dbq.InsertProtectedChangeParams{
		OrgID: org, ID: ids.NewV7(), Category: string(c.Category), Surface: string(c.Surface), SubjectID: c.SubjectID,
		Subject: c.Subject, Summary: sb, Widening: c.Widening, Digest: sum, Payload: payload, Author: author.Principal.ID,
		AuthorCredential: string(author.Credential), State: state,
	})
	if err != nil {
		return nil, err
	}
	kind := string(c.Category)
	if c.Surface == SurfaceSettings {
		kind = KindSettings
	}
	req, err := g.Requests.Open(ctx, tx, Request{
		Domain: DomainProtected, Kind: kind, Subject: row.ID, Digest: sum, Summary: summary, Required: 1, By: author,
	})
	if err != nil {
		return nil, err
	}
	if err := one(q.SetProtectedChangeRequest(ctx, req, org, row.ID)); err != nil {
		return nil, err
	}
	if err := record(ctx, tx, author, "protected_change.requested", row.ID, map[string]string{
		"category": string(c.Category), "surface": string(c.Surface), "subject": c.Subject,
		"widening": strings.Join(c.Widening, ","), "change_request": req.String(),
	}); err != nil {
		return nil, err
	}
	return &PendingError{Change: row.ID, Request: req}, nil
}

// Eligible reports whether user may confirm the protected change of a
// request (the change ceremony's Eligible, D42a (1)): a different person
// from its author, holding the surface's permission at the org, not marked
// compromised. An emergency review needs someone other than the person who
// applied it.
func (g *Gate) Eligible(ctx context.Context, tx db.TenantTx, request, user ids.UUID) (bool, string, error) {
	q := dbq.New(tx)
	row, err := q.GetProtectedChangeByRequest(ctx, tx.OrgID(), request)
	if db.IsNoRows(err) {
		return false, "NOT_FOUND", nil
	} else if err != nil {
		return false, "", err
	}
	review := row.ReviewRequestID != nil && *row.ReviewRequestID == request
	switch {
	case !review && row.Author == user:
		return false, "SAME_PERSON", nil
	case review && row.Publisher != nil && *row.Publisher == user:
		return false, "SAME_PERSON", nil
	}
	return g.eligiblePerson(ctx, tx, user, Surface(row.Surface).Permission())
}

func (g *Gate) eligiblePerson(ctx context.Context, tx db.TenantTx, user ids.UUID, p td.Permission) (bool, string, error) {
	s, err := personSubject(ctx, tx, user)
	if err != nil {
		return false, "", err
	}
	if s == nil {
		return false, "NOT_ACTIVE", nil
	}
	if !s.Can(p, td.OrgPath(tx.OrgID())) {
		return false, "MISSING_PERMISSION", nil
	}
	if g.Compromise != nil {
		bad, err := g.Compromise.CompromisedTx(ctx, tx, user)
		if err != nil {
			return false, "", err
		}
		if bad {
			return false, "COMPROMISED", nil
		}
	}
	return true, "", nil
}

// Apply runs the confirmed change of a request in the confirming
// transaction (the change ceremony's Apply): the surface's code again, as
// the author, who must still hold its permission; an error fails the
// confirmation (D42a (3)). Confirming an emergency review records it.
func (g *Gate) Apply(ctx context.Context, tx db.TenantTx, request ids.UUID, confirmers []ids.UUID) error {
	if len(confirmers) == 0 {
		return ErrInvalid
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	row, err := q.ProtectedChangeOfRequest(ctx, org, request)
	if db.IsNoRows(err) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	publisher := confirmers[0]
	actor := tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: publisher}}}
	if row.ReviewRequestID != nil && *row.ReviewRequestID == request {
		if err := one(q.ReviewEmergencyChange(ctx, publisher, org, row.ID)); err != nil {
			return ErrState
		}
		return record(ctx, tx, actor, "protected_change.emergency_reviewed", row.ID, map[string]string{
			"category": row.Category, "subject": row.Subject, "applied_by": uuidString(row.Publisher),
		})
	}
	if row.State != StatePending || row.Author == publisher {
		return ErrState
	}
	if err := g.run(ctx, tx, row); err != nil {
		return err
	}
	p := publisher
	if _, err := q.DecideProtectedChange(ctx, dbq.DecideProtectedChangeParams{
		State: StateApplied, Publisher: &p, OrgID: org, ID: row.ID,
	}); err != nil {
		return err
	}
	return record(ctx, tx, actor, "protected_change.applied", row.ID, map[string]string{
		"category": row.Category, "surface": row.Surface, "subject": row.Subject,
		"author": row.Author.String(), "publisher": publisher.String(),
	})
}

// run re-runs a stored change as its author.
func (g *Gate) run(ctx context.Context, tx db.TenantTx, row dbq.PcProtectedChange) error {
	if Surface(row.Surface) == SurfaceSettings {
		var s struct {
			Category Category `json:"category"`
		}
		if err := json.Unmarshal(row.Payload, &s); err != nil || !s.Category.Valid() {
			return ErrInvalid
		}
		return dbq.New(tx).SetProtectedCategoryMode(ctx, dbq.SetProtectedCategoryModeParams{
			OrgID: tx.OrgID(), Category: string(s.Category), Mode: string(ModeOff), UpdatedBy: row.Author,
		})
	}
	a, ok := g.appliers[Surface(row.Surface)]
	if !ok {
		return ErrUnavailable
	}
	s, err := personSubject(ctx, tx, row.Author)
	if err != nil {
		return err
	}
	if s == nil {
		return pcerr.New(pcerr.FailedPrecondition, "AUTHOR_NOT_ACTIVE", "the change's author is no longer an active person")
	}
	author := tenancy.Caller{Subject: *s, Credential: tenancy.Credential(row.AuthorCredential)}
	return a(applying(ctx, Surface(row.Surface), row.SubjectID), tx, author, row.Payload)
}

// personSubject loads an active person's current bindings, or nil.
func personSubject(ctx context.Context, tx db.TenantTx, user ids.UUID) (*td.Subject, error) {
	q := dbq.New(tx)
	u, err := q.GetUser(ctx, tx.OrgID(), user)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if u.State != "ACTIVE" {
		return nil, nil
	}
	p := td.PrincipalRef{Kind: td.KindUser, ID: user}
	b, err := tenancy.Bindings(ctx, q, tx.OrgID(), p)
	if err != nil {
		return nil, err
	}
	return &td.Subject{Org: tx.OrgID(), Principal: p, Bindings: b}, nil
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "protected_change", ID: id.String()}, Details: details,
	})
	return err
}

func uuidString(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// one returns db.ErrNoRows-like ErrState unless exactly one row changed.
func one(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	return nil
}
