// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect

import (
	"context"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Ceremony is internal/changes as the Gate's Requests (D6): protected
// changes and clearings are its requests, confirmed with security keys on
// /changes/{id}.
type Ceremony struct {
	Changes *changes.Service
}

// Open implements Requests.
func (c Ceremony) Open(ctx context.Context, tx db.TenantTx, r Request) (ids.UUID, error) {
	var content [32]byte
	copy(content[:], r.Digest)
	req, err := c.Changes.RequestTx(ctx, tx, r.By, changes.Requested{
		Domain: r.Domain, Kind: r.Kind, Subject: r.Subject, Content: content, Summary: r.Summary, Required: r.Required,
	})
	return req.ID, err
}

// Void implements Requests: it voids the pending request id (every pending
// request of its domain about its subject, which is the one request: a
// protected change or a compromise has its own subject).
func (c Ceremony) Void(ctx context.Context, tx db.TenantTx, id ids.UUID, reason string) error {
	r, err := dbq.New(tx).GetChangeRequest(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	if r.State != changes.StatePending {
		return nil
	}
	actor, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	_, err = c.Changes.Void(ctx, tx, actor, r.Domain, r.SubjectID, reason)
	return err
}

// Pending implements Requests.
func (c Ceremony) Pending(ctx context.Context, tx db.TenantTx, id ids.UUID) (bool, error) {
	r, err := dbq.New(tx).GetChangeRequest(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return r.State == changes.StatePending && !r.Expired, nil
}

// Register registers protect's change kinds with the ceremony: every
// category and SETTINGS (one distinct publisher), EMERGENCY_REVIEW (up to
// 72 hours, D74), and the CLEAR of a compromise (two other people). A
// protected change follows its request when the request ends unapplied
// (DECLINED, EXPIRED, VOIDED; D72 P2).
func Register(svc *changes.Service, g *Gate, p *Publishers) {
	one := func(context.Context, db.TenantTx, changes.Request) (int, error) { return 1, nil }
	h := changes.Handler{
		Permission:         td.PermProtectedChangeManage,
		DeclinePermissions: []td.Permission{td.PermProtectedChangeManage},
		Required:           one,
		Eligible: func(ctx context.Context, tx db.TenantTx, r changes.Request, user ids.UUID) (bool, string, error) {
			return g.Eligible(ctx, tx, r.ID, user)
		},
		Apply: func(ctx context.Context, tx db.TenantTx, r changes.Request, confirmers []ids.UUID) error {
			return g.Apply(ctx, tx, r.ID, confirmers)
		},
		Closed: func(ctx context.Context, tx db.TenantTx, r changes.Request, state string) error {
			return g.Closed(ctx, tx, r.ID, state, r.DecidedReason)
		},
	}
	for _, k := range append(categoryKinds(), KindSettings) {
		svc.Register(DomainProtected, k, h)
	}
	review := h
	review.TTL = changes.MaxTTL
	review.Closed = func(ctx context.Context, tx db.TenantTx, r changes.Request, state string) error {
		return g.ReviewClosed(ctx, tx, r.ID, state)
	}
	svc.Register(DomainProtected, KindEmergencyReview, review)
	svc.Register(DomainPublisher, KindClear, changes.Handler{
		Permission:         td.PermPublisherCompromise,
		DeclinePermissions: []td.Permission{td.PermPublisherCompromise},
		Required:           func(context.Context, db.TenantTx, changes.Request) (int, error) { return 2, nil },
		Eligible: func(ctx context.Context, tx db.TenantTx, r changes.Request, user ids.UUID) (bool, string, error) {
			return p.EligibleClear(ctx, tx, r.ID, user)
		},
		Apply: func(ctx context.Context, tx db.TenantTx, r changes.Request, confirmers []ids.UUID) error {
			return p.ApplyClear(ctx, tx, r.ID, confirmers)
		},
	})
}

func categoryKinds() []string {
	out := make([]string, 0, 4)
	for _, c := range Categories() {
		out = append(out, string(c))
	}
	return out
}

var reasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Closed moves a pending protected change to its request's end state
// (D72 P2): a declined, expired or voided request applies nothing, and its
// change can no longer be applied in an emergency.
func (g *Gate) Closed(ctx context.Context, tx db.TenantTx, request ids.UUID, state, reason string) error {
	switch state {
	case changes.StateDeclined, changes.StateExpired, changes.StateVoided:
	default:
		return nil
	}
	q := dbq.New(tx)
	row, err := q.GetProtectedChangeByRequest(ctx, tx.OrgID(), request)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	if row.State != StatePending || row.ChangeRequestID == nil || *row.ChangeRequestID != request {
		return nil
	}
	if !reasonPattern.MatchString(reason) {
		reason = state
	}
	_, err = q.DecideProtectedChange(ctx, dbq.DecideProtectedChangeParams{State: state, Reason: &reason, OrgID: tx.OrgID(), ID: row.ID})
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	if c := g.closers[Surface(row.Surface)]; c != nil && state != changes.StateVoided {
		return c(ctx, tx, row.Author, row.Payload)
	}
	return nil
}

// Closer runs in the closing transaction when a stored change of its
// surface is declined or expires (not when it is voided): an organization
// identity provider whose activation lapsed is disabled (G0 M18 D169).
type Closer func(ctx context.Context, tx db.TenantTx, author ids.UUID, payload []byte) error

// OnClose sets the Closer of a surface.
func (g *Gate) OnClose(s Surface, c Closer) {
	if g.closers == nil {
		g.closers = map[Surface]Closer{}
	}
	g.closers[s] = c
}

// reviewActor records an emergency review's end, which no person does.
var reviewActor = evdomain.Actor{Type: "system", ID: "protect"}

// KindReviewExpired is the owned failure of an emergency change whose
// review ended unconfirmed (D98 L3, D116 U2).
const KindReviewExpired = "protected_change.review_expired"

// Why an emergency review ended unconfirmed (D116 U2).
var reviewEndReasons = map[string]string{
	changes.StateExpired:  "review_expired",
	changes.StateDeclined: "review_declined",
	changes.StateVoided:   "review_voided",
}

// ReviewClosed handles an emergency review request that ended unconfirmed:
// it expired, was declined or was voided (D98 L3, D116 U2). The emergency
// change stays applied and nothing is undone: its review state becomes
// REVIEW_EXPIRED, the reason is recorded, and the person who applied it
// owns a protected_change.review_expired failure in the operations queue
// until someone opens a new review (OpenEmergencyReview).
func (g *Gate) ReviewClosed(ctx context.Context, tx db.TenantTx, request ids.UUID, state string) error {
	reason, ok := reviewEndReasons[state]
	if !ok {
		return nil
	}
	org := tx.OrgID()
	row, err := dbq.New(tx).ExpireEmergencyReview(ctx, org, request)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	publisher := uuidString(row.Publisher)
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "protected_change.review_expired", Actor: reviewActor, Outcome: audit.Success,
		Object: &audit.Object{Type: "protected_change", ID: row.ID.String()},
		Details: map[string]string{
			"category": row.Category, "subject": row.Subject, "applied_by": publisher, "review_request": request.String(),
			"reason": reason,
		},
	}); err != nil {
		return err
	}
	if g.Failures == nil {
		return nil
	}
	owner := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: publisher}
	_, _, err = g.Failures.ReportTx(ctx, tx, reflexdomain.Failure{
		Org:  org,
		Kind: KindReviewExpired,
		Summary: "The review of the emergency " + row.Category + " change to " + row.Subject +
			" ended unconfirmed (" + reason + "). The change stays applied.",
		NextStep: "A person holding " + string(Surface(row.Surface).Permission()) + " opens a new review of protected change " +
			row.ID.String() + "; a publisher other than its author and the person who applied it confirms it.",
		Owner:     &owner,
		Scope:     []reflexdomain.Subject{owner},
		DedupeKey: reviewFailureKey(row.ID),
	})
	return err
}

func reviewFailureKey(change ids.UUID) string { return KindReviewExpired + ":" + change.String() }

// failureResolver resolves owned failures through the failure sink's
// resolution path (reflex failures.Sink).
type failureResolver interface {
	Resolve(ctx context.Context, tx pgx.Tx, org ids.OrgID, kind string, keys []string, resolution string,
		actor evdomain.Actor) ([]ids.UUID, error)
}

// resolveReviewFailure resolves an emergency change's open
// protected_change.review_expired failure once a new review is opened or
// it is reviewed (D116 U3); a sink that cannot resolve leaves it open.
func (g *Gate) resolveReviewFailure(ctx context.Context, tx db.TenantTx, change ids.UUID, resolution string, actor evdomain.Actor) error {
	r, ok := g.Failures.(failureResolver)
	if !ok {
		return nil
	}
	_, err := r.Resolve(ctx, tx.Pgx(), tx.OrgID(), KindReviewExpired, []string{reviewFailureKey(change)}, resolution, actor)
	return err
}
