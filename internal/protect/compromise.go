// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Compromise states.
const (
	CompromiseActive  = "ACTIVE"
	CompromiseCleared = "CLEARED"
)

// Exposed item kinds (D43 ListExposed).
const (
	ItemPolicyVersion     = "POLICY_VERSION"
	ItemPolicyChange      = "POLICY_CHANGE"
	ItemPackageVersion    = "PACKAGE_VERSION"
	ItemPackageKey        = "PACKAGE_KEY"
	ItemAutomationVersion = "AUTOMATION_VERSION"
	ItemProtectedChange   = "PROTECTED_CHANGE"
	ItemPromotion         = "PROMOTION"
	ItemGrant             = "GRANT"
)

// Review decisions.
const (
	DecisionKeep     = "KEEP"
	DecisionRollback = "ROLLBACK"
)

// Errors.
var (
	ErrCompromised = pcerr.New(pcerr.PermissionDenied, "PUBLISHER_COMPROMISED",
		"this person is marked compromised and cannot confirm, approve, publish, activate or promote")
	ErrEdition = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED",
		"marking a compromised publisher needs the Business edition")
	ErrCompromiseNotFound = pcerr.New(pcerr.NotFound, "COMPROMISE_NOT_FOUND", "compromise not found")
	ErrCompromiseState    = pcerr.New(pcerr.FailedPrecondition, "COMPROMISE_STATE", "the compromise is cleared")
	ErrAlreadyMarked      = pcerr.New(pcerr.AlreadyExists, "PUBLISHER_ALREADY_MARKED", "this person is already marked compromised")
	ErrSelfReview         = pcerr.New(pcerr.PermissionDenied, "SAME_PERSON",
		"the compromised person cannot review or clear their own items")
	ErrNotExposed = pcerr.New(pcerr.NotFound, "ITEM_NOT_EXPOSED", "the item is not on this compromise's exposure list")
	ErrReviewed   = pcerr.New(pcerr.AlreadyExists, "ITEM_REVIEWED", "the item was already reviewed")
	ErrUnreviewed = pcerr.New(pcerr.FailedPrecondition, "EXPOSURE_UNREVIEWED", "every exposed item must be reviewed first")
	// ErrExposureTruncated: a source listed more than ExposureCap items, so
	// the exposure is not known in full and the mark is not cleared (D110 P5).
	ErrExposureTruncated = pcerr.New(pcerr.FailedPrecondition, "EXPOSURE_TRUNCATED",
		"the exposure list is truncated: a source has more items than it lists, so the mark cannot be cleared")
	ErrNoRollback  = pcerr.New(pcerr.Unimplemented, "ROLLBACK_UNAVAILABLE", "this kind of item cannot be rolled back here")
	ErrCompromiseQ = pcerr.New(pcerr.InvalidArgument, "COMPROMISE_INVALID",
		"a person, a time not in the future and a reason of 1 to 500 characters are required")
)

// Editions is the licence source.
type Editions interface {
	Current(ctx context.Context) (domain.Entitlements, error)
}

// OnCompromise runs in the marking transaction (D43): it voids the
// person's pending requests in one ceremony, pauses the automations whose
// ceiling they approved, halts the rollouts they confirmed. It returns
// counts for the audit record ("<what>": "<n>").
type OnCompromise func(ctx context.Context, tx db.TenantTx, user ids.UUID, since time.Time, by tenancy.Caller) (map[string]string, error)

// ExposureSource lists more of what a person published since a time (the
// automation versions they confirmed, the promotions they made).
type ExposureSource func(ctx context.Context, tx db.TenantTx, user ids.UUID, since time.Time) ([]Item, error)

// Rollback undoes one exposed item through its existing path (rollback,
// quarantine, pause, revoke) as the reviewer in ctx.
type Rollback func(ctx context.Context, id string) error

// Publishers is PublisherService's use cases (D43, HR-293), and the
// CompromiseChecker every confirmation path asks.
type Publishers struct {
	Pool     *db.Pool
	Gate     *Gate
	Editions Editions
	On       []OnCompromise
	Sources  map[string]ExposureSource
	Undo     map[string]Rollback
}

// Compromised reports whether user is marked compromised (D11's
// CompromiseChecker): a valid signature never exempts.
func (p *Publishers) Compromised(ctx context.Context, ptx pgx.Tx, org ids.OrgID, user ids.UUID) (bool, error) {
	tx, err := db.AdoptTenantTx(ctx, ptx, org)
	if err != nil {
		return false, err
	}
	return p.CompromisedTx(ctx, tx, user)
}

// CompromisedTx is Compromised in a tenant transaction.
func (p *Publishers) CompromisedTx(ctx context.Context, tx db.TenantTx, user ids.UUID) (bool, error) {
	return dbq.New(tx).UserCompromised(ctx, tx.OrgID(), user)
}

// Item is one exposed item and its review, if any.
type Item struct {
	Kind, ID, Label string
	At              time.Time
	Review          *dbq.PcCompromiseReview
}

// Compromise is a mark with its exposure.
type Compromise struct {
	dbq.PcCompromisedPublisher
	Items []Item
	// Truncated: a source listed more than ExposureCap items, so Items is
	// not everything and the mark cannot be cleared (D110 P5).
	Truncated bool
}

func (p *Publishers) caller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermPublisherCompromise, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHuman
	}
	// Every publisher use case needs the edition (D72 P11).
	return c, p.entitled(ctx)
}

func (p *Publishers) entitled(ctx context.Context) error {
	if p.Editions == nil {
		return ErrEdition
	}
	e, err := p.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.PublisherCompromise() {
		return ErrEdition
	}
	return nil
}

// MarkCompromised marks a person compromised from since (one person with
// publisher.compromise and a fresh step-up: it only narrows). In the same
// transaction their pending protected changes are voided and every
// OnCompromise hook runs (D43, HR-293).
func (p *Publishers) MarkCompromised(ctx context.Context, user ids.UUID, since time.Time, reason string, su stepup.StepUp) (dbq.PcCompromisedPublisher, error) {
	c, err := p.caller(ctx)
	if err != nil {
		return dbq.PcCompromisedPublisher{}, err
	}
	reason = strings.TrimSpace(reason)
	if user.IsZero() || since.IsZero() || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) < 1 || utf8.RuneCountInString(reason) > 500 {
		return dbq.PcCompromisedPublisher{}, ErrCompromiseQ
	}
	var out dbq.PcCompromisedPublisher
	err = p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, su, now); err != nil {
			return err
		}
		if since.After(now) {
			return ErrCompromiseQ
		}
		if _, err := q.GetUser(ctx, c.Org, user); db.IsNoRows(err) {
			return pcerr.New(pcerr.NotFound, "USER_NOT_FOUND", "user not found")
		} else if err != nil {
			return err
		}
		out, err = q.InsertCompromisedPublisher(ctx, dbq.InsertCompromisedPublisherParams{
			OrgID: c.Org, ID: ids.NewV7(), UserID: user, Since: since, Reason: reason, MarkedBy: c.Principal.ID,
			MarkedCredential: su.Credential,
		})
		if db.IsUniqueViolation(err) {
			return ErrAlreadyMarked
		} else if err != nil {
			return err
		}
		details := map[string]string{"user": user.String(), "since": since.UTC().Format(time.RFC3339)}
		voided, err := q.VoidPendingProtectedChangesBy(ctx, reasonCompromised, c.Org, user)
		if err != nil {
			return err
		}
		for _, v := range voided {
			if v.ChangeRequestID != nil && p.Gate != nil && p.Gate.Requests != nil {
				if err := p.Gate.Requests.Void(ctx, tx, *v.ChangeRequestID, reasonCompromised); err != nil {
					return err
				}
			}
		}
		details["protected_changes_voided"] = strconv.Itoa(len(voided))
		for _, on := range p.On {
			more, err := on(ctx, tx, user, since, c)
			if err != nil {
				return err
			}
			maps.Copy(details, more)
		}
		return p.record(ctx, tx, c, "publisher.compromised", out.ID, details)
	})
	return out, err
}

// Get returns a compromise with its exposure list and reviews
// (publisher.compromise).
func (p *Publishers) Get(ctx context.Context, id ids.UUID) (Compromise, error) {
	c, err := p.caller(ctx)
	if err != nil {
		return Compromise{}, err
	}
	var out Compromise
	err = p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = p.load(ctx, tx, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// List lists compromises, newest first (publisher.compromise).
func (p *Publishers) List(ctx context.Context, activeOnly bool, limit int) ([]dbq.PcCompromisedPublisher, error) {
	c, err := p.caller(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []dbq.PcCompromisedPublisher
	err = p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ListCompromisedPublishers(ctx, c.Org, activeOnly, int32(limit)) //nolint:gosec // G115: 1..200
		return err
	}, db.ReadOnly())
	return out, err
}

func (p *Publishers) load(ctx context.Context, tx db.TenantTx, id ids.UUID) (Compromise, error) {
	q := dbq.New(tx)
	row, err := q.GetCompromisedPublisher(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return Compromise{}, ErrCompromiseNotFound
	} else if err != nil {
		return Compromise{}, err
	}
	items, truncated, err := p.exposed(ctx, tx, row.UserID, row.Since)
	if err != nil {
		return Compromise{}, err
	}
	reviews, err := q.ListCompromiseReviews(ctx, tx.OrgID(), id)
	if err != nil {
		return Compromise{}, err
	}
	for i := range items {
		for j := range reviews {
			if reviews[j].ItemKind == items[i].Kind && reviews[j].ItemID == items[i].ID {
				items[i].Review = &reviews[j]
			}
		}
	}
	return Compromise{PcCompromisedPublisher: row, Items: items, Truncated: truncated}, nil
}

// ExposureCap is how many items one exposure source lists. Its query reads
// one more, so a source past the cap marks the list truncated, and a
// truncated list is never cleared (D110 P5, EXPOSURE_TRUNCATED).
const ExposureCap = 1000

// exposed lists what user published since a time (D43): policy versions
// they published, policy change requests they confirmed, package versions
// they activated (audit trail), org package keys they registered (revoke
// them COMPROMISED, F596), protected changes they published or reviewed,
// grants they issued, and every ExposureSource's items. truncated reports
// a source past ExposureCap.
func (p *Publishers) exposed(ctx context.Context, tx db.TenantTx, user ids.UUID, since time.Time) (out []Item, truncated bool, err error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	principal := td.PrincipalRef{Kind: td.KindUser, ID: user}.String()
	capped := func(n int) int {
		if n > ExposureCap {
			truncated = true
			return ExposureCap
		}
		return n
	}
	add := func(kind, id, label string, at time.Time) {
		out = append(out, Item{Kind: kind, ID: id, Label: label, At: at})
	}
	pv, err := q.ExposedPolicyVersions(ctx, org, principal, since)
	if err != nil {
		return nil, false, err
	}
	for _, r := range pv[:capped(len(pv))] {
		add(ItemPolicyVersion, r.ItemID, r.Label, deref(r.At))
	}
	pc, err := q.ExposedPolicyChanges(ctx, org, user, since)
	if err != nil {
		return nil, false, err
	}
	for _, r := range pc[:capped(len(pc))] {
		add(ItemPolicyChange, r.ItemID, r.Label, r.At)
	}
	pa, err := q.ExposedPackageActivations(ctx, org, user.String(), since)
	if err != nil {
		return nil, false, err
	}
	for _, r := range pa[:capped(len(pa))] {
		add(ItemPackageVersion, r.ItemID, r.Label, r.At)
	}
	pk, err := q.ExposedPackageKeys(ctx, org, principal, since)
	if err != nil {
		return nil, false, err
	}
	for _, r := range pk[:capped(len(pk))] {
		add(ItemPackageKey, r.ItemID, r.Label, r.At)
	}
	ch, err := q.ExposedProtectedChanges(ctx, org, since, user)
	if err != nil {
		return nil, false, err
	}
	for _, r := range ch[:capped(len(ch))] {
		add(ItemProtectedChange, r.ItemID, r.Label, r.At)
	}
	gs, err := q.ExposedGrants(ctx, org, user, since)
	if err != nil {
		return nil, false, err
	}
	for _, r := range gs[:capped(len(gs))] {
		add(ItemGrant, r.ItemID, r.Label, r.At)
	}
	for _, kind := range slices.Sorted(maps.Keys(p.Sources)) {
		more, err := p.Sources[kind](ctx, tx, user, since)
		if err != nil {
			return nil, false, err
		}
		out = append(out, more[:capped(len(more))]...)
	}
	slices.SortStableFunc(out, func(a, b Item) int { return a.At.Compare(b.At) })
	return out, truncated, nil
}

// ReviewExposed records an independent KEEP or ROLLBACK decision on one
// exposed item (publisher.compromise; anyone but the compromised person,
// the marker included). ROLLBACK first undoes the item through its
// existing path as the reviewer.
func (p *Publishers) ReviewExposed(ctx context.Context, id ids.UUID, kind, item, decision, note string) (Item, error) {
	c, err := p.caller(ctx)
	if err != nil {
		return Item{}, err
	}
	if decision != DecisionKeep && decision != DecisionRollback {
		return Item{}, ErrInvalid
	}
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > 500 || !utf8.ValidString(note) {
		return Item{}, ErrInvalid
	}
	var target Item
	err = p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		cp, err := p.load(ctx, tx, id)
		if err != nil {
			return err
		}
		// A reviewer under any active mark reviews nothing (D72 P9).
		if err := (&Gate{Compromise: p}).refuseCompromised(ctx, tx, c.Principal.ID); err != nil {
			return err
		}
		return p.reviewable(c, cp, kind, item, &target)
	}, db.ReadOnly())
	if err != nil {
		return Item{}, err
	}
	if decision == DecisionRollback {
		undo, ok := p.Undo[kind]
		if !ok {
			return Item{}, ErrNoRollback
		}
		if err := undo(ctx, item); err != nil {
			return Item{}, err
		}
	}
	err = p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cp, err := q.LockCompromisedPublisher(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if cp.State != CompromiseActive {
			return ErrCompromiseState
		}
		var n *string
		if note != "" {
			n = &note
		}
		inserted, err := q.InsertCompromiseReview(ctx, dbq.InsertCompromiseReviewParams{
			OrgID: c.Org, CompromiseID: id, ItemKind: kind, ItemID: item, Decision: decision, Reviewer: c.Principal.ID, Note: n,
		})
		if err != nil {
			return err
		}
		if inserted != 1 {
			return ErrReviewed
		}
		return p.record(ctx, tx, c, "publisher.exposure_reviewed", id, map[string]string{
			"item_kind": kind, "item": item, "decision": decision, "user": cp.UserID.String(),
		})
	})
	if err != nil {
		return Item{}, err
	}
	target.Review = &dbq.PcCompromiseReview{
		OrgID: c.Org, CompromiseID: id, ItemKind: kind, ItemID: item, Decision: decision, Reviewer: c.Principal.ID,
	}
	return target, nil
}

func (p *Publishers) reviewable(c tenancy.Caller, cp Compromise, kind, item string, target *Item) error {
	switch {
	case cp.State != CompromiseActive:
		return ErrCompromiseState
	case cp.UserID == c.Principal.ID:
		return ErrSelfReview
	}
	i := slices.IndexFunc(cp.Items, func(x Item) bool { return x.Kind == kind && x.ID == item })
	if i < 0 {
		return ErrNotExposed
	}
	if cp.Items[i].Review != nil {
		return ErrReviewed
	}
	*target = cp.Items[i]
	return nil
}

// ClearCompromise asks for a mark to be cleared (publisher.compromise; not
// the compromised person): only once every exposed item is reviewed, and
// it applies when two other people confirm its change request (domain
// publisher, kind CLEAR).
func (p *Publishers) ClearCompromise(ctx context.Context, id ids.UUID) (ids.UUID, error) {
	c, err := p.caller(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if p.Gate == nil || p.Gate.Requests == nil {
		return ids.UUID{}, ErrUnavailable
	}
	var req ids.UUID
	err = p.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.LockCompromisedPublisher(ctx, c.Org, id); db.IsNoRows(err) {
			return ErrCompromiseNotFound
		} else if err != nil {
			return err
		}
		cp, err := p.load(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := (&Gate{Compromise: p}).refuseCompromised(ctx, tx, c.Principal.ID); err != nil {
			return err
		}
		switch {
		case cp.State != CompromiseActive:
			return ErrCompromiseState
		case cp.UserID == c.Principal.ID:
			return ErrSelfReview
		case cp.Truncated:
			return ErrExposureTruncated
		case slices.ContainsFunc(cp.Items, func(i Item) bool { return i.Review == nil }):
			return ErrUnreviewed
		}
		if cp.ClearRequestID != nil {
			if err := p.Gate.Requests.Void(ctx, tx, *cp.ClearRequestID, reasonSuperseded); err != nil {
				return err
			}
		}
		req, err = p.Gate.Requests.Open(ctx, tx, Request{
			Domain: DomainPublisher, Kind: KindClear, Subject: id, Digest: clearDigest(cp), Required: 2, By: c,
			Summary: map[string]string{
				"user": cp.UserID.String(), "since": cp.Since.UTC().Format(time.RFC3339), "items": strconv.Itoa(len(cp.Items)),
			},
		})
		if err != nil {
			return err
		}
		if err := one(q.SetCompromiseClearRequest(ctx, req, c.Org, id)); err != nil {
			return err
		}
		return p.record(ctx, tx, c, "publisher.clear_requested", id, map[string]string{
			"user": cp.UserID.String(), "change_request": req.String(),
		})
	})
	return req, err
}

// EligibleClear is the CLEAR request's Eligible: publisher.compromise, not
// the compromised person, not compromised themself.
func (p *Publishers) EligibleClear(ctx context.Context, tx db.TenantTx, request, user ids.UUID) (bool, string, error) {
	cp, err := dbq.New(tx).CompromiseOfClearRequest(ctx, tx.OrgID(), request)
	if db.IsNoRows(err) {
		return false, "NOT_FOUND", nil
	} else if err != nil {
		return false, "", err
	}
	if cp.UserID == user {
		return false, "SAME_PERSON", nil
	}
	// The mark itself is the compromise source of truth here.
	return (&Gate{Compromise: p}).eligiblePerson(ctx, tx, user, td.PermPublisherCompromise)
}

// ApplyClear clears the mark in the confirming transaction, if every item
// is still reviewed.
func (p *Publishers) ApplyClear(ctx context.Context, tx db.TenantTx, request ids.UUID, confirmers []ids.UUID) error {
	q := dbq.New(tx)
	row, err := q.CompromiseOfClearRequest(ctx, tx.OrgID(), request)
	if db.IsNoRows(err) {
		return ErrCompromiseNotFound
	} else if err != nil {
		return err
	}
	cp, err := p.load(ctx, tx, row.ID)
	if err != nil {
		return err
	}
	if cp.Truncated {
		return ErrExposureTruncated
	}
	if slices.ContainsFunc(cp.Items, func(i Item) bool { return i.Review == nil }) {
		return ErrUnreviewed
	}
	if err := one(q.ClearCompromisedPublisher(ctx, tx.OrgID(), row.ID)); err != nil {
		return ErrCompromiseState
	}
	by := make([]string, len(confirmers))
	for i, u := range confirmers {
		by[i] = u.String()
	}
	actor := tenancy.Caller{Subject: td.Subject{Org: tx.OrgID(), Principal: td.PrincipalRef{Kind: td.KindUser, ID: confirmers[0]}}}
	return p.record(ctx, tx, actor, "publisher.cleared", row.ID, map[string]string{
		"user": row.UserID.String(), "confirmed_by": strings.Join(by, ","),
	})
}

// clearDigest binds a CLEAR request to the reviewed exposure.
func clearDigest(cp Compromise) []byte {
	var b strings.Builder
	b.WriteString(cp.ID.String())
	for _, i := range cp.Items {
		b.WriteString("\x00" + i.Kind + "\x00" + i.ID)
		if i.Review != nil {
			b.WriteString("\x00" + i.Review.Decision + "\x00" + i.Review.Reviewer.String())
		}
	}
	sum := sha256Sum([]byte(b.String()))
	return sum[:]
}

func (p *Publishers) record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "compromised_publisher", ID: id.String()}, Details: details,
	})
	return err
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// ROLLBACK refusals (D72 P1).
var (
	ErrRollbackNotYet = pcerr.New(pcerr.Unimplemented, "NOT_YET_AVAILABLE",
		"rolling back this kind of item is not available yet: review it KEEP or come back once it is")
	ErrRollbackNotCurrent = pcerr.New(pcerr.FailedPrecondition, "ROLLBACK_NOT_CURRENT",
		"the version is no longer the published one, so there is nothing to roll back")
	ErrRollbackNoEarlier = pcerr.New(pcerr.FailedPrecondition, "ROLLBACK_NO_EARLIER",
		"no version was published before this one to roll back to")
)

// ErrKeepOnly: the kind has no undo of its own (a policy change request
// is already voided by the mark; a protected change's effect is undone by
// a new change), so it is reviewed KEEP (D90 Q2).
var ErrKeepOnly = pcerr.New(pcerr.FailedPrecondition, "KEEP_ONLY",
	"this kind of item is reviewed KEEP: undo its effect with a new change if needed")

// RollbackPending is a ROLLBACK that opened a change request instead of
// applying (a loosening policy rollback, D90 Q1): nothing is recorded, and
// the reviewer records ROLLBACK again once the request is confirmed.
func RollbackPending(request ids.UUID) error {
	return pcerr.New(pcerr.FailedPrecondition, "ROLLBACK_PENDING_CONFIRMATION",
		"the rollback waits for its change request "+request.String()+" to be confirmed; review ROLLBACK again once it applies")
}

// PromotionRevoker revokes an agent's promotion (govern's
// RevokePromotion), as the reviewer in ctx.
type PromotionRevoker interface {
	RevokePromotion(ctx context.Context, id ids.UUID, reason string) error
}

// PromotionUndo is the ROLLBACK of an exposed promotion through r.
func PromotionUndo(r PromotionRevoker) Rollback {
	return func(ctx context.Context, item string) error {
		id, err := ids.ParseUUID(item)
		if err != nil {
			return ErrNotExposed
		}
		return r.RevokePromotion(ctx, id, ReasonCompromisedPublisher)
	}
}

// ReasonCompromisedPublisher is the reason recorded by undoing an item of
// a compromised publisher.
const ReasonCompromisedPublisher = "PUBLISHER_COMPROMISED"
