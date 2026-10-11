// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package retention

import (
	"context"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the retention use cases.
var (
	ErrHumanOnly     = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrCategory      = pcerr.New(pcerr.InvalidArgument, "INVALID_CATEGORY", "unknown retention category")
	ErrDays          = pcerr.New(pcerr.InvalidArgument, "INVALID_RETENTION_DAYS", "the days are outside the category's bounds")
	ErrHoldScope     = pcerr.New(pcerr.InvalidArgument, "INVALID_HOLD_SCOPE", "a hold covers the org, an agent, a run, a transaction or a time range")
	ErrHoldRange     = pcerr.New(pcerr.InvalidArgument, "INVALID_HOLD_RANGE", "a time range starts before it ends")
	ErrReason        = pcerr.New(pcerr.InvalidArgument, "INVALID_REASON", "a reason of 1 to 2000 characters is required")
	ErrScopeNotFound = pcerr.New(pcerr.NotFound, "HOLD_SCOPE_NOT_FOUND", "the agent, run or transaction was not found")
	ErrHoldNotFound  = pcerr.New(pcerr.NotFound, "LEGAL_HOLD_NOT_FOUND", "legal hold not found")
	ErrHoldNotActive = pcerr.New(pcerr.FailedPrecondition, "LEGAL_HOLD_NOT_ACTIVE", "the legal hold is no longer active")
)

// MaxReason is the longest reason a person may give, in characters.
const MaxReason = 2000

// Notifier enqueues notifications in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service serves the retention and legal hold use cases as pc_app. Every
// one is human only and needs evidence.retention.manage at org scope.
type Service struct {
	Pool *db.Pool
	// Notify tells the org's admins and auditors about shortenings and
	// released holds; nil sends nothing.
	Notify Notifier
}

// manager returns the caller, who must be a person holding
// evidence.retention.manage at org scope.
func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, c.Require(td.PermEvidenceRetentionManage, td.OrgPath(c.Org))
}

func revisionsOf(rows []dbq.ListRetentionRevisionsRow) []Revision {
	out := make([]Revision, 0, len(rows))
	for _, r := range rows {
		out = append(out, Revision{
			ID: r.ID, Category: Category(r.Category), Number: int(r.Revision), Days: int(r.Days), SetBy: r.SetBy,
			Created: r.CreatedAt, Effective: r.EffectiveFrom,
		})
	}
	return out
}

// ensureDefaults records the default of every category the org has no
// revision of yet, so every removal names a recorded revision.
func ensureDefaults(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	for _, c := range Categories() {
		if err := q.InsertRetentionDefault(ctx, dbq.InsertRetentionDefaultParams{
			OrgID: org, ID: ids.NewV7(), Category: string(c), Days: int32(bounds[c].Default), //nolint:gosec // G115: ≤ 3650
		}); err != nil {
			return err
		}
	}
	return nil
}

// EnsureDefaults records the default of every category the org has no
// revision of yet (the job calls it as pc_app before removing anything).
func EnsureDefaults(ctx context.Context, pool *db.Pool, org ids.OrgID) error {
	return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return ensureDefaults(ctx, dbq.New(tx), org)
	})
}

// Policy is one category's retention.
type Policy struct {
	Category Category
	Bounds   Bounds
	Current  Revision
	// Pending is a shortening recorded and not in effect yet.
	Pending *Revision
}

func policiesAt(revs []Revision, now time.Time) []Policy {
	out := make([]Policy, 0, len(bounds))
	for _, c := range Categories() {
		p := Policy{Category: c, Bounds: bounds[c]}
		if cur, ok := Current(revs, c, now); ok {
			p.Current = cur
		} else {
			p.Current = Revision{Category: c, Days: bounds[c].Default, Effective: now}
		}
		if pend, ok := Pending(revs, c, now); ok {
			p.Pending = &pend
		}
		out = append(out, p)
	}
	return out
}

// Policies returns every category's retention, recording the defaults of
// categories never recorded.
func (s *Service) Policies(ctx context.Context) ([]Policy, error) {
	c, err := manager(ctx)
	if err != nil {
		return nil, err
	}
	var out []Policy
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := ensureDefaults(ctx, q, c.Org); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ListRetentionRevisions(ctx, c.Org)
		if err != nil {
			return err
		}
		out = policiesAt(revisionsOf(rows), now)
		return nil
	})
	return out, err
}

// Change is the outcome of SetPolicy.
type Change struct {
	Policy    Policy
	Changed   bool
	Shortened bool
}

// SetPolicy records a new revision of cat's period: at once when it is at
// least the period in effect, 7 days later when it is shorter (audited and
// notified to the org's admins and auditors). Setting the period in effect
// while a shortening is pending cancels the shortening.
func (s *Service) SetPolicy(ctx context.Context, cat Category, days int) (Change, error) {
	c, err := manager(ctx)
	if err != nil {
		return Change{}, err
	}
	b, ok := BoundsOf(cat)
	if !ok {
		return Change{}, ErrCategory
	}
	if !b.Allows(days) {
		return Change{}, ErrDays
	}
	var out Change
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockRetention(ctx, c.Org.UUID()); err != nil {
			return err
		}
		if err := ensureDefaults(ctx, q, c.Org); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ListRetentionRevisions(ctx, c.Org)
		if err != nil {
			return err
		}
		revs := revisionsOf(rows)
		cur, _ := Current(revs, cat, now)
		_, pending := Pending(revs, cat, now)
		if days == cur.Days && !pending {
			out = Change{Policy: policiesAt(revs, now)[categoryIndex(cat)]}
			return nil
		}
		shorten := days < cur.Days
		by := c.Principal.ID
		next := Next(revs, cat)
		id := ids.NewV7()
		r, err := q.InsertRetentionRevision(ctx, dbq.InsertRetentionRevisionParams{
			OrgID: c.Org, ID: id, Category: string(cat), Revision: int32(next), Days: int32(days), //nolint:gosec // G115: bounded
			SetBy: &by, Shorten: shorten,
		})
		if err != nil {
			return err
		}
		rev := Revision{ID: id, Category: cat, Number: next, Days: days, SetBy: &by, Created: r.CreatedAt, Effective: r.EffectiveFrom}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.retention_changed", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "retention_policy", ID: id.String()},
			Details: map[string]string{
				"category": string(cat), "days": strconv.Itoa(days), "previous_days": strconv.Itoa(cur.Days),
				"revision": strconv.Itoa(next), "effective": rev.Effective.UTC().Format(time.RFC3339),
				"shortened": strconv.FormatBool(shorten),
			},
		}); err != nil {
			return err
		}
		if shorten {
			if err := s.tell(ctx, tx, q, c.Org, "evidence.retention_shortened", map[string]string{
				"category": string(cat), "days": strconv.Itoa(days), "previous_days": strconv.Itoa(cur.Days),
				"effective": rev.Effective.UTC().Format(time.RFC3339),
			}); err != nil {
				return err
			}
		}
		out = Change{Policy: policiesAt(append(revs, rev), now)[categoryIndex(cat)], Changed: true, Shortened: shorten}
		return nil
	})
	return out, err
}

func categoryIndex(c Category) int {
	for i, x := range Categories() {
		if x == c {
			return i
		}
	}
	return 0
}

// tell notifies the org's admins and auditors (HR-198).
func (s *Service) tell(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, typ string, params map[string]string) error {
	if s.Notify == nil {
		return nil
	}
	people, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin), string(td.RoleAuditor)})
	if err != nil {
		return err
	}
	_, err = s.Notify.Enqueue(ctx, tx, napp.Message{Org: org, Type: typ, Params: params, Personal: people})
	return err
}

// HoldScope is what a hold covers.
type HoldScope string

// Hold scopes.
const (
	ScopeOrg         HoldScope = "org"
	ScopeAgent       HoldScope = "agent"
	ScopeRun         HoldScope = "run"
	ScopeTransaction HoldScope = "transaction"
	ScopeTimeRange   HoldScope = "time_range"
)

// Hold states.
const (
	HoldActive   = "ACTIVE"
	HoldReleased = "RELEASED"
)

// HoldRequest places a hold.
type HoldRequest struct {
	Scope HoldScope
	// ID names the agent, run or transaction.
	ID *ids.UUID
	// Start and End bound a time range (start inclusive, end exclusive).
	Start, End *time.Time
	Reason     string
}

// Hold is a stored legal hold.
type Hold = dbq.PcLegalHold

func validReason(s string) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n >= 1 && n <= MaxReason
}

func (h HoldRequest) check() error {
	switch h.Scope {
	case ScopeOrg:
		if h.ID != nil || h.Start != nil || h.End != nil {
			return ErrHoldScope
		}
	case ScopeAgent, ScopeRun, ScopeTransaction:
		if h.ID == nil || h.ID.IsZero() || h.Start != nil || h.End != nil {
			return ErrHoldScope
		}
	case ScopeTimeRange:
		if h.ID != nil || h.Start == nil || h.End == nil {
			return ErrHoldScope
		}
		if !h.Start.Before(*h.End) {
			return ErrHoldRange
		}
	default:
		return ErrHoldScope
	}
	if !validReason(h.Reason) {
		return ErrReason
	}
	return nil
}

// CreateHold places a hold, effective at once: the retention job's next
// batch sees it, and no batch runs while it is being placed.
func (s *Service) CreateHold(ctx context.Context, h HoldRequest) (Hold, error) {
	c, err := manager(ctx)
	if err != nil {
		return Hold{}, err
	}
	if err := h.check(); err != nil {
		return Hold{}, err
	}
	var out Hold
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if h.ID != nil {
			found, err := q.RetentionScopeExists(ctx, string(h.Scope), c.Org, *h.ID)
			if err != nil {
				return err
			}
			if !found {
				return ErrScopeNotFound
			}
		}
		if err := q.LockRetention(ctx, c.Org.UUID()); err != nil {
			return err
		}
		out, err = q.InsertLegalHold(ctx, dbq.InsertLegalHoldParams{
			OrgID: c.Org, ID: ids.NewV7(), Scope: string(h.Scope), ScopeID: h.ID, RangeStart: h.Start, RangeEnd: h.End,
			Reason: h.Reason, CreatedBy: c.Principal.ID,
		})
		if err != nil {
			return err
		}
		details := map[string]string{"scope": string(h.Scope)}
		if h.ID != nil {
			details["scope_id"] = h.ID.String()
		}
		if h.Start != nil {
			details["start"], details["end"] = h.Start.UTC().Format(time.RFC3339), h.End.UTC().Format(time.RFC3339)
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "evidence.legal_hold_created", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "legal_hold", ID: out.ID.String()}, Details: details,
		})
		return err
	})
	return out, err
}

// ReleaseHold releases an active hold (audited, and notified to the org's
// admins and auditors). Retention applies again to what it held.
func (s *Service) ReleaseHold(ctx context.Context, id ids.UUID, reason string) (Hold, error) {
	c, err := manager(ctx)
	if err != nil {
		return Hold{}, err
	}
	if !validReason(reason) {
		return Hold{}, ErrReason
	}
	var out Hold
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		h, err := q.GetLegalHold(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrHoldNotFound
		} else if err != nil {
			return err
		}
		if h.State != HoldActive {
			return ErrHoldNotActive
		}
		out, err = q.ReleaseLegalHold(ctx, dbq.ReleaseLegalHoldParams{ReleasedBy: &c.Principal.ID, Reason: &reason, OrgID: c.Org, ID: id})
		if db.IsNoRows(err) {
			return ErrHoldNotActive
		} else if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.legal_hold_released", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "legal_hold", ID: id.String()}, Details: map[string]string{"scope": h.Scope},
		}); err != nil {
			return err
		}
		return s.tell(ctx, tx, q, c.Org, "evidence.legal_hold_released", map[string]string{"hold": id.String(), "scope": h.Scope})
	})
	return out, err
}

// HoldPage is one page of holds, newest first.
type HoldPage struct {
	Items []Hold
	Next  string
}

// ListHolds lists the org's holds, newest first, optionally in one state.
func (s *Service) ListHolds(ctx context.Context, state string, size int32, token string) (HoldPage, error) {
	c, err := manager(ctx)
	if err != nil {
		return HoldPage{}, err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return HoldPage{}, err
	}
	var before *ids.UUID
	if !pr.After.IsZero() {
		before = &pr.After
	}
	var st *string
	if state != "" {
		st = &state
	}
	var out HoldPage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListLegalHoldsPage(ctx, dbq.ListLegalHoldsPageParams{
			OrgID: c.Org, State: st, Before: before, MaxRows: pr.Limit(),
		})
		if err != nil {
			return err
		}
		out.Items, out.Next = page.Finish(pr, rows, func(h Hold) ids.UUID { return h.ID })
		return nil
	}, db.ReadOnly())
	return out, err
}
