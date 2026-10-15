// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// EmergencyReview is how long a distinct publisher has to review an
// emergency change (D42, F590).
const EmergencyReview = 72 * time.Hour

// FailureSink records owned failures (reflex failures.Sink).
type FailureSink interface {
	ReportTx(ctx context.Context, tx db.TenantTx, f reflexdomain.Failure) (ids.UUID, bool, error)
}

// Service is ProtectedChangeService's use cases (D42).
type Service struct {
	Pool     *db.Pool
	Gate     *Gate
	Failures FailureSink
}

// Setting is one category's protection.
type Setting struct {
	Category  Category
	Mode      Mode
	UpdatedBy ids.UUID
	UpdatedAt time.Time
}

// Changes is a page of protected changes.
type Changes = []dbq.PcProtectedChange

func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermProtectedChangeManage, td.OrgPath(c.Org))
}

// GetSettings returns every category's mode (protected_change.manage).
func (s *Service) GetSettings(ctx context.Context) ([]Setting, error) {
	c, err := manager(ctx)
	if err != nil {
		return nil, err
	}
	var out []Setting
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListProtectedChangeSettings(ctx, c.Org)
		if err != nil {
			return err
		}
		stored := map[Category]dbq.ListProtectedChangeSettingsRow{}
		for _, r := range rows {
			stored[Category(r.Category)] = r
		}
		for _, cat := range Categories() {
			st := Setting{Category: cat, Mode: ModeOff}
			if r, ok := stored[cat]; ok {
				st.Mode, st.UpdatedBy, st.UpdatedAt = Mode(r.Mode), r.UpdatedBy, r.UpdatedAt
			}
			out = append(out, st)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// SetCategoryMode turns a category on at once (one person: it only
// narrows) or asks for it to be turned off, which is itself a protected
// change (kind SETTINGS) another holder of protected_change.manage
// confirms (D42, HR-292). Setting the current mode changes nothing.
func (s *Service) SetCategoryMode(ctx context.Context, cat Category, mode Mode) (Setting, error) {
	c, err := manager(ctx)
	if err != nil {
		return Setting{}, err
	}
	if !c.Human() {
		return Setting{}, ErrHuman
	}
	if !cat.Valid() || !mode.Valid() {
		return Setting{}, ErrInvalid
	}
	var pending *PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockProtectedChangeSettings(ctx, c.Org); err != nil {
			return err
		}
		cur, err := q.ProtectedCategoryMode(ctx, c.Org, string(cat))
		if err != nil {
			return err
		}
		switch {
		case Mode(cur) == mode:
			return nil
		case mode == ModeDistinctPublisher:
			if err := q.SetProtectedCategoryMode(ctx, dbq.SetProtectedCategoryModeParams{
				OrgID: c.Org, Category: string(cat), Mode: string(mode), UpdatedBy: c.Principal.ID,
			}); err != nil {
				return err
			}
			return record(ctx, tx, c, "protected_change.category_enabled", SubjectID(SurfaceSettings, string(cat)),
				map[string]string{"category": string(cat)})
		}
		if s.Gate == nil {
			return ErrUnavailable
		}
		var err2 error
		pending, err2 = s.Gate.store(ctx, tx, c, Change{
			Category: cat, Surface: SurfaceSettings, Subject: string(cat),
			Summary:  map[string]string{"category": string(cat), "from": cur, "to": string(mode)},
			Widening: []string{"mode"}, Payload: map[string]string{"category": string(cat), "mode": string(mode)},
		}, StatePending)
		return err2
	})
	if err != nil {
		return Setting{}, err
	}
	if pending != nil {
		return Setting{}, pending
	}
	all, err := s.GetSettings(ctx)
	if err != nil {
		return Setting{}, err
	}
	for _, st := range all {
		if st.Category == cat {
			return st, nil
		}
	}
	return Setting{}, ErrNotFound
}

// List lists protected changes, newest first (protected_change.manage).
// state and category are optional filters; before pages.
func (s *Service) List(ctx context.Context, state string, cat Category, before ids.UUID, limit int) (Changes, error) {
	c, err := manager(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	p := dbq.ListProtectedChangesParams{OrgID: c.Org, MaxRows: int32(limit)} //nolint:gosec // G115: 1..200
	if state != "" {
		p.State = &state
	}
	if cat != "" {
		v := string(cat)
		p.Category = &v
	}
	if !before.IsZero() {
		p.BeforeID = &before
	}
	var out Changes
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ListProtectedChanges(ctx, p)
		return err
	}, db.ReadOnly())
	return out, err
}

// ApplyEmergency applies a pending protected change now (F590): a person
// holding incident.respond, with a fresh step-up, who is not marked
// compromised. The change runs as its author, is recorded EMERGENCY with
// the caller as its publisher, its pending request is voided, and a
// review request opens that a distinct publisher must confirm within 72
// hours, with an owned failure protected_change.emergency_review.
func (s *Service) ApplyEmergency(ctx context.Context, request ids.UUID, su stepup.StepUp) (dbq.PcProtectedChange, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return dbq.PcProtectedChange{}, err
	}
	if err := c.Require(td.PermIncidentRespond, td.OrgPath(c.Org)); err != nil {
		return dbq.PcProtectedChange{}, err
	}
	if !c.Human() {
		return dbq.PcProtectedChange{}, ErrHuman
	}
	if s.Gate == nil || s.Gate.Requests == nil {
		return dbq.PcProtectedChange{}, ErrUnavailable
	}
	var out dbq.PcProtectedChange
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, su, now); err != nil {
			return err
		}
		if s.Gate.Compromise != nil {
			bad, err := s.Gate.Compromise.CompromisedTx(ctx, tx, c.Principal.ID)
			if err != nil {
				return err
			}
			if bad {
				return ErrCompromised
			}
		}
		row, err := q.ProtectedChangeOfRequest(ctx, c.Org, request)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.State != StatePending || row.ChangeRequestID == nil || *row.ChangeRequestID != request ||
			Surface(row.Surface) == SurfaceSettings {
			return ErrState
		}
		if err := s.Gate.run(ctx, tx, row); err != nil {
			return err
		}
		by := c.Principal.ID
		if out, err = q.DecideProtectedChange(ctx, dbq.DecideProtectedChangeParams{
			State: StateEmergency, Publisher: &by, Reason: ptr(reasonEmergency), OrgID: c.Org, ID: row.ID,
		}); err != nil {
			return err
		}
		if err := s.Gate.Requests.Void(ctx, tx, request, reasonEmergency); err != nil {
			return err
		}
		review, err := s.Gate.Requests.Open(ctx, tx, Request{
			Domain: DomainProtected, Kind: KindEmergencyReview, Subject: row.ID, Digest: row.Digest, Required: 1, By: c,
			Summary: map[string]string{
				"category": row.Category, "surface": row.Surface, "subject": row.Subject, "applied_by": c.Principal.String(),
				"author": "user:" + row.Author.String(), "widening": joinWidening(row.Widening),
			},
		})
		if err != nil {
			return err
		}
		if err := one(q.SetEmergencyReviewRequest(ctx, review, c.Org, row.ID)); err != nil {
			return err
		}
		out.ReviewRequestID = &review
		if s.Failures != nil {
			if _, _, err := s.Failures.ReportTx(ctx, tx, reflexdomain.Failure{
				Org: c.Org, Kind: "protected_change.emergency_review",
				Summary:   "An emergency " + row.Category + " change to " + row.Subject + " was applied without a second person.",
				NextStep:  "A publisher other than the person who applied it confirms its review request " + review.String() + " within 72 hours.",
				Deadline:  now.Add(EmergencyReview),
				DedupeKey: "protected_change.emergency_review:" + row.ID.String(),
				Scope:     []reflexdomain.Subject{{Type: reflexdomain.SubjectUser, ID: c.Principal.ID.String()}},
			}); err != nil {
				return err
			}
		}
		return record(ctx, tx, c, "protected_change.emergency_applied", row.ID, map[string]string{
			"category": row.Category, "surface": row.Surface, "subject": row.Subject, "author": row.Author.String(),
			"publisher": c.Principal.ID.String(), "review_request": review.String(),
		})
	})
	return out, err
}

func ptr[T any](v T) *T { return &v }

func joinWidening(w []string) string {
	out := ""
	for i, s := range w {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// ByRequest returns the protected change of a change request, for the
// emergency page (incident.respond).
func (s *Service) ByRequest(ctx context.Context, request ids.UUID) (dbq.PcProtectedChange, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return dbq.PcProtectedChange{}, err
	}
	if err := c.Require(td.PermIncidentRespond, td.OrgPath(c.Org)); err != nil {
		return dbq.PcProtectedChange{}, err
	}
	var out dbq.PcProtectedChange
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetProtectedChangeByRequest(ctx, c.Org, request)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		return err
	}, db.ReadOnly())
	return out, err
}
