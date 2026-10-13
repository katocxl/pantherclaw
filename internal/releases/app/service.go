// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app manages change windows (G0 M8 track P, HR-207): a person
// holding release.window.manage creates one for an environment and
// optionally a repository, which retires the current one, or retires
// one. Every change is audited. What a window allows is decided by the
// database clock (HR-171), here and in the finalization that consumes a
// window requirement.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/releases/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrInvalid  = pcerr.New(pcerr.InvalidArgument, "CHANGE_WINDOW_INVALID", "the change window is not valid")
	ErrNotFound = pcerr.New(pcerr.NotFound, "CHANGE_WINDOW_NOT_FOUND", "change window not found")
	ErrRetired  = pcerr.New(pcerr.FailedPrecondition, "CHANGE_WINDOW_RETIRED", "the change window is retired")
	ErrReason   = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 500 characters is required")
	// ErrChanged: another window for the same environment and repository
	// was created at the same time, and this one lost (HR-004).
	ErrChanged = pcerr.New(pcerr.Aborted, "CHANGE_WINDOW_CHANGED", "the environment's change window changed concurrently; read it again")
)

// Record is a stored window.
type Record struct {
	ID ids.UUID
	domain.Window
	Revision  int
	State     string
	CreatedBy string
	CreatedAt time.Time
	RetiredBy string
	RetiredAt *time.Time
}

// Service manages change windows.
type Service struct {
	Pool *db.Pool
}

func (s *Service) caller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermReleaseWindowManage, td.OrgPath(c.Org))
}

// Create stores a window. It retires the environment's and repository's
// current window, whose revision it follows. The environment is stored in
// lowercase (domain.NormalizeEnvironment). Of two windows created at the
// same time for one environment and repository, the second to commit
// fails with ErrChanged. The audit event records how many weekly entries,
// one-off windows and freezes the window has and their Digest, and for a
// replacement the window it replaces and how many freezes that one had.
func (s *Service) Create(ctx context.Context, w domain.Window) (Record, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return Record{}, err
	}
	w.Environment = domain.NormalizeEnvironment(w.Environment)
	if err := w.Validate(); err != nil {
		return Record{}, pcerr.Wrap(err, pcerr.InvalidArgument, "CHANGE_WINDOW_INVALID", strings.TrimPrefix(err.Error(), "releases: "))
	}
	weekly, err := json.Marshal(orEmpty(w.Weekly), json.Deterministic(true))
	if err != nil {
		return Record{}, err
	}
	oneOff, err := json.Marshal(orEmpty(w.OneOff), json.Deterministic(true))
	if err != nil {
		return Record{}, err
	}
	freezes, err := json.Marshal(orEmpty(w.Freezes), json.Deterministic(true))
	if err != nil {
		return Record{}, err
	}
	var out Record
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		by := c.Principal.String()
		details := map[string]string{"environment": w.Environment, "repository": w.Repository, "time_zone": w.TimeZone}
		current, err := q.ActiveChangeWindow(ctx, c.Org, w.Environment, w.Repository)
		switch {
		case db.IsNoRows(err):
		case err != nil:
			return err
		default:
			replaced, err := recordOf(current)
			if err != nil {
				return err
			}
			if _, err := q.RetireChangeWindow(ctx, &by, c.Org, current.ID); err != nil {
				return err
			}
			// A replacement that drops a freeze weakens it: say so.
			details["replaces"], details["replaced_freezes"] = current.ID.String(), strconv.Itoa(len(replaced.Freezes))
		}
		last, err := q.LastChangeWindowRevision(ctx, c.Org, w.Environment, w.Repository)
		if err != nil {
			return err
		}
		p := dbq.InsertChangeWindowParams{
			OrgID: c.Org, ID: ids.NewV7(), Environment: w.Environment, TimeZone: w.TimeZone, Weekly: weekly, OneOff: oneOff,
			Freezes: freezes, Revision: last + 1, CreatedBy: by,
		}
		if w.Repository != "" {
			p.Repository = &w.Repository
		}
		row, err := q.InsertChangeWindow(ctx, p)
		if db.IsUniqueViolation(err) {
			// A concurrent Create for the same environment and repository
			// committed its window, or its revision, first.
			return ErrChanged
		} else if err != nil {
			return err
		}
		if out, err = recordOf(row); err != nil {
			return err
		}
		digest, err := Digest(out.Window)
		if err != nil {
			return err
		}
		details["weekly"], details["one_off"] = strconv.Itoa(len(out.Weekly)), strconv.Itoa(len(out.OneOff))
		details["freezes"], details["window_sha256"] = strconv.Itoa(len(out.Freezes)), digest
		return s.audit(ctx, tx, c, "release.window.created", row.ID, details)
	})
	return out, err
}

// Digest is the SHA-256, in hex, of what a window allows: its time zone,
// weekly entries, one-off windows and freezes as deterministic JSON. The
// window-created audit event carries it with how many of each there are,
// so the stored window, which is never changed, can be checked against
// the audit record, and a replacement that shortens or drops a freeze
// shows in it.
func Digest(w domain.Window) (string, error) {
	b, err := json.Marshal(struct {
		TimeZone string          `json:"time_zone"`
		Weekly   []domain.Weekly `json:"weekly"`
		OneOff   []domain.Span   `json:"one_off"`
		Freezes  []domain.Span   `json:"freezes"`
	}{w.TimeZone, orEmpty(w.Weekly), orEmpty(w.OneOff), orEmpty(w.Freezes)}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Retire retires a window; releases to its environment then need another.
func (s *Service) Retire(ctx context.Context, id ids.UUID, reason string) (Record, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return Record{}, err
	}
	if n := len([]rune(reason)); n < 1 || n > 500 {
		return Record{}, ErrReason
	}
	var out Record
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		by := c.Principal.String()
		row, err := q.RetireChangeWindow(ctx, &by, c.Org, id)
		if db.IsNoRows(err) {
			if _, err := q.GetChangeWindow(ctx, c.Org, id); db.IsNoRows(err) {
				return ErrNotFound
			}
			return ErrRetired
		} else if err != nil {
			return err
		}
		if out, err = recordOf(row); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "release.window.retired", id, map[string]string{
			"environment": row.Environment, "reason": reason,
		})
	})
	return out, err
}

// List lists the windows, of one environment (in any case) when it is not
// "", and the retired ones too when asked.
func (s *Service) List(ctx context.Context, environment string, retired bool) ([]Record, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	environment = domain.NormalizeEnvironment(environment)
	var out []Record
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListChangeWindows(ctx, c.Org, environment, retired)
		if err != nil {
			return err
		}
		for _, r := range rows {
			rec, err := recordOf(r)
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, err
}

// Decision is what the windows say about a release now.
type Decision struct {
	State domain.State
	// At is the database clock that decided.
	At time.Time
	// Windows are the ACTIVE windows that apply.
	Windows []Record
}

// Active decides a release to an environment and repository now.
func (s *Service) Active(ctx context.Context, environment, repository string) (Decision, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return Decision{}, err
	}
	if !domain.ValidEnvironment(environment) || !domain.ValidRepository(repository) {
		return Decision{}, ErrInvalid
	}
	var out Decision
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = Decide(ctx, dbq.New(tx), c.Org, environment, repository)
		return err
	})
	return out, err
}

// Decide is what the ACTIVE windows say about a release to environment
// (in any case) and repository at the database clock (HR-171). The
// finalization that consumes a window requirement calls it in its own
// transaction.
func Decide(ctx context.Context, q *dbq.Queries, org ids.OrgID, environment, repository string) (Decision, error) {
	environment = domain.NormalizeEnvironment(environment)
	rows, err := q.ApplicableChangeWindows(ctx, org, environment, repository)
	if err != nil {
		return Decision{}, err
	}
	out := Decision{At: time.Now()}
	windows := make([]domain.Window, 0, len(rows))
	for _, r := range rows {
		rec, err := recordOf(dbq.PcChangeWindow{
			OrgID: r.OrgID, ID: r.ID, Environment: r.Environment, Repository: r.Repository, TimeZone: r.TimeZone, Weekly: r.Weekly,
			OneOff: r.OneOff, Freezes: r.Freezes, Revision: r.Revision, State: r.State, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		})
		if err != nil {
			return Decision{}, err
		}
		out.At = r.DecidedAt
		out.Windows = append(out.Windows, rec)
		windows = append(windows, rec.Window)
	}
	if len(rows) == 0 {
		now, err := q.DBNow(ctx)
		if err != nil {
			return Decision{}, err
		}
		out.At = now
	}
	out.State = domain.Decide(windows, environment, repository, out.At)
	return out, nil
}

func recordOf(r dbq.PcChangeWindow) (Record, error) {
	out := Record{
		ID: r.ID, Window: domain.Window{Environment: r.Environment, TimeZone: r.TimeZone}, Revision: int(r.Revision), State: r.State,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, RetiredAt: r.RetiredAt,
	}
	if r.Repository != nil {
		out.Repository = *r.Repository
	}
	if r.RetiredBy != nil {
		out.RetiredBy = *r.RetiredBy
	}
	for _, f := range []struct {
		raw []byte
		to  any
	}{{r.Weekly, &out.Weekly}, {r.OneOff, &out.OneOff}, {r.Freezes, &out.Freezes}} {
		if err := json.Unmarshal(f.raw, f.to); err != nil {
			return Record{}, err
		}
	}
	return out, nil
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "change_window", ID: id.String()},
		Details: details,
	})
	return err
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
