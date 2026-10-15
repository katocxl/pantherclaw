// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package failures records owned operational failures (G0 M10 D18, F641):
// what broke, where, who owns it, by when and what to do next. A repeat
// with the same dedupe key while the failure is open counts into it.
package failures

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Failure states.
const (
	StateOpen     = "OPEN"
	StateAssigned = "ASSIGNED"
	StateResolved = "RESOLVED"
)

// DefaultDeadline is how long an owner has when the reporter names no
// deadline.
const DefaultDeadline = 24 * time.Hour

// ErrInvalidFailure reports a failure the sink refuses.
var ErrInvalidFailure = errors.New("failures: invalid failure")

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)

// Sink is the core FailureSink.
type Sink struct {
	// Now is the clock for default deadlines; time.Now when nil.
	Now func() time.Time
}

var _ reflexdomain.FailureSink = (*Sink)(nil)

// Report implements reflexdomain.FailureSink.
func (s *Sink) Report(ctx context.Context, ptx pgx.Tx, f reflexdomain.Failure) (ids.UUID, error) {
	tx, err := db.AdoptTenantTx(ctx, ptx, f.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	id, _, err := s.ReportTx(ctx, tx, f)
	return id, err
}

// ReportTx records f in a tenant transaction and reports whether it was
// new.
func (s *Sink) ReportTx(ctx context.Context, tx db.TenantTx, f reflexdomain.Failure) (ids.UUID, bool, error) {
	if f.Org != tx.OrgID() {
		return ids.UUID{}, false, db.ErrTenantMismatch
	}
	if err := validate(f); err != nil {
		return ids.UUID{}, false, err
	}
	scope := f.Scope
	if scope == nil {
		scope = []reflexdomain.Subject{}
	}
	sb, err := json.Marshal(scope)
	if err != nil {
		return ids.UUID{}, false, err
	}
	deadline := f.Deadline
	if deadline.IsZero() {
		now := time.Now
		if s.Now != nil {
			now = s.Now
		}
		deadline = now().Add(DefaultDeadline)
	}
	p := dbq.UpsertFailureParams{
		OrgID: f.Org, ID: ids.NewV7(), Kind: f.Kind, Summary: f.Summary, NextStep: f.NextStep, Scope: sb,
		Deadline: deadline, DedupeKey: f.DedupeKey, State: StateOpen,
	}
	if f.Owner != nil {
		t, id := string(f.Owner.Type), f.Owner.ID
		p.OwnerType, p.OwnerID, p.State = &t, &id, StateAssigned
	}
	row, err := dbq.New(tx).UpsertFailure(ctx, p)
	if err != nil {
		return ids.UUID{}, false, fmt.Errorf("failures: report: %w", err)
	}
	return row.ID, row.Inserted, nil
}

func validate(f reflexdomain.Failure) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrInvalidFailure, what) }
	switch {
	case f.Org.IsZero():
		return bad("no org")
	case !kindPattern.MatchString(f.Kind) || len(f.Kind) > 100:
		return bad("kind must be a dotted lowercase name")
	case f.Summary == "" || len(f.Summary) > 2000:
		return bad("summary 1..2000 bytes")
	case f.NextStep == "" || len(f.NextStep) > 1000:
		return bad("next step 1..1000 bytes")
	case f.DedupeKey == "" || len(f.DedupeKey) > reflexdomain.MaxKey:
		return bad("dedupe key 1..512 bytes")
	case len(f.Scope) > reflexdomain.MaxSubjects:
		return bad("at most 32 scope subjects")
	case f.Owner != nil && !f.Owner.Valid():
		return bad("invalid owner")
	}
	for _, s := range f.Scope {
		if !s.Valid() {
			return bad("invalid scope subject")
		}
	}
	return nil
}
