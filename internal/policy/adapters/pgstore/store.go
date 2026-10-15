// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgstore stores policy bundles per org in PostgreSQL: immutable
// versions, at most one published per org (the policy/app BundleStore port,
// part 1; G0 M4 part 2, design decision 20).
package pgstore

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Errors.
var (
	ErrNotFound = errors.New("policy: version not found")
	// ErrNotDraft reports a publication of a version that is not a draft
	// (a lost race or a repeat, HR-004).
	ErrNotDraft = app.ErrNotDraft
	// ErrPublishedChanged: another version is published than expected.
	ErrPublishedChanged = app.ErrPublishedChanged
)

// MaxBundleBytes is the largest stored bundle.
const MaxBundleBytes = 4 << 20

// Store implements app.BundleStore.
type Store struct {
	Pool *db.Pool
}

var (
	_ app.BundleStore  = (*Store)(nil)
	_ app.VersionStore = (*Store)(nil)
)

// Version is one stored bundle version.
type Version struct {
	ID          ids.UUID
	BundleID    string
	Version     int
	State       string
	CreatedBy   string
	CreatedAt   time.Time
	PublishedAt *time.Time
}

// Published implements app.BundleStore: the org's published bundle, or nil.
func (s *Store) Published(ctx context.Context, org ids.OrgID) (*domain.Bundle, error) {
	var out *domain.Bundle
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.PublishedInTx(ctx, tx, org)
		return err
	})
	return out, err
}

// PublishedInTx is Published inside the caller's transaction (the
// Authority's one-snapshot read).
func (s *Store) PublishedInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) (*domain.Bundle, error) {
	row, err := dbq.New(tx).GetPublishedPolicy(ctx, org)
	if db.IsNoRows(err) {
		return nil, nil //nolint:nilnil // no published policy
	}
	if err != nil {
		return nil, err
	}
	return decode(row.Bundle)
}

// CreateVersion stores a bundle as the next draft version of its policy
// and returns the version id and number. The stored bundle carries that
// number, whatever the caller set.
func (s *Store) CreateVersion(ctx context.Context, org ids.OrgID, b *domain.Bundle, createdBy string, ev *audit.Event) (ids.UUID, int, error) {
	id := ids.NewV7()
	var version int
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		policyID, err := q.GetPolicyID(ctx, org, b.ID)
		if db.IsNoRows(err) {
			policyID = ids.NewV7()
			err = q.InsertPolicy(ctx, org, policyID, b.ID)
		}
		if err != nil {
			return err
		}
		next, err := q.NextPolicyVersion(ctx, org, policyID)
		if err != nil {
			return err
		}
		stored := *b
		stored.Version, version = int(next), int(next)
		if err := stored.Validate(); err != nil {
			return err
		}
		raw, err := json.Marshal(stored, json.Deterministic(true))
		if err != nil {
			return err
		}
		if len(raw) > MaxBundleBytes {
			return fmt.Errorf("%w: the bundle is larger than %d bytes", domain.ErrInvalid, MaxBundleBytes)
		}
		digest := domain.ContentDigest(&stored)
		if err := q.InsertPolicyVersion(ctx, dbq.InsertPolicyVersionParams{
			OrgID: org, ID: id, PolicyID: policyID, Version: next, Bundle: raw, ContentDigest: digest[:], CreatedBy: createdBy,
		}); err != nil {
			return err
		}
		return record(ctx, tx, ev, map[string]string{"version_id": id.String(), "version": strconv.Itoa(version)})
	})
	return id, version, err
}

// Get returns a stored version's bundle and state.
func (s *Store) Get(ctx context.Context, org ids.OrgID, id ids.UUID) (*domain.Bundle, string, error) {
	var out *domain.Bundle
	var state string
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPolicyVersion(ctx, org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		state = row.State
		out, err = decode(row.Bundle)
		return err
	})
	return out, state, err
}

// List returns the org's versions, newest first.
func (s *Store) List(ctx context.Context, org ids.OrgID, limit int) ([]Version, error) {
	var out []Version
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPolicyVersions(ctx, org, int32(min(max(limit, 1), 200)))
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, Version{
				ID: r.ID, BundleID: r.BundleID, Version: int(r.Version), State: r.State,
				CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, PublishedAt: r.PublishedAt,
			})
		}
		return nil
	})
	return out, err
}

func decode(raw []byte) (*domain.Bundle, error) {
	var b domain.Bundle
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("policy: stored bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("policy: stored bundle: %w", err)
	}
	return &b, nil
}

func record(ctx context.Context, tx db.TenantTx, ev *audit.Event, details map[string]string) error {
	if ev == nil {
		return nil
	}
	e := *ev
	e.Details = details
	_, err := audit.Record(ctx, tx, e)
	return err
}

// Version returns one stored version with its bundle.
func (s *Store) Version(ctx context.Context, org ids.OrgID, id ids.UUID) (app.VersionInfo, error) {
	var out app.VersionInfo
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.VersionInTx(ctx, tx, org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// VersionInTx implements app.GateStore.
func (s *Store) VersionInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (app.VersionInfo, error) {
	r, err := dbq.New(tx).GetPolicyVersion(ctx, org, id)
	if db.IsNoRows(err) {
		return app.VersionInfo{}, app.ErrVersionNotFound
	}
	if err != nil {
		return app.VersionInfo{}, err
	}
	return app.VersionInfo{
		ID: r.ID, BundleID: r.BundleID, Version: int(r.Version), State: r.State, Bundle: r.Bundle,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, PublishedAt: r.PublishedAt, ContentDigest: r.ContentDigest,
	}, nil
}

// PublishedVersion returns the org's published version, or nil.
func (s *Store) PublishedVersion(ctx context.Context, org ids.OrgID) (*app.VersionInfo, error) {
	var out *app.VersionInfo
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetPublishedPolicy(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &app.VersionInfo{
			ID: r.ID, BundleID: r.BundleID, Version: int(r.Version), State: "PUBLISHED", Bundle: r.Bundle,
			CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, PublishedAt: r.PublishedAt, ContentDigest: r.ContentDigest,
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ListVersions returns the org's versions, newest first, without bundles.
func (s *Store) ListVersions(ctx context.Context, org ids.OrgID, limit int) ([]app.VersionInfo, error) {
	vs, err := s.List(ctx, org, limit)
	out := make([]app.VersionInfo, 0, len(vs))
	for _, v := range vs {
		out = append(out, app.VersionInfo{
			ID: v.ID, BundleID: v.BundleID, Version: v.Version, State: v.State,
			CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt, PublishedAt: v.PublishedAt,
		})
	}
	return out, err
}
