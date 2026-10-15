// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package policytest is test setup, not product: it publishes a policy for
// tests that only need "some policy published" (G0 M11.1 design decision
// 10). It stores the version, records a passing validation and test run of
// its content and publishes it through the store's one publication path,
// the gate's conditional UPDATE (HR-230). Product code never imports it;
// the gate's own tests use the real path.
package policytest

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Actor is the author and publisher of record of what Publish stores.
const Actor = "test:policytest"

// Publish stores b as a new version of org and publishes it, superseding
// the published version, and returns the version id. It fails the test on
// any error.
func Publish(ctx context.Context, t testing.TB, pool *db.Pool, org ids.OrgID, b *domain.Bundle) ids.UUID {
	t.Helper()
	id, err := PublishAs(ctx, pool, org, b, Actor)
	if err != nil {
		t.Fatalf("policytest.Publish: %v", err)
	}
	return id
}

// PublishAs is Publish with a publisher of record, returning the error.
func PublishAs(ctx context.Context, pool *db.Pool, org ids.OrgID, b *domain.Bundle, by string) (ids.UUID, error) {
	s := &pgstore.Store{Pool: pool}
	id, _, err := s.CreateVersion(ctx, org, b, by, nil)
	if err != nil {
		return ids.UUID{}, err
	}
	return id, publishStored(ctx, s, org, id, by)
}

// PublishVersion publishes an already stored version of org as Publish
// does. It fails the test on any error.
func PublishVersion(ctx context.Context, t testing.TB, pool *db.Pool, org ids.OrgID, id ids.UUID) {
	t.Helper()
	if err := publishStored(ctx, &pgstore.Store{Pool: pool}, org, id, Actor); err != nil {
		t.Fatalf("policytest.PublishVersion: %v", err)
	}
}

func publishStored(ctx context.Context, s *pgstore.Store, org ids.OrgID, id ids.UUID, by string) error {
	v, err := s.Version(ctx, org, id)
	if err != nil {
		return err
	}
	var digest [32]byte
	copy(digest[:], v.ContentDigest)
	if _, err := s.RecordValidation(ctx, org, id, digest, domain.ValidationResult{Passed: true}, by); err != nil {
		return err
	}
	run, err := s.RecordTestRun(ctx, org, id, digest, domain.TestResult{Passed: true}, by)
	if err != nil {
		return err
	}
	var base ids.UUID
	if cur, err := s.PublishedVersion(ctx, org); err != nil {
		return err
	} else if cur != nil {
		base = cur.ID
	}
	return s.PublishTested(ctx, org, app.PublishRequest{
		Version: id, Digest: digest, TestRun: run, Base: base, PublishedBy: by,
	})
}
