// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgstore_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

func bundle(reason string) *domain.Bundle {
	return &domain.Bundle{ID: "org-policy", Version: 99, Rules: []domain.Rule{{
		ID: "no-large", Kind: domain.Forbid, Summary: "no large refunds", Operations: []string{"payments.refund.create"},
		When: `action.params.amount > money("1000", "USD")`, Reason: reason,
	}}}
}

func TestIntPolicyVersionsAndPublication(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s := &pgstore.Store{Pool: p}
	if b, err := s.Published(ctx, org); err != nil || b != nil {
		t.Fatalf("no published policy yet: %v %v", b, err)
	}
	v1, n1, err := s.CreateVersion(ctx, org, bundle("TOO_LARGE"), "user:alice", nil)
	if err != nil || n1 != 1 {
		t.Fatalf("v1: %d %v", n1, err)
	}
	v2, n2, err := s.CreateVersion(ctx, org, bundle("TOO_LARGE_V2"), "user:alice", nil)
	if err != nil || n2 != 2 {
		t.Fatalf("v2: %d %v", n2, err)
	}
	if err := s.Publish(ctx, org, v1, "user:bob", nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.Published(ctx, org); b == nil || b.Version != 1 || b.Rules[0].Reason != "TOO_LARGE" {
		t.Fatalf("published %+v", b)
	}
	// Concurrent publications of the same draft: exactly one wins.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() { errs[i] = s.Publish(ctx, org, v2, "user:bob", nil) })
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		} else if !errors.Is(err, pgstore.ErrNotDraft) && !db.IsUniqueViolation(err) {
			t.Fatalf("unexpected %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d publications won", wins)
	}
	if b, _ := s.Published(ctx, org); b == nil || b.Version != 2 {
		t.Fatalf("published %+v", b)
	}
	if _, state, _ := s.Get(ctx, org, v1); state != "SUPERSEDED" {
		t.Fatalf("the previous version is %s", state)
	}
	if err := s.Publish(ctx, org, v1, "user:bob", nil); !errors.Is(err, pgstore.ErrNotDraft) {
		t.Fatalf("a superseded version was published again: %v", err)
	}
	if vs, err := s.List(ctx, org, 10); err != nil || len(vs) != 2 {
		t.Fatalf("list %d %v", len(vs), err)
	}
	if _, _, err := s.Get(ctx, ids.New[ids.Org](), v1); !errors.Is(err, pgstore.ErrNotFound) {
		t.Fatalf("another org's version was found: %v", err)
	}
}

// TestIntPublishExpectingRefusesAConcurrentPublish (G0 M8 C4): a publish
// that expects the published version succeeds only while that version is
// still published; of drafts racing from the same expected version exactly
// one is published, the others refused with ErrPublishedChanged, and the
// expectation "none is published" holds only until something is.
func TestIntPublishExpectingRefusesAConcurrentPublish(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s := &pgstore.Store{Pool: p}
	draft := func(reason string) ids.UUID {
		t.Helper()
		id, _, err := s.CreateVersion(ctx, org, bundle(reason), "user:alice", nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	none := ids.UUID{}
	v1, v2 := draft("REASON_A"), draft("REASON_B")
	if err := s.PublishExpecting(ctx, org, v1, "user:bob", &none, nil); err != nil {
		t.Fatalf("publish expecting none: %v", err)
	}
	if err := s.PublishExpecting(ctx, org, v2, "user:bob", &none, nil); !errors.Is(err, pgstore.ErrPublishedChanged) {
		t.Fatalf("publish expecting none once one is published: %v", err)
	}

	// Drafts edited from v1 race: one wins, the rest see it.
	drafts := []ids.UUID{draft("REASON_C"), draft("REASON_D"), draft("REASON_E"), draft("REASON_F")}
	var wg sync.WaitGroup
	errs := make([]error, len(drafts))
	for i, d := range drafts {
		wg.Go(func() { errs[i] = s.PublishExpecting(ctx, org, d, "user:bob", &v1, nil) })
	}
	wg.Wait()
	var won ids.UUID
	for i, err := range errs {
		switch {
		case err == nil && won.IsZero():
			won = drafts[i]
		case err == nil:
			t.Fatalf("two publishes from v1 won: %s and %s", won, drafts[i])
		case !errors.Is(err, pgstore.ErrPublishedChanged):
			t.Fatalf("unexpected %v", err)
		}
	}
	if won.IsZero() {
		t.Fatal("no publish from v1 won")
	}
	for _, d := range drafts {
		if _, state, _ := s.Get(ctx, org, d); (d == won) != (state == "PUBLISHED") || (d != won && state != "DRAFT") {
			t.Fatalf("draft %s is %s (won %s)", d, state, won)
		}
	}
	if err := s.PublishExpecting(ctx, org, v2, "user:bob", &won, nil); err != nil {
		t.Fatalf("publish expecting the current version: %v", err)
	}
}
