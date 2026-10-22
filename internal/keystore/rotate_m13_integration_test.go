// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package keystore_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TestHR372_RotateSigningKeysIsAllOrNothing: several purposes rotate in one
// transaction; when one of them fails, none has a new key.
func TestHR372_RotateSigningKeysIsAllOrNothing(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	if err := keystore.LoadSigningKeys(ctx, p, kp, keys.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	active := func() map[keys.Purpose]string {
		ks, err := keystore.PublishedKeys(ctx, p, []keys.Purpose{keys.PurposeCheckpoints, keys.PurposeEvidencePacks})
		if err != nil {
			t.Fatal(err)
		}
		out := map[keys.Purpose]string{}
		for _, k := range ks {
			if k.State == keys.StateActive {
				out[k.Purpose] = k.KID
			}
		}
		return out
	}
	before := active()
	op := domain.Actor{Type: "operator", ID: "cli:test@host"}
	// The second checkpoints rotation finds no active key it saw: the whole
	// transaction rolls back.
	if _, err := keystore.RotateSigningKeys(ctx, p, kp,
		[]keys.Purpose{keys.PurposeEvidencePacks, keys.PurposeCheckpoints, keys.PurposeCheckpoints}, op); err == nil {
		t.Fatal("a failing rotation succeeded")
	}
	if after := active(); after[keys.PurposeEvidencePacks] != before[keys.PurposeEvidencePacks] ||
		after[keys.PurposeCheckpoints] != before[keys.PurposeCheckpoints] {
		t.Fatalf("a failed rotation changed keys: %v -> %v", before, after)
	}
	kids, err := keystore.RotateSigningKeys(ctx, p, kp, []keys.Purpose{keys.PurposeEvidencePacks, keys.PurposeCheckpoints}, op)
	if err != nil || len(kids) != 2 {
		t.Fatalf("rotate = %v, %v", kids, err)
	}
	if after := active(); after[keys.PurposeEvidencePacks] != kids[0] || after[keys.PurposeCheckpoints] != kids[1] {
		t.Fatalf("active keys %v, want %v", after, kids)
	}
}
