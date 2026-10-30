// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package blobtest

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/blob"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func TestStoreKeepsThePortContract(t *testing.T) {
	ctx := context.Background()
	s := New()
	a, b := ids.New[ids.Org](), ids.New[ids.Org]()
	r, err := s.Put(ctx, a, "pack_content", []byte("hello"))
	if err != nil || !r.Matches([]byte("hello")) {
		t.Fatalf("Put = %+v, %v", r, err)
	}
	if again, err := s.Put(ctx, a, "pack_content", []byte("hello")); err != nil || again != r {
		t.Fatalf("idempotent Put = %+v, %v", again, err)
	}
	got, err := s.Get(ctx, r)
	if err != nil || string(got) != "hello" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	got[0] = 'J' // the store keeps its own copy
	if again, _ := s.Get(ctx, r); string(again) != "hello" {
		t.Fatal("caller changed the stored blob")
	}
	// Another org's reference to the same content finds nothing.
	other := r
	other.Org = b
	if _, err := s.Get(ctx, other); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("cross-org Get: %v", err)
	}
	for _, bad := range []blob.Ref{{}, {Org: a, Kind: "Bad", SHA256: r.SHA256}, {Org: a, Kind: "k", SHA256: "zz"}} {
		if _, err := s.Get(ctx, bad); !errors.Is(err, blob.ErrInvalid) {
			t.Errorf("Get(%+v) = %v", bad, err)
		}
	}
	if _, err := s.Put(ctx, a, "pack_content", make([]byte, blob.MaxSize+1)); !errors.Is(err, blob.ErrTooLarge) {
		t.Fatalf("oversized Put: %v", err)
	}
	if err := s.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, r); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("after Delete: %v", err)
	}
	if err := s.Delete(ctx, r); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}
