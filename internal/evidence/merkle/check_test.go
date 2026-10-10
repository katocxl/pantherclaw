// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package merkle

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func leafN(i uint64) Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], i)
	return LeafHash(b[:])
}

func treeOf(t *testing.T, n uint64) *MemoryTiles {
	t.Helper()
	m := NewMemoryTiles()
	for i := range n {
		if err := m.Append(context.Background(), leafN(i)); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func check(ctx context.Context, r TileReader, n uint64) error {
	c := NewTileCheck(r)
	for i := range n {
		if err := c.Add(ctx, leafN(i)); err != nil {
			return err
		}
	}
	return c.Finish(ctx)
}

// TestHR194_TileCheckFindsEveryAlteredTile: the stored tiles of a tree pass,
// and an altered hash in a full or partial tile at any level, or a missing
// tile, fails.
func TestHR194_TileCheckFindsEveryAlteredTile(t *testing.T) {
	ctx := context.Background()
	const n = 256*256 + 300 // two levels of full tiles and partial ones
	m := treeOf(t, n)
	if err := check(ctx, m, n); err != nil {
		t.Fatalf("intact tiles: %v", err)
	}
	for _, k := range []tileKey{{0, 0}, {0, 257}, {1, 0}, {1, 1}, {2, 0}} {
		orig := m.tiles[k]
		if orig == nil {
			t.Fatalf("no tile %+v", k)
		}
		bad := append([]byte(nil), orig...)
		bad[len(bad)-1] ^= 1
		m.tiles[k] = bad
		if err := check(ctx, m, n); !errors.Is(err, ErrTileMismatch) {
			t.Errorf("tile %+v altered: %v", k, err)
		}
		delete(m.tiles, k)
		if err := check(ctx, m, n); !errors.Is(err, ErrTileNotFound) {
			t.Errorf("tile %+v missing: %v", k, err)
		}
		m.tiles[k] = orig
	}
	// A smaller tree checks against the wider stored tiles.
	if err := check(ctx, m, 1000); err != nil {
		t.Fatalf("a prefix of the tree: %v", err)
	}
}
