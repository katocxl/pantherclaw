// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package merkle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// TestHR194_BuilderMatchesTheTiledRoot: the streaming root equals the root
// computed from the tiles for every size up to 1,024.
func TestHR194_BuilderMatchesTheTiledRoot(t *testing.T) {
	ctx := context.Background()
	tiles := NewMemoryTiles()
	var b Builder
	if b.Root() != EmptyRoot() {
		t.Fatal("the empty builder's root is not the empty root")
	}
	for i := range uint64(1024) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], i)
		leaf := LeafHash(sha256.New().Sum(n[:]))
		if err := tiles.Append(ctx, leaf); err != nil {
			t.Fatal(err)
		}
		b.Add(leaf)
		want, err := Root(ctx, tiles, i+1)
		if err != nil {
			t.Fatal(err)
		}
		if b.Size() != i+1 || b.Root() != want {
			t.Fatalf("size %d: builder root differs from the tiled root", i+1)
		}
	}
}
