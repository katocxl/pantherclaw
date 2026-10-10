// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package merkle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// ErrTileMismatch reports a stored tile that differs from the tile its
// leaves give.
var ErrTileMismatch = errors.New("merkle: stored tile differs from its leaves")

// TileCheck compares stored tiles with the tiles that leaf hashes, given
// in order, produce, at every level, in O(log n) memory: each full tile is
// compared when it completes, and Finish compares the partial ones. The
// daily integrity job uses it to check the stored tree against the chain.
type TileCheck struct {
	r       TileReader
	pending [][]byte // per level, the hashes of the tile being filled
	index   []uint64 // per level, that tile's index
	size    uint64
}

// NewTileCheck checks the tiles r holds.
func NewTileCheck(r TileReader) *TileCheck { return &TileCheck{r: r} }

// Add adds the next leaf hash.
func (c *TileCheck) Add(ctx context.Context, leaf Hash) error {
	c.size++
	h := leaf
	for level := 0; ; level++ {
		if level == len(c.pending) {
			c.pending, c.index = append(c.pending, nil), append(c.index, 0)
		}
		c.pending[level] = append(c.pending[level], h[:]...)
		if len(c.pending[level]) < TileWidth*HashSize {
			return nil
		}
		if err := c.compare(ctx, level, TileWidth); err != nil {
			return err
		}
		h = subtreeRoot(c.pending[level], TileHeight)
		c.pending[level], c.index[level] = c.pending[level][:0], c.index[level]+1
	}
}

// Finish compares the partial tiles of the tree of the leaves added.
func (c *TileCheck) Finish(ctx context.Context) error {
	for level := range c.pending {
		if n := len(c.pending[level]) / HashSize; n > 0 {
			if err := c.compare(ctx, level, n); err != nil {
				return err
			}
		}
	}
	return nil
}

// Size returns the number of leaves added.
func (c *TileCheck) Size() uint64 { return c.size }

func (c *TileCheck) compare(ctx context.Context, level, width int) error {
	t := TileID{Level: level, Index: c.index[level], Width: width}
	stored, err := readTile(ctx, c.r, t)
	if err != nil {
		return err
	}
	if !bytes.Equal(stored, c.pending[level][:width*HashSize]) {
		return fmt.Errorf("%w: %s", ErrTileMismatch, t.Path())
	}
	return nil
}
