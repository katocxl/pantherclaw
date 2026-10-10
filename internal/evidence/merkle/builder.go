// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package merkle

// Builder computes the RFC 9162 root of a tree from its leaf hashes, given
// in order, in O(log n) memory: it keeps the roots of the perfect subtrees
// that make up the tree so far, largest first. The daily integrity job uses
// it to recompute a checkpoint's root from the chain itself, without the
// stored tiles.
type Builder struct {
	roots []Hash
	sizes []uint64
	n     uint64
}

// Add appends one leaf hash.
func (b *Builder) Add(leaf Hash) {
	h, size := leaf, uint64(1)
	for k := len(b.roots) - 1; k >= 0 && b.sizes[k] == size; k-- {
		h, size = NodeHash(b.roots[k], h), size*2
		b.roots, b.sizes = b.roots[:k], b.sizes[:k]
	}
	b.roots, b.sizes = append(b.roots, h), append(b.sizes, size)
	b.n++
}

// Size returns the number of leaves added.
func (b *Builder) Size() uint64 { return b.n }

// Root returns the root of the tree of the leaves added so far.
func (b *Builder) Root() Hash {
	if b.n == 0 {
		return EmptyRoot()
	}
	h := b.roots[len(b.roots)-1]
	for k := len(b.roots) - 2; k >= 0; k-- {
		h = NodeHash(b.roots[k], h)
	}
	return h
}
