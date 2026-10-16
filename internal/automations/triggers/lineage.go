// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"slices"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Lineage is where a trigger comes from (D23, HR-278): the first trigger
// of its chain, the automations upstream of it and its depth. A trigger
// nothing automated caused has depth 0 and is its own root.
type Lineage struct {
	Root     ids.UUID
	Ancestry []ids.UUID
	Depth    int
}

// Parent is the trigger of an execution whose effects caused an event.
type Parent struct {
	Trigger    ids.UUID
	Automation ids.UUID
	Root       ids.UUID
	Ancestry   []ids.UUID
	Depth      int
}

// Child is the lineage of a trigger caused by p's execution:
// ancestry = p.ancestry + [p.automation], depth = p.depth + 1, root =
// p.root.
func (p Parent) Child() Lineage {
	root := p.Root
	if root.IsZero() {
		root = p.Trigger
	}
	anc := slices.Clone(p.Ancestry)
	if !slices.Contains(anc, p.Automation) {
		anc = append(anc, p.Automation)
	}
	return Lineage{Root: root, Ancestry: anc, Depth: p.Depth + 1}
}

// Union merges lineages (a threshold counts several events, D58): the
// ancestries' union (at most autodomain.MaxAncestry, in first-seen order),
// the greatest depth and the first root of a caused event.
func Union(ls ...Lineage) Lineage {
	var out Lineage
	for _, l := range ls {
		if l.Depth == 0 {
			continue
		}
		if out.Root.IsZero() {
			out.Root = l.Root
		}
		out.Depth = max(out.Depth, l.Depth)
		for _, a := range l.Ancestry {
			if !slices.Contains(out.Ancestry, a) {
				out.Ancestry = append(out.Ancestry, a)
			}
		}
	}
	return out
}

// Loop reports whether a trigger for automation with lineage l must be
// refused (HR-278): the automation is already upstream of itself, or the
// chain is too deep or too wide.
func (l Lineage) Loop(automation ids.UUID) bool {
	return slices.Contains(l.Ancestry, automation) || l.Depth >= autodomain.MaxDepth ||
		len(l.Ancestry) > autodomain.MaxAncestry
}

// Contains reports whether automation is upstream (D58: a threshold never
// counts an event its own executions caused).
func (l Lineage) Contains(automation ids.UUID) bool { return slices.Contains(l.Ancestry, automation) }
