// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

import "context"

// BreakTimelineForTest breaks p's armed watch as a promotion it cannot
// accept would (D213): a new timeline without sync at both ends.
func BreakTimelineForTest(p *Pool) error {
	p.timeline.mu.Lock()
	next := p.timeline.timeline + 1
	p.timeline.mu.Unlock()
	_, err := p.timeline.observe(next, false)
	return err
}

// PromoteForTest runs the running-process decision on one connection of p,
// armed as a start that verified sync on timeline, for a new primary that
// verifies it on next.
func PromoteForTest(ctx context.Context, p *Pool, timeline, next int64) error {
	p.timeline.arm(Promotion{Timeline: timeline, Sync: true})
	c, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer c.Release()
	return p.timeline.decide(ctx, c.Conn(), next, true)
}
