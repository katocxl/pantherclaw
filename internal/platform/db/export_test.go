// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package db

// BreakTimelineForTest breaks p's armed watch as a promotion it cannot
// accept would (D213): a new timeline without sync at both ends.
func BreakTimelineForTest(p *Pool) error {
	p.timeline.mu.Lock()
	next := p.timeline.timeline + 1
	p.timeline.mu.Unlock()
	_, err := p.timeline.observe(next, false)
	return err
}
