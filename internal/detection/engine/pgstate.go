// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// Bucket is the width of a window bucket.
const Bucket = time.Minute

// PG is the engine's State in one org's tenant transaction.
type PG struct {
	tx db.TenantTx
	q  *dbq.Queries
	// MaxGroups and MaxSeen are the caps; tests may lower them.
	MaxGroups, MaxSeen int
}

// NewPG returns the State of tx's org.
func NewPG(tx db.TenantTx) *PG {
	return &PG{tx: tx, q: dbq.New(tx), MaxGroups: MaxGroups, MaxSeen: MaxSeen}
}

// Window implements State.
func (p *PG) Window(ctx context.Context, rule, group string, at time.Time, dur time.Duration, distinct string, counted bool,
) (int, bool, error) {
	org := p.tx.OrgID()
	since := at.Add(-dur)
	// The caps are checked against the rule's counters, in O(1) (D59 M5).
	known, err := p.q.DetectionWindowGroupKnown(ctx, org, rule, group)
	if err != nil {
		return 0, false, err
	}
	overflow := false
	if !known {
		c, err := p.q.EnsureDetectionRuleState(ctx, org, rule)
		if err != nil {
			return 0, false, err
		}
		if int(c.WindowGroups) >= p.MaxGroups {
			group, overflow = OverflowKey, true
		}
	}
	bucket := at.UTC().Truncate(Bucket)
	inserted, err := p.q.TouchDetectionWindowGroup(ctx, dbq.TouchDetectionWindowGroupParams{OrgID: org, RuleID: rule, GroupKey: group, Bucket: bucket})
	if err != nil {
		return 0, false, err
	}
	if inserted && group != OverflowKey {
		if err := p.q.CountDetectionWindowGroup(ctx, org, rule); err != nil {
			return 0, false, err
		}
	}
	if err := p.q.AddDetectionWindowEvent(ctx, dbq.AddDetectionWindowEventParams{
		OrgID: org, RuleID: rule, GroupKey: group, Bucket: bucket, DistinctValue: distinct,
	}); err != nil {
		return 0, false, err
	}
	// The bucket holding since counts whole: a window is at most one
	// bucket wider than its duration.
	c, err := p.q.DetectionWindowCount(ctx, dbq.DetectionWindowCountParams{
		OrgID: org, RuleID: rule, GroupKey: group, Since: since.UTC().Truncate(Bucket).Add(-time.Microsecond),
	})
	if err != nil {
		return 0, false, err
	}
	if counted {
		return int(c.DistinctValues), overflow, nil
	}
	return int(c.Events), overflow, nil
}

// Seen implements State.
func (p *PG) Seen(ctx context.Context, rule string, key [32]byte, at time.Time, horizon time.Duration) (bool, bool, error) {
	org := p.tx.OrgID()
	last, err := p.q.GetDetectionSeen(ctx, org, rule, key[:])
	known := err == nil
	if err != nil && !db.IsNoRows(err) {
		return false, false, err
	}
	if !known {
		c, err := p.q.EnsureDetectionRuleState(ctx, org, rule)
		if err != nil {
			return false, false, err
		}
		if int(c.SeenKeys) >= p.MaxSeen {
			return false, true, nil
		}
	}
	if err := p.q.UpsertDetectionSeen(ctx, dbq.UpsertDetectionSeenParams{OrgID: org, RuleID: rule, KeyHash: key[:], At: at}); err != nil {
		return false, false, err
	}
	if !known {
		if err := p.q.CountDetectionSeenKey(ctx, org, rule); err != nil {
			return false, false, err
		}
	}
	return !known || at.Sub(last) > horizon, false, nil
}

// Sequence implements State.
func (p *PG) Sequence(ctx context.Context, rule, group string) (Progress, bool, error) {
	r, err := p.q.GetDetectionSequence(ctx, p.tx.OrgID(), rule, group)
	if db.IsNoRows(err) {
		return Progress{}, false, nil
	}
	if err != nil {
		return Progress{}, false, err
	}
	return Progress{Step: int(r.Step), Started: r.StartedAt, Updated: r.UpdatedAt, Evidence: r.Evidence}, true, nil
}

// SetSequence implements State.
func (p *PG) SetSequence(ctx context.Context, rule, group string, pr Progress) error {
	return p.q.UpsertDetectionSequence(ctx, dbq.UpsertDetectionSequenceParams{
		OrgID: p.tx.OrgID(), RuleID: rule, GroupKey: group, Step: int16(pr.Step), //nolint:gosec // G115: ≤ 4 steps
		StartedAt: pr.Started, UpdatedAt: pr.Updated, Evidence: pr.Evidence,
	})
}

// ClearSequence implements State.
func (p *PG) ClearSequence(ctx context.Context, rule, group string) error {
	return p.q.DeleteDetectionSequence(ctx, p.tx.OrgID(), rule, group)
}

// Prune drops window buckets, sequences and first-seen keys older than any
// rule can use.
func (p *PG) Prune(ctx context.Context, now time.Time) error {
	org := p.tx.OrgID()
	if _, err := p.q.PruneDetectionWindows(ctx, org, now.Add(-MaxWindowAge)); err != nil {
		return err
	}
	if err := p.q.PruneDetectionWindowGroups(ctx, org, now.Add(-MaxWindowAge)); err != nil {
		return err
	}
	if _, err := p.q.PruneDetectionSequences(ctx, org, now.Add(-MaxWindowAge)); err != nil {
		return err
	}
	return p.q.PruneDetectionSeen(ctx, org, now.Add(-MaxSeenAge))
}

// Retention of the engine's working memory: the longest window or
// sequence (24 h) plus a bucket, and the longest first-seen horizon (90 d).
const (
	MaxWindowAge = 24*time.Hour + Bucket
	MaxSeenAge   = 90 * 24 * time.Hour
)
