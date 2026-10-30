// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// snapReader marks while a snapshot is open.
type snapReader struct {
	pipeline.Reader
	open *bool
}

func (r snapReader) Snapshot(ctx context.Context, _ ids.OrgID, fn func(context.Context, pipeline.Reader) error) error {
	*r.open = true
	defer func() { *r.open = false }()
	return fn(ctx, r.Reader)
}

// checksAt are one matching check that records whether a snapshot was
// open when it was called.
type checksAt struct {
	open     *bool
	id       ids.UUID
	calledIn []bool
}

func (c *checksAt) Preload(ctx context.Context, _ ids.OrgID) context.Context {
	c.calledIn = append(c.calledIn, *c.open) // Preload too runs before the snapshot
	return ctx
}

func (c *checksAt) Matching(context.Context, ids.OrgID, string) ([]pipeline.ExternalTarget, error) {
	return []pipeline.ExternalTarget{{ID: c.id, Name: "opa"}}, nil
}

func (c *checksAt) Call(_ context.Context, _ ids.OrgID, calls []pipeline.ExternalCall) []pipeline.ExternalVerdict {
	c.calledIn = append(c.calledIn, *c.open)
	return []pipeline.ExternalVerdict{{CheckID: calls[0].Check.ID, Check: "opa", Decision: "deny"}}
}

// TestM16_NoConnectionIsHeldDuringTheCall: a decision asks its external
// check between two snapshots, never inside one, and decides with the
// answer (D96).
// Covers: F366
func TestM16_NoConnectionIsHeldDuringTheCall(t *testing.T) {
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	s.Refundable("ch_1")
	open := false
	checks := &checksAt{open: &open, id: ids.NewV7()}
	p := &pipeline.Pipeline{Reader: snapReader{Reader: s.W, open: &open}, External: checks}
	ev, err := p.Evaluate(context.Background(), s.Request(s.Run(g.ID, s.Alice), ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "20.00")))
	if err != nil {
		t.Fatal(err)
	}
	if len(checks.calledIn) != 3 || checks.calledIn[0] || checks.calledIn[1] || checks.calledIn[2] {
		t.Fatalf("preload, call, preload inside a snapshot: %v", checks.calledIn)
	}
	if ev.Decision != "DENY" || ev.Decisive().Code != pipeline.ReasonExternalDeny {
		t.Fatalf("%s %s", ev.Decision, ev.Decisive().Code)
	}
}
