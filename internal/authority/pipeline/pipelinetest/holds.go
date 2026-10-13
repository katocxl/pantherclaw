// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// holdKey names a transaction by its run and action.
type holdKey struct{ run, action ids.UUID }

// holdState is the world's approval requests and settings (G0 M5 part 2).
type holdState struct {
	latest   map[holdKey]*pipeline.HoldRequest
	variants []apdomain.VariantLine
	approved []apdomain.ContextLine
	settings pipeline.HoldSettings
}

func (w *World) holds() *holdState {
	if w.hold == nil {
		w.hold = &holdState{latest: map[holdKey]*pipeline.HoldRequest{}}
	}
	return w.hold
}

// SetHold makes h the latest approval request of (run, action); nil removes
// it.
func (w *World) SetHold(run, action ids.UUID, h *pipeline.HoldRequest) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if h == nil {
		delete(w.holds().latest, holdKey{run, action})
		return
	}
	c := *h
	w.holds().latest[holdKey{run, action}] = &c
}

// SetVariants sets what Variants returns.
func (w *World) SetVariants(v []apdomain.VariantLine, approved []apdomain.ContextLine) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.holds().variants, w.holds().approved = v, approved
}

// SetHoldSettings sets the org's hold settings.
func (w *World) SetHoldSettings(s pipeline.HoldSettings) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.holds().settings = s
}

// Hold implements pipeline.Reader.
func (w *World) Hold(_ context.Context, _ ids.OrgID, run, action ids.UUID) (*pipeline.HoldRequest, error) {
	if err := w.fail("Hold"); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if h, ok := w.holds().latest[holdKey{run, action}]; ok {
		c := *h
		return &c, nil
	}
	return nil, nil
}

// Variants implements pipeline.Reader.
func (w *World) Variants(context.Context, ids.OrgID, [32]byte, string, actionir.Target, time.Time) (
	[]apdomain.VariantLine, []apdomain.ContextLine, error,
) {
	if err := w.fail("Variants"); err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.holds().variants, w.holds().approved, nil
}

// HoldSettings implements pipeline.Reader.
func (w *World) HoldSettings(context.Context, ids.OrgID) (pipeline.HoldSettings, error) {
	if err := w.fail("HoldSettings"); err != nil {
		return pipeline.HoldSettings{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.holds().settings, nil
}

// holdWrite applies a finalization's approval writes (w.mu held): a hold
// supersedes the live request and records a new PENDING one, a permit
// consumes the approved request it rests on, and a DENY by expiry records
// the expiry.
func (w *World) holdWrite(wr finalize.Write) error {
	ev := wr.Eval
	h := ev.Hold
	if h == nil {
		return nil
	}
	key := holdKey{ev.RunID, ev.ActionID}
	latest := w.holds().latest[key]
	switch {
	case finalize.Holds(ev) && !wr.HoldRequest.IsZero():
		if latest != nil && latest.State.Live() && h.Request != nil && latest.ID != h.Request.ID {
			return finalize.ErrConflict
		}
		w.holds().latest[key] = &pipeline.HoldRequest{
			ID: wr.HoldRequest, State: apdomain.StatePending, Binding: h.Binding.Hash, Deadline: h.Deadline,
			Variants: h.Display.Variants, Context: h.Display.Context,
		}
	case wr.Permit != nil && h.Satisfied:
		if latest == nil || latest.State != apdomain.StateApproved || latest.Binding != h.Binding.Hash {
			return finalize.ErrConflict
		}
		latest.State = apdomain.StateConsumed
	case ev.Decision == adomain.Deny && h.Expire && latest != nil && latest.State.Live():
		latest.State, latest.EndReason = apdomain.StateExpired, apdomain.EndExpired
	}
	return nil
}

// Revalidate implements finalize.Store: the world has no responses, so
// nothing is ever voided.
func (w *World) Revalidate(context.Context, ids.OrgID, ids.UUID) error { return nil }

// ApprovalProof implements finalize.Store: the world has no responses, so
// a permit's approval carries no assertion (HR-038 is the gateway's check).
func (w *World) ApprovalProof(context.Context, ids.OrgID, ids.UUID) ([]proof.Assertion, error) {
	return nil, nil
}
