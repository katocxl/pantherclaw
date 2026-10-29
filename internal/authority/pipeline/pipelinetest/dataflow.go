// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"
	"slices"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// flowState is the world's read history (G0 M16 D73): run parents and the
// pii and secret reads its finalizations allowed.
type flowState struct {
	parents map[ids.UUID]ids.UUID
	reads   []pipeline.SensitiveRead
}

func (w *World) flows() *flowState {
	if w.flow == nil {
		w.flow = &flowState{parents: map[ids.UUID]ids.UUID{}}
	}
	return w.flow
}

// SetParentRun makes parent the parent run of child, for the run tree
// SensitiveReads counts over.
func (w *World) SetParentRun(child, parent ids.UUID) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flows().parents[child] = parent
}

// AddSensitiveRead records a sensitive read as an allowed read's
// finalization would.
func (w *World) AddSensitiveRead(r pipeline.SensitiveRead) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flows().reads = append(w.flows().reads, r)
}

// recordRead keeps the class of an allowed pii or secret read (w.mu held),
// as the transaction's read_class column does.
func (w *World) recordRead(wr finalize.Write) {
	ev := wr.Eval
	if c := ev.RecordedReadClass(); c == "pii" || c == "secret" {
		w.flows().reads = append(w.flows().reads, pipeline.SensitiveRead{
			TransactionID: wr.TransactionID, RunID: ev.RunID, Operation: ev.Operation, Class: c, At: ev.Now,
		})
	}
}

// SensitiveReads implements pipeline.Reader: the sensitive reads of every
// run sharing run's root, newest first, at most pipeline.MaxSensitiveReads.
func (w *World) SensitiveReads(_ context.Context, _ ids.OrgID, run ids.UUID) ([]pipeline.SensitiveRead, error) {
	if err := w.fail("SensitiveReads"); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fs := w.flows()
	root := func(r ids.UUID) ids.UUID {
		for range 8 {
			p, ok := fs.parents[r]
			if !ok {
				break
			}
			r = p
		}
		return r
	}
	top := root(run)
	var out []pipeline.SensitiveRead
	for _, r := range slices.Backward(fs.reads) {
		if root(r.RunID) == top && len(out) < pipeline.MaxSensitiveReads {
			out = append(out, r)
		}
	}
	return out, nil
}
