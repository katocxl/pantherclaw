// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// SetContentSignals sets the org's content signal mode and the flags on the
// root of each run's tree (G0 M27 D507).
func (w *World) SetContentSignals(mode string, kinds ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.content = pipeline.ContentState{Mode: mode, Kinds: kinds}
}

// ContentSignals implements pipeline.Reader.
func (w *World) ContentSignals(context.Context, ids.OrgID, ids.UUID) (pipeline.ContentState, error) {
	if err := w.fail("ContentSignals"); err != nil {
		return pipeline.ContentState{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.content, nil
}
