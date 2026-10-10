// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// InputSealer seals what an evaluation read for its evaluation_inputs row
// (G0 M7 design decision 11); recording.Sealer implements it.
type InputSealer interface {
	Seal(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, r *recording.Recording) (*recording.Sealed, error)
}

// recorder wraps r in a recorder of req's evaluation when the Authority
// keeps inputs.
func (a *Authority) recorder(r pipeline.Reader, req pipeline.Request) (pipeline.Reader, *recording.Recorder) {
	if a.Inputs == nil {
		return r, nil
	}
	rec := recording.NewRecorder(r, req)
	return rec, rec
}

// sealInputs seals what rec recorded for the row of (txn, evaluation). It
// runs before the finalization's transaction, so that transaction never
// waits for a key. A recording that cannot be kept fails the decision, as
// a receipt that cannot be signed does.
func (a *Authority) sealInputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, rec *recording.Recorder) (*recording.Sealed, error) {
	if a.Inputs == nil || rec == nil {
		return nil, nil //nolint:nilnil // no inputs are kept
	}
	r, err := rec.Recording()
	if err != nil {
		return nil, fmt.Errorf("finalize: record inputs: %w", err)
	}
	return a.Inputs.Seal(ctx, org, txn, evaluation, r)
}

// sealTampered seals the inputs of a tampering denial: the request and the
// action hash stored for its ids (HR-006).
func (a *Authority) sealTampered(ctx context.Context, org ids.OrgID, req pipeline.Request, prev Stored, evaluation int) (*recording.Sealed, error) {
	if a.Inputs == nil {
		return nil, nil //nolint:nilnil // no inputs are kept
	}
	return a.Inputs.Seal(ctx, org, prev.TransactionID, evaluation, recording.NewTampered(req, prev.ActionHash))
}
